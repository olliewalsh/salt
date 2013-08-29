# -*- coding: utf-8 -*-
'''
Scheduling routines are located here. To activate the scheduler make the
schedule option available to the master or minion configurations (master config
file or for the minion via config or pillar)

code-block:: yaml

    schedule:
      job1:
        function: state.sls
        seconds: 3600
        args:
          - httpd
        kwargs:
          test: True

This will schedule the command: state.sls httpd test=True every 3600 seconds
(every hour)

The scheduler also supports ensuring that there are no more than N copies of
a particular routine running.  Use this for jobs that may be long-running
and could step on each other or pile up in case of infrastructure outage.

The default for maxrunning is 1.

code-block:: yaml

    schedule:
      long_running_job:
          function: big_file_transfer
          jid_include: True
          maxrunning: 1

'''

# Import python libs
import os
import time
import datetime
import os
import sys
import logging

# Import Salt libs
import salt.utils

log = logging.getLogger(__name__)


class Schedule(object):
    '''
    Create a Schedule object, pass in the opts and the functions dict to use
    '''
    def __init__(self, opts, functions, returners=None, intervals=None):
        self.opts = opts
        self.functions = functions
        if isinstance(intervals, dict):
            self.intervals = intervals
        else:
            self.intervals = {}
        if isinstance(returners, dict):
            self.returners = returners
        else:
            self.returners = {}
        self.schedule_returner = self.option('schedule_returner')
        # Keep track of the lowest loop interval needed in this variable
        self.loop_interval = sys.maxint

    def option(self, opt):
        '''
        Return the schedule data structure
        '''
        if 'config.merge' in self.functions:
            return self.functions['config.merge'](opt, {}, omit_master=True)
        return self.opts.get(opt, {})

    def handle_func(self, func, data):
        '''
        Execute this method in a multiprocess or thread
        '''
        ret = {'id': self.opts.get('id', 'master'),
               'fun': func,
               'jid': '{0:%Y%m%d%H%M%S%f}'.format(datetime.datetime.now())}
        if 'args' in data:
            if 'kwargs' in data:
                ret['return'] = self.functions[func](
                        *data['args'],
                        **data['kwargs'])
            else:
                ret['return'] = self.functions[func](
                        *data['args'])
        else:
            ret['return'] = self.functions[func]()
        if 'returner' in data or self.schedule_returner:
            rets = []
            if isinstance(data['returner'], str):
                rets.append(data['returner'])
            elif isinstance(data['returner'], list):
                for returner in data['returner']:
                    if returner not in rets:
                        rets.append(returner)
            if isinstance(self.schedule_returner, list):
                for returner in self.schedule_returner:
                    if returner not in rets:
                        rets.append(returner)
            if isinstance(self.schedule_returner, str):
                if self.schedule_returner not in rets:
                    rets.append(self.schedule_returner)
            for returner in rets:
                ret_str = '{0}.returner'.format(returner)
                if ret_str in self.returners:
                    self.returners[ret_str](ret)
                else:
                    log.info(
                        'Job {0} using invalid returner: {1} Ignoring.'.format(
                        func, returner
                        )
                    )

    def _run(self, func, data):
        pid = os.fork()
        if pid == 0:
            salt.utils.daemonize()
            self.handle_func(func, data)
            exit(0)
        else:
            os.waitpid(pid, 0)

    def eval(self):
        '''
        Evaluate and execute the schedule
        '''
        schedule = self.option('schedule')
        if not isinstance(schedule, dict):
            return
        for job, data in schedule.items():
            if 'function' in data:
                func = data['function']
            elif 'func' in data:
                func = data['func']
            elif 'fun' in data:
                func = data['fun']
            else:
                func = None
            if func not in self.functions:
                log.info(
                    'Invalid function: {0} in job {1}. Ignoring.'.format(
                        job, func
                    )
                )
                continue
            # Add up how many seconds between now and then
            seconds = 0
            seconds += int(data.get('seconds', 0))
            seconds += int(data.get('minutes', 0)) * 60
            seconds += int(data.get('hours', 0)) * 3600
            seconds += int(data.get('days', 0)) * 86400
            # Check if the seconds variable is lower than current lowest
            # loop interval needed. If it is lower then overwrite variable
            # external loops using can then check this variable for how often
            # they need to reschedule themselves
            if seconds < self.loop_interval:
                self.loop_interval = seconds
            now = int(time.time())
            run = False
            if job in self.intervals:
                if now - self.intervals[job] >= seconds:
                    run = True
            else:
                run = True
            if not run:
                continue
            else:
                log.debug('Running scheduled job: {0}'.format(job))

            if 'jid_include' not in data or data['jid_include']:
                data['jid_include'] = True
                log.debug('schedule: This job was scheduled with jid_include, '
                          'adding to cache (jid_include defaults to True)')
                if 'maxrunning' in data:
                    log.debug('schedule: This job was scheduled with a max '
                              'number of {0}'.format(data['maxrunning']))
                else:
                    log.info('schedule: maxrunning parameter was not specified for '
                              'job {0}, defaulting to 1.'.format(job))
                    data['maxrunning'] = 1
            try:
                self._run(func, data)
            finally:
                self.intervals[job] = int(time.time())

class MinionPoolSchedule(Schedule):
    def __init__(self, minion, intervals=None):
        super(MinionPoolSchedule, self).__init__(
            minion.opts,
            minion.functions,
            minion.returners,
            intervals)
        self.minion = minion

    def _run(self, func, data):
        self.minion._handle_decoded_payload({'fun':'schedule_run', 'args':[func, data]})


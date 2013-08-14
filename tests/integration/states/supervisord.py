'''
Tests for the supervisord state
'''

# Import python lins
import os
import time
import subprocess

# Import Salt Testing libs
from salttesting.helpers import ensure_in_syspath
ensure_in_syspath('../../')

# Import salt libs
import integration

class SupervisorControl(object):
    '''
    Class to control supervisor outside of salt to test external modifications
    '''
    def __init__(self, venv_dir, conffile):
        self._supervisor_conf = conffile
        self._supervisord = os.path.join(venv_dir, 'bin', 'supervisord')
        self._supervisorctl = os.path.join(venv_dir, 'bin', 'supervisorctl')
        self._supervisor_proc = None

    def supervisorctl(self, *args):
        proc = subprocess.Popen(
            [self._supervisorctl, '-c', self._supervisor_conf] + list(args),
            stdout = subprocess.PIPE,
            stderr = subprocess.STDOUT
        )
        (out, err) = proc.communicate()
        return {'retcode': proc.returncode, 'out':out}


    def start(self):
        if self._supervisor_proc is not None:
            raise Exception("Supervisord already started")

        devnull = open(os.devnull, 'wb')

        self._supervisor_proc = subprocess.Popen(
            [self._supervisord, '-c', self._supervisor_conf, '-n'],
            stdout=devnull, stderr=subprocess.STDOUT
        )
        if self._supervisor_proc.poll() is not None:
            raise Exception('Failed to start supervisord')
        timeout = 30
        while True:
            ctl_state = self.supervisorctl('pid')
            if ctl_state['retcode'] == 0:
                break
            if timeout == 0:
                self._supervisor_proc.terminate()
                self._supervisor_proc.wait()
                self._supervisor_proc = None
                raise Exception("Failed to connect to supervisord: {0}".format(ctl_state['out']))
            else:
                time.sleep(1)
                timeout -= 1

    def stop(self):
        if self._supervisor_proc is None or self._supervisor_proc.poll() is not None:
            self._supervisor_proc = None
            #raise Exception('Supervisord is not running')
        else:
            self._supervisor_proc.terminate()
            self._supervisor_proc.wait()
            self._supervisor_proc = None

    def restart(self):
        try:
            self.stop()
        except:
            pass
        self.start()


class SupervisordTest(integration.ModuleCase,
                      integration.SaltReturnAssertsMixIn):
    '''
    Validate the supervisord states.
    '''

    def assertSaltReturnCodeOk(self, ret):
        self.assertEqual(ret['retcode'], 0)

    def setUp(self):
        super(SupervisordTest, self).setUp()
        ret = self.run_function('cmd.has_exec', ['virtualenv'])
        if not ret:
            self.skipTest('virtualenv not installed')

        self.venv_test_dir = os.path.join(integration.TMP, 'supervisortests')
        self.venv_dir = os.path.join(self.venv_test_dir, 'venv')
        self.supervisor_conf = os.path.join(self.venv_dir, 'supervisor.conf')

        if not os.path.exists(self.venv_test_dir):
            os.makedirs(self.venv_test_dir)

        if not os.path.exists(self.venv_dir):
            ret = self.run_function('virtualenv.create', [self.venv_dir])
            self.assertSaltReturnCodeOk(ret)
        ret = self.run_function(
            'pip.install', [], pkgs='supervisor', bin_env=self.venv_dir)
        self.assertSaltReturnCodeOk(ret)

        self.supervisor = SupervisorControl(self.venv_dir, self.supervisor_conf)

    def set_supervisorconf(self, programs):
        self.run_state(
            'file.managed',
            name=self.supervisor_conf,
            source='salt://supervisor.conf',
            template='jinja',
            context={
                'virtual_env': self.venv_dir,
                'programs':programs
            }
        )

    def set_simple_supervisorconf(self, autostart=True):
        programs = {
            'sleep_service':{
                'command':'sleep 600',
                'autostart':'true' if autostart else 'false',
            },
            'sleep_service2':{
                'command':'sleep 600',
                'autostart':'true' if autostart else 'false',
            }
        }
        self.set_supervisorconf(programs)

    def set_broken_supervisorconf(self, autostart=True):
        programs = {
            'sleep_service':{
                'command':'/bin/false',
                'autostart':'true' if autostart else 'false',
            },
            'sleep_service2':{
                'command':'/bin/false',
                'autostart':'true' if autostart else 'false',
            }
        }
        self.set_supervisorconf(programs)

    def start_supervisord(self, autostart=True):
        self.set_simple_supervisorconf(autostart)
        self.supervisor.start()

    def tearDown(self):
        self.supervisor.stop()

    def test_running_noservice(self):
        '''
        supervisord.running
        When supervisord is not running
        '''
        self.set_simple_supervisorconf(autostart=True)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltFalseReturn(ret)

    def test_running_stopped(self):
        '''
        supervisord.running
        When service is stopped.
        '''
        self.start_supervisord(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'Starting sleep_service')
        self.assertInSaltReturn(ret, 'sleep_service', ['changes'])

    def test_running_stopped_test(self):
        '''
        supervisord.running test=True
        When service is stopped.
        '''
        self.start_supervisord(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf,
            test=True
        )
        self.assertSaltNoneReturn(ret)
        self.assertInSaltComment(ret, 'Would start sleep_service')

    def test_running_started(self):
        '''
        supervisord.running
        When service is running.
        '''
        self.start_supervisord(autostart=True)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'sleep_service is already running')
        self.assertNotInSaltReturn(ret, 'sleep_service', ['changes'])

    def test_running_started_test(self):
        '''
        supervisord.running test=True
        When service is running.
        '''
        self.start_supervisord(autostart=True)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf,
            test=True
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'sleep_service is already running')

    def test_running_needsadding(self):
        '''
        supervisord.running
        When service needs to be added.
        '''
        self.start_supervisord(autostart=False)
        self.assertIn('removed process group', self.run_function('supervisord.remove',
            ['sleep_service'],
            conf_file=self.supervisor_conf,
            bin_env=self.venv_dir
        ))
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'Adding sleep_service')
        self.assertInSaltReturn(ret, 'sleep_service', ['changes'])

    def test_running_needsadding_test(self):
        '''
        supervisord.running test=True
        When service needs to be added.
        '''
        self.start_supervisord(autostart=False)
        self.assertIn('removed process group', self.run_function('supervisord.remove',
            ['sleep_service'],
            conf_file=self.supervisor_conf,
            bin_env=self.venv_dir
        ))
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf,
            test=True
        )
        self.assertSaltNoneReturn(ret)
        self.assertInSaltComment(ret, 'Would add sleep_service')

    def test_running_needsupdate_stopped(self):
        '''
        supervisord.running
        When stopped service needs to be updated.
        '''
        self.set_broken_supervisorconf(autostart=False)
        self.supervisor.start()
        self.set_simple_supervisorconf(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'Updating sleep_service')
        self.assertInSaltReturn(ret, 'sleep_service', ['changes'])

    def test_running_needsupdate_stopped_test(self):
        '''
        supervisord.running test=True
        When stopped service needs to be updated.
        '''
        self.set_broken_supervisorconf(autostart=False)
        self.supervisor.start()
        self.set_simple_supervisorconf(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf,
            test=True
        )
        self.assertSaltNoneReturn(ret)
        self.assertInSaltComment(ret, 'Would update sleep_service')

    def test_running_needsupdate_running(self):
        '''
        supervisord.running
        When a running service needs to be updated.
        '''
        self.set_broken_supervisorconf(autostart=True)
        self.supervisor.start()
        self.set_simple_supervisorconf(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'Updating sleep_service')
        self.assertInSaltReturn(ret, 'sleep_service', ['changes'])

    def test_running_needsupdate_running_test(self):
        '''
        supervisord.running test=True
        When a running service needs to be updated.
        '''
        self.set_broken_supervisorconf(autostart=True)
        self.supervisor.start()
        self.set_simple_supervisorconf(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf,
            test=True
        )
        self.assertSaltNoneReturn(ret)
        self.assertInSaltComment(ret, 'Would update sleep_service')

    def test_running_needsupdate_stopped_broken(self):
        '''
        supervisord.running
        When running service needs to be updated and is broken as result
        '''
        self.set_simple_supervisorconf(autostart=True)
        self.supervisor.start()
        self.set_broken_supervisorconf(autostart=False)
        ret = self.run_state(
            'supervisord.running', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltFalseReturn(ret)

    def test_running_notexists(self):
        '''
        supervisord.running
        When service doesn't exist.
        '''
        self.start_supervisord(autostart=True)
        ret = self.run_state(
            'supervisord.running', name='does_not_exist',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltFalseReturn(ret)

    def test_watch_stopped(self):
        '''
        supervisord watch
        When service is stopped.
        '''
        self.set_simple_supervisorconf(autostart=False)
        self.supervisor.start()
        foo = '{0}/test_watch_stopped.txt'.format(self.venv_test_dir)

        state={
            foo : {
                'file': [
                    'managed',
                    {'contents' : 'foo'}
                ]
            },
            'sleep_service': {
                'supervisord': [
                    'running',
                    {'conf_file':self.supervisor_conf},
                    {'bin_env':self.venv_dir},
                    {'watch': [
                            {'file': foo}
                        ]
                    }
                ]
            }
        }
        ret = self.run_function('state.high', data=state)
        for k,v in ret.items():
            if 'sleep_service' in k:
                self.assertInSaltComment({k:v}, 'Starting sleep_service')
                break 

    def test_watch_started(self):
        '''
        supervisord watch
        When service is running.
        '''
        self.set_simple_supervisorconf(autostart=True)
        self.supervisor.start()
        foo = '{0}/test_watch_started.txt'.format(self.venv_test_dir)

        state={
            foo : {
                'file': [
                    'managed',
                    {'contents' : 'foo'}
                ]
            },
            'sleep_service': {
                'supervisord': [
                    'running',
                    {'conf_file':self.supervisor_conf},
                    {'bin_env':self.venv_dir},
                    {'watch': [
                            {'file': foo}
                        ]
                    }
                ]
            }
        }
        ret = self.run_function('state.high', data=state)
        for k,v in ret.items():
            if 'sleep_service' in k:
                self.assertInSaltComment({k:v}, 'Restarting sleep_service')
                break

    def test_watch_not_triggered(self):
        '''
        supervisord watch
        When watch is not triggered.
        '''
        self.set_simple_supervisorconf(autostart=True)
        self.supervisor.start()
        foo = '{0}/test_watch_not_triggered.txt'.format(self.venv_test_dir)
        with open(foo, 'w') as outfile:
            outfile.write('foo')

        state={
            foo : {
                'file': [
                    'managed',
                    {'contents' : 'foo'}
                ]
            },
            'sleep_service': {
                'supervisord': [
                    'running',
                    {'conf_file':self.supervisor_conf},
                    {'bin_env':self.venv_dir},
                    {'watch': [
                            {'file': foo}
                        ]
                    }
                ]
            }
        }
        ret = self.run_function('state.high', data=state)
        for k,v in ret.items():
            if 'sleep_service' in k:
                self.assertInSaltComment({k:v}, 'sleep_service is already running')
                break

    def test_dead_started(self):
        '''
        supervisord.dead
        When service is running.
        '''
        self.start_supervisord(autostart=True)
        ret = self.run_state(
            'supervisord.dead', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)
        self.assertInSaltComment(ret, 'Stopping sleep_service')

    def test_dead_started_test(self):
        '''
        supervisord.dead
        When service is running.
        '''
        self.start_supervisord(autostart=True)
        ret = self.run_state(
            'supervisord.dead', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf,
            test=True
        )
        self.assertSaltNoneReturn(ret)
        self.assertInSaltComment(ret, 'Would stop sleep_service')

    def test_dead_stopped(self):
        '''
        supervisord.dead
        When service is stopped.
        '''
        self.start_supervisord(autostart=False)
        ret = self.run_state(
            'supervisord.dead', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)

    def test_dead_removed(self):
        '''
        supervisord.dead
        When service needs to be added.
        '''
        self.start_supervisord(autostart=False)
        self.run_function('supervisord.remove', [
            'sleep_service',
            None,
            self.supervisor_conf,
            self.venv_dir
        ])
        ret = self.run_state(
            'supervisord.dead', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)

    def test_dead_notexists(self):
        '''
        supervisord.dead
        When service does not exist.
        '''
        self.start_supervisord(autostart=True)
        ret = self.run_state(
            'supervisord.dead', name='does_not_exist',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)

    def test_dead_noservice(self):
        '''
        supervisord.dead when supervisord is not running
        '''
        self.set_simple_supervisorconf(autostart=True)
        ret = self.run_state(
            'supervisord.dead', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)

    def test_dead_broken(self):
        '''
        supervisord.dead
        When service needs to be added.
        '''
        self.set_broken_supervisorconf(autostart=True)
        self.supervisor.start()
        ret = self.run_state(
            'supervisord.dead', name='sleep_service',
            bin_env=self.venv_dir, conf_file=self.supervisor_conf
        )
        self.assertSaltTrueReturn(ret)

if __name__ == '__main__':
    from integration import run_tests
    run_tests(SupervisordTest)

'''
Interaction with the Supervisor daemon.
=======================================

For example:

The following web service will be restarted if the virtualenv in
/opt/myweb_service is updated or if the python-pysqlite2 package is updated.

If the supervisor config for this service changes it will be reread and the
service stopped, removed, re-added, restarted.

.. code-block:: yaml

    wsgi_server:
      supervisord:
        - running
        - require:
          - pkg: supervisor
          - file.managed: /etc/supervisor/conf.d/wsgi_server.conf
        - watch:
          - pkg: python-pysqlite2
          - virtualenv: /opt/myweb_service
'''

# Import python libs
import logging
import salt.utils

log = logging.getLogger(__name__)

class SupervisorManagerError(Exception):
    pass

class SupervisorManager(object):
    def __init__(self, name, user, conf_file, bin_env, test=False):
        self.test = test
        self.name = name
        self.user = user
        self.conf_file = conf_file
        self.bin_env = bin_env
        self._comment = ''
        self._changes = []
        self._state = None
        self._updated = ''
        self._update_state()

    _stopped_states = ('STOPPED', 'EXITED', 'FATAL')
    _intermediate_states = ('STOPPING', 'STARTING', 'BACKOFF')

    def _update_state(self):
        # When testing only fetch the state on init
        if self.test and self._state is not None:
            return

        while True:
            # Keep fetching the status while it is in an intermediate state
            self._state = __salt__['supervisord.status'](
                name=self.name,
                user=self.user,
                conf_file=self.conf_file,
                bin_env=self.bin_env
            )

            if self.name in self._state and \
                    self._state[self.name]['state'] in \
                        self._intermediate_states:
                continue
            else:
                break

        changes = __salt__['supervisord.reread'](
            user=self.user,
            conf_file=self.conf_file,
            bin_env=self.bin_env
        )
        if 'No config updates' not in changes:
            self._updated = changes

    def _stop(self):
        res = __salt__['supervisord.stop'](
            name=self.name,
            user=self.user,
            conf_file=self.conf_file,
            bin_env=self.bin_env
        )
        if 'ERROR' in res:
            raise SupervisorManagerError('Error stopping {0}: {1}'.format(
                self.name,
                res
            ))
        self._changes.append('stopped {0}'.format(self.name))
        self._update_state()

    def _start(self):
        res = __salt__['supervisord.start'](
            name=self.name,
            user=self.user,
            conf_file=self.conf_file,
            bin_env=self.bin_env
        )
        if 'ERROR' in res:
            raise SupervisorManagerError('Error starting {0}: {1}'.format(
                self.name,
                res
            ))
        self._changes.append('started {0}'.format(self.name))
        self._update_state()

    def _remove(self):
        res = __salt__['supervisord.remove'](
            name=self.name,
            user=self.user,
            conf_file=self.conf_file,
            bin_env=self.bin_env
        )
        if 'ERROR' in res:
            raise SupervisorManagerError('Error removing {0}: {1}'.format(
                self.name,
                res
            ))
        self._changes.append('removed {0}'.format(self.name))
        self._update_state()

    def _add(self):
        res = __salt__['supervisord.add'](
            name=self.name,
            user=self.user,
            conf_file=self.conf_file,
            bin_env=self.bin_env
        )
        if 'ERROR' in res:
            raise SupervisorManagerError('Error adding {0}: {1}'.format(
                self.name,
                res
            ))
        self._changes.append('added {0}'.format(self.name))
        self._update_state()

    def _is_available(self):
        return self.name in self._state

    def _has_changed(self):
        return self.name in self._updated

    def _is_stopped(self):
        return self._state[self.name]['state'] in self._stopped_states

    def ensure_running(self, restart=False):
        if self._has_changed():
            # Program has been added or changed
            if self._is_available():
                if self.test:
                    self._comment = 'Would update {0}'.format(self.name)
                    return 
                self._comment = 'Updating {0}'.format(self.name)
                if not self._is_stopped():
                     self._stop()
                self._remove()  
                self._add()
            else:
                if self.test:
                    self._comment = 'Would add {0}'.format(self.name)
                    return
                self._comment = 'Adding {0}'.format(self.name)
                self._add()
        elif not self._is_available():
            # Doesn't exist
            raise SupervisorManagerError(
                '{0} is not available'.format(self.name)
            )
        elif restart and self._is_available() and not self._is_stopped():
            # No conf change, but we want to restart so stop it now
            if self.test:
                self._comment = 'Would restart {0}'.format(self.name)
                return
            self._comment = 'Restarting {0}'.format(self.name)
            self._stop()
        else:
            # No conf change or restart, just ensure that it running
            if self._is_stopped():
                if self.test:
                    self._comment = 'Would start {0}'.format(self.name)
                    return
                self._comment = 'Starting {0}'.format(self.name)
            else:
                self._comment = '{0} is already running'.format(self.name)

        # In all cases we want to finish by ensuring the program is started
        if self._is_stopped():
            self._start()

        return True

    def ensure_dead(self):
        if self._is_available():
            if not self._is_stopped():
                if self.test:
                    self._comment = 'Would stop {0}'.format(self.name)
                    return
                self._comment = 'Stopping {0}'.format(self.name)
                self._stop()
            else:
                self._comment = '{0} is already dead'.format(self.name)
        else:
            self._comment = '{0} is not available'.format(self.name)

        return True



def running(name,
            restart=False,
            update=None,
            runas=None,
            conf_file=None,
            bin_env=None):
    '''
    Ensure the named service is running.

    name
        Service name as defined in the supervisor configuration file
    runas
        Name of the user to run the supervisorctl command
    conf_file
        path to supervisorctl config file
    bin_env
        path to supervisorctl bin or path to virtualenv with supervisor
        installed

    '''
    if update is not None:
        salt.utils.warn_until(
            (0,18),
            'The \'update\' argument has been deprecated '
            'as it is no longer required'
        )
    if restart:
        salt.utils.warn_until(
            (0,18),
            'The \'restart\' argument has been deprecated. '
            'A watch statement should be used instead to restart the service '
            'when a dependency has changed.' 
        )
        # For now just pass it to the watch function
        return mod_watch(
            name=name,
            runas=runas,
            conf_file=conf_file,
            bin_env=bin_env
        )

    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    manager = SupervisorManager(name=name,
        user=runas,
        conf_file=conf_file,
        bin_env=bin_env,
        test=__opts__['test']
    )
    try:
        ret['result'] = manager.ensure_running()
        ret['comment'] = manager._comment
    except SupervisorManagerError as e:
        ret['result'] = False
        ret['comment'] = ', '.join(e.args)
    finally:
        if len(manager._changes):
            ret['changes'][name] = ', '.join(manager._changes)
            if __opts__['test']:
                ret['result'] = None
    return ret

def dead(name,
         runas=None,
         conf_file=None,
         bin_env=None):
    '''
    Ensure the named service is dead (not running).

    name
        Service name as defined in the supervisor configuration file
    runas
        Name of the user to run the supervisorctl command
    conf_file
        path to supervisorctl config file
    bin_env
        path to supervisorctl bin or path to virtualenv with supervisor
        installed

    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    manager = SupervisorManager(
        name=name,
        user=runas,
        conf_file=conf_file,
        bin_env=bin_env,
        test=__opts__['test']
    )
    try:
        ret['result'] = manager.ensure_dead()
        ret['comment'] = manager._comment
    except SupervisorManagerError as e:
        ret['result'] = False
        ret['comment'] = ', '.join(e.args)
    finally:
        if len(manager._changes):
            ret['changes'][name] = ', '.join(manager._changes)
            if __opts__['test']:
                ret['result'] = None

    return ret


def mod_watch(name,
              runas=None,
              conf_file=None,
              bin_env=None,
              update=None):

    if update is not None:
        salt.utils.warn_until(
            (0,18),
            'The \'update\' argument has been deprecated '
            'as it is no longer required'
        )

    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    manager = SupervisorManager(
        name=name,
        user=runas,
        conf_file=conf_file,
        bin_env=bin_env,
        test=__opts__['test']
    )
    try:
        ret['result'] = manager.ensure_running(restart=True)
        ret['comment'] = manager._comment
    except SupervisorManagerError as e:
        ret['result'] = False
        ret['comment'] = ', '.join(e.args)
    finally:
        if len(manager._changes):
            ret['changes'][name] = ', '.join(manager._changes)
    return ret

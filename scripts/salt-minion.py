#!/usr/bin/env python
'''
This script is used to kick off a salt minion daemon
'''
import sys, os

try:
	sys.path.remove('')
except ValueError:
	pass

try:
	sys.path.remove(os.path.dirname(__file__))
except ValueError:
	pass

import salt.scripts
from multiprocessing import freeze_support


if __name__ == '__main__':
    # This handles the bootstrapping code that is included with frozen
    # scripts. It is a no-op on unfrozen code.
    freeze_support()
    salt.scripts.salt_minion()

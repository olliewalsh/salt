#!/usr/bin/env python
'''
Directly call a salt command in the modules, does not require a running salt
minion to run.
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

if __name__ == '__main__':
    salt.scripts.salt_call()

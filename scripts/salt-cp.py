#!/usr/bin/env python
'''
Publish commands to the salt system from the command line on the master.
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
    salt.scripts.salt_cp()

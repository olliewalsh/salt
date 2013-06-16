#!/usr/bin/env python
'''
Directly call a salt command in the modules, does not require a running salt
minion to run.
'''

import salt.scripts

if __name__ == '__main__':
    salt.scripts.salt_call()

#!/usr/bin/env python
'''
Publish commands to the salt system from the command line on the master.
'''

import salt.scripts


if __name__ == '__main__':
    salt.scripts.salt_cp()

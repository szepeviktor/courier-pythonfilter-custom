#!/usr/bin/python
# privateaddr -- Courier filter which grants selective access to some addresses
# Copyright (C) 2006-2008  Gordon Messmer <gordon@dragonsdawn.net>
#
# This file is part of pythonfilter.
#
# pythonfilter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pythonfilter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pythonfilter.  If not, see <http://www.gnu.org/licenses/>.

import sys
import re
import courier.config
import courier.control


# private_rcpts is a list of addresses which should only accept
# mail from listed senders.  The key name should be the private
# address; the value should be a list of regexes which match
# approved senders.
private_rcpts = { 'help@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'webmaster@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'msdn@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'researchhelp@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'desktophelp@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'securityhelp@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'gnlhelp@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'memshelp@ee.washington.edu': ['[^@]*@.*washington.edu'],
                  'compstudenthelp@ee.washington.edu': ['[^@]*@.*washington.edu'] }


def initFilter():
    courier.config.applyModuleConfig('privateaddr.py', globals())

    # Avoid recompiling REs on each run by compiling them here:
    global _private_re
    _private_re = {}
    for x in private_rcpts.keys():
        for y in private_rcpts[x]:
            _private_re[y] = re.compile(y)

    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "privateaddr" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Refuse mail if recipient is private, and sender is not approved."""
    for addr in courier.control.getRecipientsData(controlFileList):
        if addr[1]:
            if(addr[1].startswith('rfc822;')):
                rcpt = addr[1][7:]
            else:
                rcpt = addr[1]
        else:
                rcpt = addr[0]
        if courier.config.locallowercase():
            rcpt = rcpt.lower()
        if private_rcpts.has_key(rcpt):
            senderAllowed = 0
            sender = courier.control.getSender(controlFileList)
            for pattern in private_rcpts[rcpt]:
                if _private_re[pattern].match(sender):
                    senderAllowed = 1
            if senderAllowed == 0:
                sys.stderr.write('Message to %s from %s refused by privateaddr.py\n' % 
                                 (rcpt, sender) )
                return '517 Sender is not allowed by privacy settings.'
    return ''

#!/usr/bin/python
# localsenders -- Courier filter which validates sender addresses, if they are local
# Copyright (C) 2007  Gordon Messmer <gordon@dragonsdawn.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import sys
import courier.authdaemon
import courier.config
import courier.control


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "localsenders" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Validate sender addresses, if their domain is locally hosted."""
    try:
        sender = courier.control.getSender(controlFileList)
    except:
        return '451 Internal failure locating control files'
    sparts = sender.split('@')
    if len(sparts) != 2:
        return ''
    try:
        if courier.config.isLocal(sparts[1]):
            senderInfo = courier.authdaemon.getUserInfo('smtp', sparts[0])
        if courier.config.isHosteddomain(sparts[1]):
            senderInfo = courier.authdaemon.getUserInfo('smtp', sender)
    except courier.authdaemon.KeyError:
        return '517 Sender does not exist: %s' % sender
    return ''


if __name__ == '__main__':
    # For debugging, you can create a file or set of files that
    # mimics the Courier control file set.
    if not sys.argv[1:]:
        print 'Use:  localsenders.py <control file>'
        sys.exit(1)
    initFilter()
    print doFilter('', sys.argv[1])

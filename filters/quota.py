#!/usr/bin/python
# quota -- Courier filter which checks recipients' quotas
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

import os
import sys
import courier.authdaemon
import courier.config
import courier.control


def _checkQuota(addr):
    try:
        userInfo = courier.authdaemon.getUserInfo('smtp', addr)
    except courier.authdaemon.KeyError:
        # shouldn't happen if addr is local or hosted, and
        # courier accepted the address
        sys.stderr.write('quota filter: authdaemon failed to look up "%s"' % addr)
        return ''
    except courier.authdaemon.IoError, e:
        sys.stderr.write('quota filter: authdaemon failed, "%s"' % e.message)
        return ''
    if userInfo.has_key('MAILDIR'):
        maildirsize = os.path.join(userInfo['MAILDIR'], 'maildirsize')
    else:
        maildirsize = os.path.join(userInfo['HOME'], 'Maildir', 'maildirsize')
    try:
        sizeFile = open(maildirsize, 'r')
        (quotaSizeStr, quotaCountStr) = sizeFile.readline().strip().split(',')
        quotaSize = long(quotaSizeStr[:-1])
        quotaCount = long(quotaCountStr[:-1])
        mailSize = 0
        mailCount = 0
        quotaLine = sizeFile.readline()
        while quotaLine:
            (lineSize, lineCount) = quotaLine.strip().split()
            mailSize = mailSize + long(lineSize)
            mailCount = mailCount + long(lineCount)
            quotaLine = sizeFile.readline()
        if (mailSize >= quotaSize) or (mailcount >= quotaCount):
            return 'User "%s" is over quota' % addr
    except:
        return ''
    return ''
    

def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "quota" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Reject mail if any recipient is over quota"""
    rcpts = courier.control.getRecipientsData(controlFileList)
    for x in rcpts:
        (user, domain) = x.split('@', 1)
        if courier.config.isLocal(domain):
            quotaError = _checkQuota(user)
            if quotaError:
                return quotaError
        elif courier.config.isHosteddomain(domain):
            quotaError = _checkQuota('%s@%s' % (user, domain))
            if quotaError:
                return '421 %s' % quotaError
    return ''


if __name__ == '__main__':
    # For debugging, you can create a file or set of files that
    # mimics the Courier control file set.
    # Run this script with the name of those files as arguments,
    # and it'll check each recipient's quota.
    if not sys.argv[1:]:
        print 'Use:  quota.py <control file>'
        sys.exit(1)
    print doFilter('', sys.argv[1:])
#!/usr/bin/python
# quota -- Courier filter which checks recipients' quotas
# Copyright (C) 2007-2008  Gordon Messmer <gordon@dragonsdawn.net>
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

import os
import sys
import courier.authdaemon
import courier.config
import courier.control


def _parsequota(quota):
    bytes = 0
    messages = 0
    qbits = [ x.strip() for x in quota.split(',') ]
    for qbit in qbits:
        if qbit[-1] == 'S':
            bytes = long(qbit[:-1])
        elif qbit[-1] == 'C':
            messages = long(qbit[:-1])
        else:
            raise ValueError('quota string "%s" not parseable' % quota)
    return (bytes, messages)


def _checkQuota(addr):
    try:
        userInfo = courier.authdaemon.getUserInfo('smtp', addr)
    except courier.authdaemon.KeyError:
        # shouldn't happen if addr is local or hosted, and
        # courier accepted the address
        sys.stderr.write('quota filter: authdaemon failed to look up "%s"\n' % addr)
        return ''
    except courier.authdaemon.IoError, e:
        sys.stderr.write('quota filter: authdaemon failed, "%s"\n' % e)
        return ''
    if userInfo.has_key('MAILDIR'):
        maildirsize = os.path.join(userInfo['MAILDIR'], 'maildirsize')
    else:
        maildirsize = os.path.join(userInfo['HOME'], 'Maildir', 'maildirsize')
    try:
        sizeFile = open(maildirsize, 'r')
        (quotaSize, quotaCount) = _parsequota(sizeFile.readline())
        mailSize = 0
        mailCount = 0
        quotaLine = sizeFile.readline()
        while quotaLine:
            (lineSize, lineCount) = quotaLine.strip().split()
            mailSize += long(lineSize)
            mailCount += long(lineCount)
            quotaLine = sizeFile.readline()
        if ((quotaSize and mailSize >= quotaSize)
            or (quotaCount and mailcount >= quotaCount)):
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
        (user, domain) = x[0].split('@', 1)
        if courier.config.isLocal(domain):
            quotaError = _checkQuota(user)
            if quotaError:
                return '421 %s' % quotaError
        elif courier.config.isHosteddomain(domain):
            quotaError = _checkQuota(x[0])
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
    initFilter()
    print doFilter('', sys.argv[1:])
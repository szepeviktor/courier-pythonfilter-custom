#!/usr/bin/python
# clamav -- Courier filter which scans messages with ClamAV
# Copyright (C) 2004  Robert Penz <robert@penz.name>
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
import courier.config
import courier.quarantine

localSocket = ''
action = 'reject'

try:
    import pyclamav
    def scanMessage(bodyFile, controlFileList):
        try:
            avresult = pyclamav.scanfile(bodyFile)
        except Exception, e:
            return "554 " + str(e)
        if avresult[0]:
            return handleVirus(bodyFile, controlFileList, avresult[1])
        return ''
except ImportError:
    import pyclamd
    def scanMessage(bodyFile, controlFileList):
        try:
            pyclamd.init_unix_socket(localSocket)
            avresult = pyclamd.scan_file(bodyFile)
        except Exception, e:
            return "554 " + str(e)
        if avresult != None and avresult.has_key(bodyFile):
            return handleVirus(bodyFile, controlFileList, avresult[bodyFile])
        return ''


def handleVirus(bodyFile, controlFileList, virusSignature):
    if action == 'reject':
        return "554 Virus found - Signature is %s" % virusSignature
    else:
        courier.quarantine.quarantine(bodyFile, controlFileList,
                                      'The virus %s was found in the message' % virusSignature)
        return '050 OK'


def initFilter():
    courier.config.applyModuleConfig('clamav.py', globals())
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "clamav" python filter\n')


def doFilter(bodyFile, controlFileList):
    return scanMessage(bodyFile, controlFileList)


if __name__ == '__main__':
    # we only work with 1 parameter
    if len(sys.argv) < 3:
        print "Usage: clamav.py <message_body_file> <control_files>"
        sys.exit(0)
    initFilter()
    print doFilter(sys.argv[1], sys.argv[2:])

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
try:
    import pyclamav
    def scanMessage(bodyFile):
        try:
            avresult = pyclamav.scanfile(bodyFile)
        except Exception, e:
            return "554 " + str(e)
        if avresult[0]:
            return "554 Virus found - Signature is %s" % avresult[1]
        return ''
except ImportError:
    import pyclamd
    def scanMessage(bodyFile):
        try:
            pyclamd.init_unix_socket()
            avresult = pyclamd.scan_file(bodyFile)
        except Exception, e:
            return "554 " + str(e)
        if avresult != None and avresult.has_key(bodyFile):
            return "554 Virus found - Signature is %s" % avresult[bodyFile]
        return ''


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "clamav" python filter\n')


def doFilter(bodyFile, controlFileList):
    return scanMessage(bodyFile)


if __name__ == '__main__':
    # we only work with 1 parameter
    if len(sys.argv) != 2:
        print "Usage: clamav.py <message_body_file>"
        sys.exit(0)
    print doFilter(sys.argv[1], "")

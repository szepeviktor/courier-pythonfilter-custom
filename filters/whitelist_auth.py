#!/usr/bin/python
# whitelist_auth -- Courier filter which exempts authenticated users from filtering
# Copyright (C) 2006  Gordon Messmer <gordon@dragonsdawn.net>
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

import courier.control
import sys


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "whitelist_auth" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Return a 200 code if the sender appears to have authenticated.

    Courier does not currently contain this information in its control
    files, so we look at the first Received header.  The first one
    should always have come from Courier, and be trusted information.

    After returning a 200 code, the pythonfilter process will
    discontinue further filter processing.

    """

    authUser = courier.control.getAuthUser(controlFileList, bodyFile)
    if authUser:
        return '200 Ok'
    else:
        # Return no decision for everyone else.
        return ''


if __name__ == '__main__':
    # For debugging, you can create a file that contains a message,
    # including the headers.
    # Run this script with the name of that file as an argument,
    # and it'll print either "200 Ok" to indicate that the sender
    # is whitelisted, or nothing to indicate that the remaining
    # filters would be run.
    if not sys.argv[1:]:
        print 'Use:  whitelist_auth.py <control file>'
        sys.exit(1)
    print doFilter(sys.argv[1], [])

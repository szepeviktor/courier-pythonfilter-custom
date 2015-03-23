#!/usr/bin/python
# whitelist_dnswl -- Courier filter which exempts DNS whitelisted IPs from filtering
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

import sys
import socket
import courier.control
import courier.config


dnswlZone = ['list.dnswl.org']


def initFilter():
    courier.config.applyModuleConfig('whitelist_dnswl.py', globals())
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "whitelist_dnswl" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Return a 200 code if the message came from an IP in a DNS whitelist.

    After returning a 200 code, the pythonfilter process will
    discontinue further filter processing.

    """

    try:
        sendersIP = courier.control.getSendersIP(controlFileList)
    except:
        return '451 Internal failure locating control files'

    if sendersIP and '.' in sendersIP:
        # '.' must be in sendersIP until there are DNSWLs that support IPv6
        octets = sendersIP.split('.')
        octets.reverse()
        octetsR = '.'.join(octets)
        for zone in dnswlZone:
            lookup = '%s.%s' % (octetsR, zone)
            try:
                lookupResult = socket.gethostbyname(lookup)
            except:
                lookupResult = None
            if lookupResult:
                # For now, any result is good enough.
                return '200 Ok'

    # Return no decision for everyone else.
    return ''


if __name__ == '__main__':
    # For debugging, you can create a file that contains one line,
    # formatted as Courier's Received-From-MTA record:
    # faddresstype; address
    # Run this script with the name of that file as an argument,
    # and it'll print either "200 Ok" to indicate that the address
    # is whitelisted, or nothing to indicate that the remaining
    # filters would be run.
    if not sys.argv[1:]:
        print 'Use:  whitelist_dnswl.py <control file>'
        sys.exit(1)
    initFilter()
    print doFilter('', sys.argv[1:])

#!/usr/bin/python
# whitelist_block -- Courier filter which exempts un-BLOCK-ed IPs from filtering
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

import sys
import courier.control
import courier.config


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "whitelist_block" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Whitelist messages based on smtpaccess.dat.
    
    The smtpaccess.dat file is checked for a BLOCK value.  If one
    is found with an empty value, a 200 code will be returned.
    After returning a 200 code, the pythonfilter process will
    discontinue further filter processing.

    """

    try:
        sendersIP = courier.control.getSendersIP(controlFileList)
    except:
        return '451 Internal failure locating control files'

    if sendersIP and courier.config.getSmtpaccessVal('BLOCK', sendersIP) == '':
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
        print 'Use:  whitelist_block.py <control file>'
        sys.exit(1)
    initFilter()
    print doFilter('', sys.argv[1:])

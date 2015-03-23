#!/usr/bin/python
# log_aliases -- Courier filter which logs the original address of messages deliverd to aliases
# Copyright (C) 2008  Gordon Messmer <gordon@dragonsdawn.net>
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


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "log_aliases" python filter\n')


def doFilter(bodyFile, controlFileList):
    for addr in courier.control.getRecipientsData(controlFileList):
        if addr[1]:
            if(addr[1].startswith('rfc822;')):
                addr[1] = addr[1][7:]
            sys.stderr.write('Message delivered to %s was originally addressed to %s.\n' % \
                             (addr[0], addr[1]))
    return ''

#!/usr/bin/python
# noreceivedheaders -- Courier filter which strips AUTH data from messages
# Copyright (C) 2004-2008  Gordon Messmer <gordon@dragonsdawn.net>
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
import courier.xfilter


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "noreceivedheaders" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Remove the Received header if the sender authenticated himself."""
    authUser = courier.control.getAuthUser(controlFileList, bodyFile)
    if authUser is None:
        return ''
    try:
        mfilter = courier.xfilter.XFilter('noreceivedheaders', bodyFile,
                                          controlFileList)
    except courier.xfilter.LoopError, e:
        # LoopError indicates that we've already filtered this message.
        return ''
    mmsg = mfilter.getMessage()
    del mmsg['Received']
    submitVal = mfilter.submit()
    return submitVal


if __name__ == '__main__':
    # For debugging, you can create a file that contains a message,
    # including the headers.
    if not sys.argv[1:]:
        print 'Use:  noreceivedheaders.py <control file>'
        sys.exit(1)
    initFilter()
    courier.xfilter.XFilter = courier.xfilter.DummyXFilter
    print doFilter(sys.argv[1], [])

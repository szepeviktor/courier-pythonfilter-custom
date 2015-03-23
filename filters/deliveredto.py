#!/usr/bin/python
# deliveredto -- Courier filter which checks "Delivered-to" headers
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

import email
import sys
import courier.config


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "deliveredto" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Check 'Delivered-to' header

    Reject messages if the Delivered-to header indicates a
    locally hosted domain.

    """
    try:
        bfStream = open(bodyFile)
    except:
        return '451 Internal failure opening message data file'
    try:
        message = email.message_from_file(bfStream)
    except Exception, e:
        return '451 Internal failure parsing message data file'
    if 'Delivered-To' in message:
        dheader = message['Delivered-To']
        dparts = dheader.split('@')
        if len(dparts) != 2:
            return ''
        if(courier.config.isLocal(dparts[1]) or 
           courier.config.isHosteddomain(dparts[1])):
            return '501 Mail loop - already have my Delivered-To: header.'
    return ''


if __name__ == '__main__':
    # For debugging, you can create a file or set of files that
    # mimics the Courier control file set.
    if not sys.argv[1:]:
        print 'Use:  deliveredto.py <message body file>'
        sys.exit(1)
    print doFilter(sys.argv[1], '')

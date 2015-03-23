#!/usr/bin/python
# spfcheck -- Courier filter which checks SPF records using the "spf" module
# Copyright (C) 2004  Jon Nelson <jnelson@jamponi.net>
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
#
# License: GPL v2

import sys
import courier.control
import spf


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the SPF python filter\n')


def doFilter(bodyFile, controlFileList):
    """Use the SPF mechanism to whitelist, blacklist, or graylist email.

    blacklisted email is rejected, whitelisted email is accepted, and
    greylisted email is accepted with a logline.  Currently, it's
    probably far too optimistic to log greylisted.

    """
    try:
        senders_mta = courier.control.getSendersMta(controlFileList)
        senders_ip = courier.control.getSendersIP(controlFileList)
        sender = courier.control.getSender(controlFileList)
    except:
        return '451 Internal failure locating control files'

    # question: what if sender is '' or '<>' or '<@>' or '@' ??
    helo = senders_mta.split(' ')[1]
    results = spf.check(i=senders_ip, s=sender, h=helo)
    # results are pass,deny,unknown
    (decision, numeric, text) = results
    if decision == 'pass':
        return ''
    elif decision == 'unknown':
        sys.stderr.write('SPF returns "unknown" for %s,%s\n' % (senders_ip, sender,helo))
        return ''
    elif decision == 'deny':
        return '517 SPF returns deny'
    else:
        sys.stderr.write('SPF returns "%s" which is not understood.\n' % (results))
        return ''

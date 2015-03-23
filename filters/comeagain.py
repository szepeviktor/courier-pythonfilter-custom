#!/usr/bin/python
# comeagain -- Courier filter implementing a "greylisting" technique.
# Copyright (C) 2003-2008  Gordon Messmer <gordon@dragonsdawn.net>
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

import md5
import sys
import time
import courier.config
import courier.control
import TtlDb


# The good/bad senders lists will be scrubbed at the interval indicated
# in seconds.  All records older than the "sendersTTL" number of seconds
# will be removed from the lists.
sendersTTL = 60 * 60 * 24 * 30
sendersPurgeInterval = 60 * 60 * 12


def initFilter():
    courier.config.applyModuleConfig('comeagain.py', globals())
    # Keep a dictionary of sender/recipient pairs that we've seen before
    try:
        global _senders
        _senders = TtlDb.TtlDb('correspondents', sendersTTL, sendersPurgeInterval)
    except TtlDb.OpenError, e:
        sys.stderr.write('Could not open comeagain TtlDb: %s\n' % e)
        sys.exit(1)
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "comeagain" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Return a temporary failure message if this sender hasn't tried to
    deliver mail previously.

    Search through the control files and discover the envelope sender
    and message recipients.  If the sender has written to these
    recipients before, allow the message.  Otherwise, throw a
    temporary failure, and expect the remote MTA to try again.  Many
    spamware sites and viruses will not, preventing these messages
    from getting into the users' mailbox.

    """

   # Grab the sender from the control files.
    try:
        sender = courier.control.getSender(controlFileList)
    except:
        return '451 Internal failure locating control files'
    if sender == '':
        # Null sender is allowed as a non-fatal error
        return ''

    _senders.purge()

    # Create a new MD5 object.  The pairs of sender/recipient will
    # be stored in the db in the form of an MD5 digest.
    senderMd5 = md5.new(sender)

    # Create a digest for each recipient and look it up in the db.
    # Update the timestamp of each pair as we look them up.  If any
    # pair does not exist, we'll have to ask the sender to deliver
    # again.
    foundAll=1
    _senders.lock()
    try:
        for recipient in courier.control.getRecipients(controlFileList):
            correspondents = senderMd5.copy()
            correspondents.update(recipient)
            cdigest = correspondents.hexdigest()
            if not _senders.has_key(cdigest):
                foundAll = 0
            _senders[cdigest] = time.time()
    finally:
        _senders.unlock()

    if foundAll:
        return ''
    else:
        return('421 Please send the message again to prove you are not spamware or virusware.')


if __name__ == '__main__':
    # For debugging, you can create a file that contains one line,
    # beginning with an 's' character, followed by an email address
    # and more lines, beginning with an 'r' character, for each
    # recipient.  Run this script with the name of that file as an
    # argument, and it'll validate that email address.
    if not sys.argv[1:]:
        print 'Use: comeagain.py <control file>'
        sys.exit(1)
    initFilter()
    print doFilter('', sys.argv[1:])

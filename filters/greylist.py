#!/usr/bin/python
# greylist -- Courier filter implementing a "greylisting" technique.
# Copyright (C) 2005-2008  Mickael Marchand <marchand@kde.org>
# Copyright (C) 2006-2008  Georg Lutz <georg-list@georglutz.de>
# Copyright (C) 2006-2008  Gordon Messmer <gordon@dragonsdawn.net>
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

import hashlib
import sys
import time
import re
import courier.config
import courier.control
import TtlDb


# Enable or disable debug logging.
doDebug = 0

# The good/bad senders lists will be scrubbed at the interval indicated,
# in seconds, by the sendersPurgeInterval setting.  Any triplets which
# haven't successfully passed a message will be purged at the age
# indicated by sendersNotPassedTTL.  Any triplets which have passed a
# message will be purged at the age indicated by sendersPassedTTL, and
# will have to prove themselves again.  A triplet must be at as old as
# greylistTime to be accepted.
sendersPurgeInterval = 60 * 60 * 2
sendersPassedTTL = 60 * 60 * 24 * 36
sendersNotPassedTTL = 60 * 60 * 24
greylistTime = 300

_IPv4Regex = re.compile('^(\d+\.\d+\.\d+)\.\d+$')


def _Debug(msg):
    if doDebug:
        sys.stderr.write(msg + '\n')


def initFilter():
    courier.config.applyModuleConfig('greylist.py', globals())
    # Keep a dictionary of sender/recipient/IP triplets that we've seen before
    try:
        global _sendersPassed
        global _sendersNotPassed
        _sendersPassed = TtlDb.TtlDb('greylist_Passed', sendersPassedTTL, sendersPurgeInterval)
        _sendersNotPassed = TtlDb.TtlDb('greylist_NotPassed', sendersNotPassedTTL, sendersPurgeInterval)
    except TtlDb.OpenError, e:
        sys.stderr.write('Could not open greylist TtlDb: %s\n' % e)
        sys.exit(1)

    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "greylist" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Return a temporary failure message if this sender hasn't tried to
    deliver mail previously.

    Search through the control files and discover the envelope sender
    and message recipients.  If the sender has written to these
    recipients before, allow the message.  Otherwise, throw a
    temporary failure, and expect the remote MTA to try again.  Many
    spamware sites and viruses will not, preventing these messages
    from getting into the users' mailbox.

    This strategy is based on the whitepaper at:
    http://projects.puremagic.com/greylisting/whitepaper.html

    """

    sendersIP = courier.control.getSendersIP(controlFileList)
    # Calculate the /24 network
    IPv4Match = _IPv4Regex.match(sendersIP)
    if(IPv4Match is None):
        # IPv6 network calculation isn't handled yet
        sendersIPNetwork = sendersIP
    else:
       sendersIPNetwork = IPv4Match.group(1)

   # Grab the sender from the control files.
    try:
        sender = courier.control.getSender(controlFileList)
    except:
        return '451 Internal failure locating control files'
    if sender == '':
        # Null sender is allowed as a non-fatal error
        return ''
    sender = sender.lower()

    _sendersPassed.purge()
    _sendersNotPassed.purge()

    # Create a new MD5 object.  The sender/recipient/IP triplets will
    # be stored in the db in the form of an MD5 digest.
    senderMd5 = hashlib.md5(sender)

    # Create a digest for each triplet and look it up first in the
    # _sendersNotPassed db.  If it's found there, but is not old
    # enough to meet greylistTime, save the minimum amount of time
    # the sender must wait before retrying for the error message that
    # we'll return.  If it is old enough, remove the digest from
    # _sendersNotPassed db, and save it in the _sendersPassed db.
    # Then, check for the triplet in _sendersPassed db, and update
    # its time value if found.  If the triplet isn't found in the
    # _sendersPassed db, then create a new entry in the
    # _sendersNotPassed db, and save the minimum wait time.
    foundAll = 1
    biggestTimeToGo = 0

    for recipient in courier.control.getRecipients(controlFileList):
        recipient = recipient.lower()

        correspondents = senderMd5.copy()
        correspondents.update(recipient)
        correspondents.update(sendersIPNetwork)
        cdigest = correspondents.hexdigest()
        _sendersPassed.lock()
        _sendersNotPassed.lock()
        try:
            if _sendersNotPassed.has_key(cdigest):
                _Debug('found triplet in the NotPassed db')
                firstTimestamp = float(_sendersNotPassed[cdigest])
                timeToGo = firstTimestamp + greylistTime - time.time()
                if timeToGo > 0:
                    # The sender needs to wait longer before this delivery is allowed.
                    _Debug('triplet in NotPassed db is not old enough')
                    foundAll = 0
                    if timeToGo > biggestTimeToGo:
                        biggestTimeToGo = timeToGo
                else:
                    _Debug('triplet in NotPassed db is now passed')
                    _sendersPassed[cdigest] = time.time()
                    del(_sendersNotPassed[cdigest])
            elif _sendersPassed.has_key(cdigest):
                _Debug('triplet found in the Passed db')
                _sendersPassed[cdigest] = time.time()
            else:
                _Debug('new triplet in this message')
                foundAll = 0
                timeToGo = greylistTime
                if timeToGo > biggestTimeToGo:
                    biggestTimeToGo = timeToGo
                _sendersNotPassed[cdigest] = time.time()
        finally:
            _sendersNotPassed.unlock()
            _sendersPassed.unlock()

    if foundAll:
        return ''
    else:
        return('451 4.7.1 Greylisting in action, please come back in %s' % time.strftime("%H:%M:%S", time.gmtime(biggestTimeToGo)))


if __name__ == '__main__':
    # For debugging, you can create a file that contains one line,
    # beginning with an 's' character, followed by an email address
    # and more lines, beginning with an 'r' character, for each
    # recipient.  Run this script with the name of that file as an
    # argument, and it'll validate that email address.
    if not sys.argv[1:]:
        print 'Use: greylist.py <control file>'
        sys.exit(1)
    initFilter()
    print doFilter('', sys.argv[1:])

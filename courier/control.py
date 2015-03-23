#!/usr/bin/python
# courier.control -- python module for handling Courier message control files
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

import config
import re
import string
import time


def getLines(controlFileList, key, maxLines=0):
    """Return a list of values in the controlFileList matching key.

    "key" should be a one character string.  See the "Control Records"
    section of Courier's Mail Queue documentation for a list of valid
    control record keys.

    If the "maxLines" argument is given, it must be a number greater
    than zero.  No more values than indicated by this argument will
    be returned.

    """
    lines = []
    for cf in controlFileList:
        cfo = open(cf)
        ctlLine = cfo.readline()
        while ctlLine:
            if ctlLine[0] == key:
                lines.append(ctlLine[1:].strip())
                if maxLines and len(lines) == maxLines:
                    break
            ctlLine = cfo.readline()
        if maxLines and len(lines) == maxLines:
            break
    return lines


def getSendersMta(controlFileList):
    """Return the "Received-From-MTA" record.

    Courier's documentation indicates that this specifies what goes
    into this header for DSNs generated due to this message.

    """
    senderLines = getLines(controlFileList, 'f', 1)
    if senderLines:
        return senderLines[0]
    else:
        return None


_sender_ipv4_re = re.compile('\[(?:::ffff:)?(\d*.\d*.\d*.\d*)\]')
_sender_ipv6_re = re.compile('\[([0-9a-f:]*)\]')
def getSendersIP(controlFileList):
    """Return an IP address if one is found in the "Received-From-MTA" record."""
    sender = getSendersMta(controlFileList)
    if not sender:
        return sender
    rematch = _sender_ipv4_re.search(sender)
    if rematch and rematch.group(1):
        return rematch.group(1)
    # else, we probably have an IPv6 address
    rematch = _sender_ipv6_re.search(sender)
    return rematch.group(1)


def getSender(controlFileList):
    """Return the envelope sender."""
    senderLines = getLines(controlFileList, 's', 1)
    if senderLines:
        return senderLines[0]
    else:
        return None


def getRecipients(controlFileList):
    """Return a list of message recipients.

    This list contains addresses in canonical format, after Courier's
    address rewriting and alias expansion.

    """
    return [x[0] for x in getRecipientsData(controlFileList)]


def getRecipientsData(controlFileList):
    """Return a list of lists with details about message recipients.

    Each list in the list returned will have the following elements:
    0: The rewritten address
    1: The "original message recipient", as defined by RFC1891
    2: Zero or more characters indicating DSN behavior.

    """
    recipientsData = []
    for cf in controlFileList:
        rcpts = _getRecipientsFromFile(cf)
        for x in rcpts:
            if x[1] is False:
                recipientsData.append(x[2])
    return recipientsData


def _getRecipientsFromFile(controlFile):
    """Return a list of lists with details about message recipients.

    Each list in the list returned will have the following elements:
    0: The sequence number of this recipient
    1: Delivery status as either True (delivered) or False (not delivered)
    2: A list containing the following elements, describing this recipient:
        0: The rewritten address
        1: The "original message recipient", as defined by RFC1891
        2: Zero or more characters indicating DSN behavior.

    """

    def _addr(recipients, r):
        if r and r[0]:
            x = [len(recipients), False, r]
            recipients.append(x)

    cfo = open(controlFile)
    recipients = []
    r = ['', '', ''] # This list will contain the recipient data.
    ctlLine = cfo.readline()
    while ctlLine:
        if ctlLine[0] == 'r':
            r[0] = ctlLine[1:].strip()
        if ctlLine[0] == 'R':
            r[1] = ctlLine[1:].strip()
        if ctlLine[0] == 'N':
            r[2] = ctlLine[1:].strip()
            # This completes a new record, add it to the recipient data list.
            _addr(recipients, r)
            r = ['', '', '']
        if ctlLine[0] == 'S' or ctlLine[0] == 'F':
            # Control file records either a successful or failed
            # delivery.  Either way, mark this recipient completed.
            rnum, time = ctlLine.split(' ', 1)
            rnum = int(rnum[1:])
            recipients[rnum][1] = True
        ctlLine = cfo.readline()
    return recipients


def getControlData(controlFileList):
    """Return a dictionary containing all of the data that was given to submit.

    The dictionary will have the following elements:
    's': The envelope sender
    'f': The "Received-From-MTA" record
    'e': The envid of this message, as specified in RFC1891, or None
    't': Either 'F' or 'H', specifying FULL or HDRS in the RET parameter
         that was given in the MAIL FROM command, as specified in RFC1891,
         or None
    'V': 1 if the envelope sender address should be VERPed, 0 otherwise
    'U': The security level requested for the message
    'u': The "message source" given on submit's command line
    'r': The list of recipients, as returned by getRecipientsData

    See courier/libs/comctlfile.h in the Courier source code, and the
    submit(8) man page for more information.

    """
    data = {'s': '',
            'f': '',
            'e': None,
            't': None,
            'V': None,
            'U': '',
            'u': None,
            'r': []}
    for cf in controlFileList:
        cfo = open(cf)
        ctlLine = cfo.readline()
        while ctlLine:
            if ctlLine[0] == 's':
                data['s'] = ctlLine[1:].strip()
            if ctlLine[0] == 'f':
                data['f'] = ctlLine[1:].strip()
            if ctlLine[0] == 'e':
                data['e'] = ctlLine[1:].strip()
            if ctlLine[0] == 't':
                data['t'] = ctlLine[1:].strip()
            if ctlLine[0] == 'V':
                data['V'] = 'V'
            if ctlLine[0] == 'U':
                data['U'] = ctlLine[1:].strip()
            if ctlLine[0] == 'u':
                data['u'] = ctlLine[1:].strip()
            ctlLine = cfo.readline()
    data['r'] = getRecipientsData(controlFileList)
    return data


def addRecipient(controlFileList, recipient):
    """Add a recipient to a controlFileList set.

    The recipient argument must contain a canonical address.  Local
    aliases are not allowed.

    """
    recipientData = [recipient, '', '']
    addRecipientData(controlFileList, recipientData)


def addRecipientData(controlFileList, recipientData):
    """Add a recipient to a controlFileList set.

    The recipientData argument must contain the same information that
    is normally returned by the getRecipientsData function for each
    recipient.  Recipients should be added one at a time.

    """
    # FIXME:  How strict is courier about its upper limit of
    # recipients per control file?  It's easiest to append the
    # recipient to the last control file, but it would be more
    # robust to check the number of recipients in it first and
    # create a new file if necessary.
    if len(recipientData) != 3:
        raise ValueError('recipientData must be a list of 3 values.')
    cf = controlFileList[-1]
    cfo = open(cf, 'a')
    cfo.write('r%s\n' % recipientData[0])
    cfo.write('R%s\n' % recipientData[1])
    cfo.write('N%s\n' % recipientData[2])
    cfo.close()


def _markComplete(controlFile, recipientIndex):
    """Mark a single recipient's delivery as completed."""
    cfo = open(controlFile, 'a')
    cfo.seek(0, 2) # Seek to the end of the file
    cfo.write('I%d R 250 Ok - Removed by courier.control.py\n' %
              recipientIndex)
    cfo.write('S%d %d\n' % (recipientIndex, int(time.time())))


def delRecipient(controlFileList, recipient):
    """Remove a recipient from the list.

    The recipient arg is a canonical address found in one of the
    control files in controlFileList.

    The first recipient in the controlFileList that exactly matches
    the address given will be removed by way of marking that delivery
    complete, successfully.

    You should log all such removals so that messages are never
    silently lost.

    """
    for cf in controlFileList:
        rcpts = _getRecipientsFromFile(cf)
        for x in rcpts:
            if(x[1] is False # Delivery is not complete for this recipient
               and x[2][0] == recipient):
                _markComplete(cf, x[0])
                return


def delRecipientData(controlFileList, recipientData):
    """Remove a recipient from the list.

    The recipientData arg is a list similar to the data returned by
    getRecipientsData found in one of the control files in
    controlFileList.

    The first recipient in the controlFileList that exactly matches
    the data given will be removed by way of marking that delivery
    complete, successfully.

    You should log all such removals so that messages are never
    silently lost.

    """
    if len(recipientData) != 3:
        raise ValueError('recipientData must be a list of 3 values.')
    for cf in controlFileList:
        rcpts = _getRecipientsFromFile(cf)
        for x in rcpts:
            if(x[1] is False # Delivery is not complete for this recipient
               and x[2] == recipientData):
                _markComplete(cf, x[0])
                return


_hostname = config.me()
_auth_regex = re.compile(r'\((?:IDENT: [^,]*, )?AUTH: \S+ ([^,)]*)(?:, [^)]*)?\)\s*by %s' % _hostname)
def _checkHeader(header):
    """Search header for _auth_regex.

    If the header is not a "Received" header, return None to indicate
    that scanning should continue.

    If the header is a "Received" header and does not match the regex,
    return 0 to indicate that the filter should stop processing
    headers.

    If the header is a "Received" header and matches the regex, return
    the username used during authentication.

    """
    if header[:9] != 'Received:':
        return None
    found = _auth_regex.search(header)
    if found:
        return found.group(1)
    else:
        return 0


def getAuthUser(controlFileList, bodyFile=None):
    """Return the username used during SMTP AUTH, if available.
    
    The return value with be a string containing the username used
    for authentication during submission of the message, or None,
    if authentication was not used.
    
    The arguments are requested with controlFileList first in order
    to be more consistent with other functions in this module.
    Courier currently stores auth info only in the message header,
    so bodyFile will be examined for that information.  Should that
    ever change, and controlFileList contain the auth info, older
    filters will not break due to changes in this interface.  Filters
    written after such a change in Courier will be able to omit the
    bodyFile argument.
    
    """
    try:
        bfStream = open(bodyFile)
    except:
        return None
    header = bfStream.readline()
    while 1:
        buffer = bfStream.readline()
        if buffer == '\n' or buffer == '':
            # There are no more headers.  Scan the header we've got and quit.
            auth = _checkHeader(header)
            break
        if buffer[0] in string.whitespace:
            # This is a continuation line.  Add buffer to header and loop.
            header += buffer
        else:
            # This line begins a new header.  Check the previous header and
            # replace it before looping.
            auth = _checkHeader(header)
            if auth != None:
                break
            else:
                header = buffer
    if auth:
        return auth
    else:
        return None


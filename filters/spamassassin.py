#!/usr/bin/python
# spamassassin -- Courier filter which scans messages with spamassassin
# Copyright (C) 2007-2008  Jerome Blion <jerome@hebergement-pro.org>
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

import os.path
import sys
import commands
import email
import courier.config
import courier.xfilter

 
spamcPath = '/usr/bin/spamc'
# This is the maximum size of a message that we'll try to scan.
# 500 KiB is spamc's default.
maxMsgSize = 512000
# If you want to scan messages as a user other than the one as
# which pythonfilter runs, specify the user's name in the modules
# configuration file.
username = None
# If rejectScore is set to a number, then the score in the X-Spam-Status
# header will be used to determine whether or not to reject the message.
# Otherwise, messages will be rejected if they are spam.
rejectScore = None


def initFilter():
    courier.config.applyModuleConfig('spamassassin.py', globals())
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "spamassasinfilter" python filter\n')


def checkRejectCondition(status, resultHeader):
    if not resultHeader:
        resultHeader = ''
    else:
        resultHeader = resultHeader.replace('\n', '')
    if rejectScore is None or resultHeader == '':
        # No rejectScore is configured or spamassassin is configured not
        # to create new headers, so simply use the exit status of
        # spamc.  If the exit status is not 0, then the message is spam.
        if status != 0:
            return '554 Mail rejected - spam detected: ' + resultHeader
    elif resultHeader.startswith('Yes,'):
        # Attempt to load the score from the resultHeader.
        resultwords = resultHeader.split()
        for word in resultwords:
            if word.startswith('score='):
                score = float(word[6:])
                if score >= rejectScore:
                    return '554 Mail rejected - spam detected: ' + resultHeader
    return None


def doFilter(bodyFile, controlFileList):
    msgSize = os.path.getsize(bodyFile)
    if msgSize > maxMsgSize:
        return ''
    try:
        userarg = ''
        if username:
            userarg = ' -u ' + username
        cmd = '%s %s -s %d -E < %s' % (spamcPath, userarg, maxMsgSize, bodyFile) 
        (status,output) = commands.getstatusoutput(cmd)
    except Exception, e:
        return "454 " + str(e)

    # Parse the output of spamc into an email.message object.
    result = email.message_from_string(output)
    resultHeader = result['X-Spam-Status']

    rejectMsg = checkRejectCondition(status, resultHeader)
    if rejectMsg is not None:
        return rejectMsg

    # If the message wasn't rejected, then replace the message with
    # the output of spamc.
    try:
        mfilter = courier.xfilter.XFilter('spamassassin', bodyFile,
                                          controlFileList)
    except courier.xfilter.LoopError, e:
        # LoopError indicates that we've already filtered this message.
        return ''
    mfilter.setMessage(result)
    submitVal = mfilter.submit()
    return submitVal


if __name__ == '__main__':
    # we only work with 1 parameter
    if len(sys.argv) != 2:
        print "Usage: spamassassin.py <message body file>"
        sys.exit(0)
    initFilter()
    courier.xfilter.XFilter = courier.xfilter.DummyXFilter
    print doFilter(sys.argv[1], [])

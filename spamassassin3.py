#!/usr/bin/python
# file: spamassassin3.py
# -*- coding: iso-8859-2 -*-

import os.path
import sys
import commands
import email
import courier.config
import courier.xfilter
import courier.control
import time
import socket
import re

__VERSION__ = "0.09"

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
rejectScore = 7.0
spamcTarpit = 10.0

# fail2ban/filter.d/couriersmtp.local
# failregex = error,relay=<HOST>,.*550 User unknown
#             error,relay=<HOST>,.*554 Mail rejected - reverse DNS lookup failure
#             error,relay=<HOST>,.*554 Mail rejected - spam detected
#             error,relay=<HOST>,.*535 Authentication failed

def initFilter():
    courier.config.applyModuleConfig('spamassassin3.py', globals())
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "spamassassin3" ' + __VERSION__ + ' python filter\n')


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

    # CHECK.rDNS: nem megbizhato a spamd; van, hogy megallapitja: nincs, kozben letezik a kuldonek a rDNS-e
    #             /var/mail/.spamassassin/user_prefs: "score RDNS_NONE 5.0"
    #"""
    try:
        senders_ip = courier.control.getSendersIP(controlFileList)
        sender_revdns = socket.gethostbyaddr(senders_ip)[0]
    except:
        time.sleep(spamcTarpit)
        return '554 Mail rejected - reverse DNS lookup failure' + ' (' + senders_ip + ')'
    #"""

    # CHECK.size limit
    msgSize = os.path.getsize(bodyFile)
    if msgSize > maxMsgSize:
        return ''

    # CHECK.image-only mail
    origMsg = email.message_from_file(open(bodyFile, "r"))
    #sys.stderr.write('spamassassin3: non-text maintype:' + origMsg.get_payload(0).get_content_maintype() + '_\n')
    if origMsg.is_multipart() and len(origMsg.get_payload()) == 1\
            and (origMsg.get_payload(0).get_content_maintype() in ['image', 'application']):
        time.sleep(spamcTarpit)
        return '554 Mail rejected - this is a non-text message'

    # CHECK.small-message mail
    # FIXME  max. size 2K
    if not origMsg.is_multipart() and re.match(".*www\. [a-z0-9]+\. (com|net|org).*", origMsg.get_payload()):
        time.sleep(spamcTarpit)
        return '554 Mail rejected - this is a spacey-url ;o)'

    # CHECK.spamc exitcode
    try:
        userarg = ''
        if username:
            userarg = ' -u ' + username
        cmd = '%s %s -s %d -E < %s' % (spamcPath, userarg, maxMsgSize, bodyFile) 
        (status,output) = commands.getstatusoutput(cmd)
    except Exception, e:
        time.sleep(spamcTarpit)
        return "454 " + str(e)

    # CHECK.spam score
    result = email.message_from_string(output)
    resultHeader = result['X-Spam-Status']
    rejectMsg = checkRejectCondition(status, resultHeader)
    if rejectMsg is not None:
        time.sleep(spamcTarpit)
        return rejectMsg

    # If the message wasn't rejected, then replace the message with
    # the output of spamc.
    try:
        mfilter = courier.xfilter.XFilter('spamassassin3', bodyFile,
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
        print "Usage: spamassassin3.py <message body file>"
        sys.exit(0)
    initFilter()
    courier.xfilter.XFilter = courier.xfilter.DummyXFilter
    print doFilter(sys.argv[1], [])

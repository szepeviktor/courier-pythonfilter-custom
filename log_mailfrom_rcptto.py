#!/usr/bin/python
# file: log_mailfrom_rcptto.py
# -*- coding: utf-8 -*-

import sys
import courier.control

__VERSION__ = "0.02"

# @FIXME Use getRecipientsData()
#     RCPT TO:<viktor@szepe.net> ORCPT=rfc822;info@szepe.net

def initFilter():
    sys.stderr.write('Initialized the "log_mailfrom_rcptto" ' + __VERSION__ + ' python filter\n')

def doFilter(bodyFile, controlFileList):
    sender = courier.control.getSender(controlFileList)
    if sender:
        logsender = sender
    else:
        logsender = ''

    for rcpt in courier.control.getRecipientsData(controlFileList):
        if rcpt[1]:
            if(rcpt[1].startswith('rfc822;')):
                logrcpt = rcpt[1][7:]
            else:
                logrcpt = rcpt[1]
        else:
            logrcpt = rcpt[0]
        sys.stderr.write('log_mailfrom_rcptto.py: MAIL is coming FROM: <%s>, has ReCiPienT TO: <%s>.\n' % \
            (logsender, logrcpt))
    return ''

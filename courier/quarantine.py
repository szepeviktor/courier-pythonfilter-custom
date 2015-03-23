#!/usr/bin/python
# courier.quarantine -- python module for quarantining and releasing messages
# Copyright (C) 2008  Gordon Messmer <gordon@dragonsdawn.net>
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

import anydbm
import datetime
import email
import fcntl
import os
import time
import cPickle as pickle
import courier.config
import courier.xfilter


def _getDb():
    """Return the dbm and lock file handles."""
    config = courier.config.getModuleConfig('Quarantine')
    dbmfile = '%s/msgs.db' % config['dir']
    lockfile = '%s/msgs.lock' % config['dir']
    lock = open(lockfile, 'w')
    fcntl.flock(lock, fcntl.LOCK_EX)
    dbm = anydbm.open(dbmfile, 'c')
    return(dbm, lock)


def _closeDb(dbm, lock):
    """Unlock and close the lock and dbm files"""
    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    lock.close()
    dbm.close()


def _copyFile(source, destination):
    dfile = open(destination, 'w')
    sfile = open(source, 'r')
    dfile.write(sfile.read())


def sendNotice(message, address, sender=None):
    import smtplib
    if not sender:
        sender = 'postmaster@%s' % courier.config.me()
    msg = ('From: Mail Quarantine System <%s>\r\n'
           'To: <%s>\r\n'
           'Subject: Quarantine notice\r\n\r\n'
           '%s'
           % (sender, address, message))
    server = smtplib.SMTP('localhost')
    server.sendmail('', address, msg)
    server.quit()


def sendFailureNotice(id, address):
    message = """The quarantine system received a request from your address
to release the message with id '%s' from the quarantine.  That message
was not found.  It may have already expired.

I'm sorry that it didn't work out.  Please contact your system admin
for further assistance.
""" % id
    sendNotice(message, address)


def quarantine(bodyFile, controlFileList, explanation):
    config = courier.config.getModuleConfig('Quarantine')
    # Generate an ID for this quarantined message.  The ID will consist
    # of the inode number for the body file.  The inode number from the
    # original body file will be used for the temporary file's name.
    obodyinfo = os.stat(bodyFile)
    bodypath = '%s/tmp.%s' % (config['dir'], obodyinfo.st_ino)
    body = open(bodypath, 'w')
    bodyinfo = os.fstat(body.fileno())
    body.close()
    id = bodyinfo.st_ino
    # Copy files to quarantine
    quarantinePaths = ('%s/D%s' % (config['dir'], id), [])
    os.rename(bodypath, quarantinePaths[0])
    ctlFileExt = ''
    ctlFileNum = 0
    _copyFile(bodyFile, quarantinePaths[0])
    for x in controlFileList:
        ctlFilePath = '%s/C%s%s' % (config['dir'], id, ctlFileExt) 
        ctlFileNum += 1
        ctlFileExt = '.%s' % ctlFileNum
        _copyFile(x, ctlFilePath)
        quarantinePaths[1].append(ctlFilePath)
    # Open and lock the quarantine DB
    (dbm, lock) = _getDb()
    # Record this set of files in the DB
    dbm[repr(id)] = pickle.dumps((time.time(), quarantinePaths))
    # Unlock the DB
    _closeDb(dbm, lock)
    # Prepare notice for recipients of quarantined message
    release = 'quarantine-%s-%s@%s' % (config['siteid'],
                                       id,
                                       courier.config.me())
    days = config['days']
    expiration = datetime.date.fromtimestamp(time.time() + (days * 86400)).strftime('%a %B %d, %Y')
    # Parse the message for its sender and subject:
    try:
        bfStream = open(bodyFile)
    except:
        raise #InitError('Internal failure opening message data file')
    try:
        qmessage = email.message_from_file(bfStream)
    except Exception, e:
        # TODO: Handle this error.
        raise #InitError('Internal failure parsing message data file: %s' % str(e))
    qmessageSender = qmessage['from']
    qmessageSubject = qmessage['subject']
    message = """You received a message that was quarantined because:
%s

This message will be held in the quarantine until %s.
After that time, it will no longer be possible to release the message.

The message appears to have come from %s, although 
this address could have been forged and should not be trusted.  The
message subject was "%s".

If this was a message that you were expecting, and you know that it
is safe to continue, then send a new message to the following address
to release the quarantined message.  If you do not recognise the
sender, or were not expecting this message, then releasing it from
the quarantine could be very harmful.  You will almost always want
to simply ignore this notice.

Quarantine release address:
%s
    """ % (explanation,
           expiration,
           qmessageSender,
           qmessageSubject,
           release)
    # Mark recipients complete and send notices.
    controlData = courier.control.getControlData(controlFileList)
    for x in controlData['r']:
        courier.control.delRecipientData(controlFileList, x)
        sendNotice(message, x[0])


def release(requestedId, address):
    # Open and lock the quarantine DB
    (dbm, lock) = _getDb()
    if dbm.has_key(requestedId):
        (qtime, quarantinePaths) = pickle.loads(dbm[requestedId])
    else:
        (qtime, quarantinePaths) = (None, None)
    # Unlock the DB
    _closeDb(dbm, lock)
    # If quarantinePaths is None, then an invalid ID was requested.
    if not quarantinePaths:
        # Alert the user that his request failed
        sendFailureNotice(requestedId, address)
        return
    # Load message with XFilter
    qmsg = courier.xfilter.XFilter('quarantine', quarantinePaths[0], quarantinePaths[1])
    # Check the recipients for one matching the requestor
    for x in qmsg.getControlData()['r']:
        if(x[0] == address or
           x[1] == address or
           x[1] == '%s%s' % ('rfc822;', address)):
            # Inject the message with "submit" for requestor
            qmsg.submitInject('local', [x])
            return
    # If no address matched, alert the user that the request was invalid.
    sendFailureNotice(requestedId, address) 


def purge():
    config = courier.config.getModuleConfig('Quarantine')
    # Open and lock the quarantine DB
    (dbm, lock) = _getDb()
    minVal = time.time() - (int(config['days']) * 86400)
    for x in dbm.keys():
        (qtime, quarantinePaths) = pickle.loads(dbm[x])
        if qtime < minVal:
            # Files may have been removed for some reason, don't treat
            # that as a fatal condition.
            try:
                os.remove(quarantinePaths[0])
            except:
                pass
            for p in quarantinePaths[1]:
                try:
                    os.remove(p)
                except:
                    pass
            del dbm[x]
    # Unlock the DB
    _closeDb(dbm, lock)

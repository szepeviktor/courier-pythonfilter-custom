#!/usr/bin/python
# courier.authdaemon -- python module for Courier's authdaemon
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

import errno
import select
import socket


_socketPath = '/var/spool/authdaemon/socket'
_timeoutSock = 10
_timeoutWrite = 10
_timeoutRead = 30


class AuthDaemonError(Exception):
    """Base class for exceptions in this module."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class IoError(AuthDaemonError):
    """Exception raised by errors communicating with authdaemond.
    
    Attributes:
        message -- explanation of the error"""
    pass


class KeyError(AuthDaemonError):
    """Exception raised by lookup failures reported by authdaemond.
    
    Attributes:
        message -- explanation of the error"""
    pass


def _connect():
    try:
        authSock = socket.socket(socket.AF_UNIX)
    except socket.error:
        raise IoError('could not create socket')
    if _timeoutSock == 0:
        try:
            authSock.connect(_socketPath)
            authSock.setblocking(0)
        except socket.error:
            raise IoError('could not connect to authdaemon socket')
    else:
        # Try to connect to the non-blocking socket.  We expect connect()
        # to throw an error, indicating that the connection is in progress.
        # Use select to wait for the connection to complete, and then check
        # for errors with getsockopt.
        authSock.setblocking(0)
        try:
            authSock.connect(_socketPath)
        except socket.error, e:
            if e[0] != errno.EINPROGRESS:
                raise IoError('connection failed, error: %d, "%s"' % (e[0], e[1]))
            readySocks = select.select([authSock], [], [], _timeoutSock)
            if authSock in readySocks[0]:
                soError = authSock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if soError:
                    raise IoError('connection failed, error: %d' % soError)
            else:
                # The connection timed out.
                raise IoError('connection timed out')
    return authSock


def _writeAuth(authSock, cmd):
    try:
        # Loop: Wait for select() to indicate that the socket is ready
        # for data, and call send().  If send returns a value smaller
        # than the total length of cmd, save the remaining data, and
        # continue to attempt to send it.  If select() times out, raise
        # an exception and let the handler close the connection.
        while cmd:
            readySocks = select.select([], [authSock], [], _timeoutWrite)
            if not readySocks[1]:
                raise socket.error('Write timed out.')
            sent = authSock.send(cmd)
            if sent < len(cmd):
                cmd = cmd[sent:]
            else:
                # All the data was written, break the loop.
                break
    except socket.error:
        raise IoError('connection to authdaemon lost while sending request')


def _readAuth(authSock, term):
    data = ''
    datal = 0
    terml = len(term)
    while 1:
        readySocks = select.select([authSock], [], [], _timeoutRead)
        if not readySocks[0]:
            raise IoError('timeout when reading authdaemon reply')
        buf = authSock.recv(1024)
        if not buf:
            raise IoError('connection closed when reading authdaemon reply')
        data += buf
        datal += len(buf)
        # Detect the termination marker from authdaemon
        if datal >= terml and data.endswith(term):
            break
        if datal >= 5 and data.endswith('FAIL\n'):
            break
    return data.split('\n')


def _doAuth(cmd):
    """Send cmd to the authdaemon, and return a dictionary containing its reply."""
    authSock = _connect()
    _writeAuth(authSock, cmd)
    authData = _readAuth(authSock, '\n.\n')
    authInfo = {}
    for authLine in authData:
        if authLine == 'FAIL':
            raise KeyError('authdaemon returned FAIL')
        if '=' not in authLine:
            continue
        (authKey, authVal) = authLine.split('=',1)
        authInfo[authKey] = authVal
    return authInfo


def getUserInfo(service, uid):
    cmd = 'PRE . %s %s\n' % (service, uid)
    userInfo = _doAuth(cmd)
    return userInfo

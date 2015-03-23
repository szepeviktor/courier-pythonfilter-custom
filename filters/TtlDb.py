#!/usr/bin/python
# TtlDb -- Helper function for handling DBs of TTL tokens
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

import anydbm
import sys
import thread
import time


_dbmDir = '/var/state/pythonfilter'


class TtlDbError(Exception):
    """Base class for exceptions in this module."""
    pass


class LockError(TtlDbError):
    """Exception raised by detectable locking errors.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        self.message = message


class OpenError(TtlDbError):
    """Exception raised if there are problems creating the TtlDb instance.

    Attributes:
        message -- explanation of the error
    """
    def __init__(self, message):
        self.message = message


class TtlDb:
    """Wrapper for dbm containing tokens with a TTL.
    
    This is used when a db is required which simply tracks whether or not
    a token exists, and when it was last used.  Token values should be the
    value of time.time() when the token was last used.  The tokens will
    be removed from the db if their value indicates that they haven't been
    used within the TTL period.
    
    A TtlDb.OpenError exception will be raised if the db can't be opened.
    """
    def __init__(self, name, TTL, PurgeInterval):
        self.dbLock = thread.allocate_lock()
        try:
            self.db = anydbm.open(_dbmDir + '/' + name, 'c')
        except:
            raise OpenError('Failed to open %s db in %s, make sure that the directory exists\n' % (name, _dbmDir))
        # The db will be scrubbed at the interval indicated in seconds.
        # All records older than the "TTL" number of seconds will be 
        # removed from the db.
        self.TTL = TTL
        self.PurgeInterval = PurgeInterval
        # A value of 0 will cause the db to purge the first time the 
        # purge() function is called.  After the first time, the db
        # will not be purged until the PurgeInterval has passed.
        self.LastPurged = 0


    def lock(self):
        self.dbLock.acquire()


    def unlock(self):
        """Unlock the database"""
        try:
            # Synchronize the database to disk if the db type supports that
            try:
                self.db.sync()
            except AttributeError:
                # this dbm library doesn't support the sync() method
                pass
        finally:
            self.dbLock.release()


    def purge(self):
        """Remove all keys who have outlived their TTL.
        
        Don't call this function inside a locked section of code.
        """
        self.lock()
        try:
            if time.time() > (self.LastPurged + self.PurgeInterval):
                # Any token whose value is less than "minVal" is no longer valid.
                minVal = time.time() - self.TTL
                for key in self.db.keys():
                    if float(self.db[key]) < minVal:
                        del self.db[key]
                self.LastPurged = time.time()
        finally:
            self.unlock()


    def has_key(self, key):
        return self.db.has_key(key)


    def __getitem__(self, key):
        return self.db[key]


    def __setitem__(self, key, value):
        self.db[key] = value


    def __delitem__(self, key):
        del(self.db[key])

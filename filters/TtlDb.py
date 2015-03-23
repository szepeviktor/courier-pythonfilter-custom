#!/usr/bin/python
# TtlDb -- Helper function for handling DBs of TTL tokens
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

import sys
import thread
import time
import courier.config


class TtlDbError(Exception):
    """Base class for exceptions in this module."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class LockError(TtlDbError):
    """Exception raised by detectable locking errors.

    Attributes:
        message -- explanation of the error
    """
    pass


class OpenError(TtlDbError):
    """Exception raised if there are problems creating the TtlDb instance.

    Attributes:
        message -- explanation of the error
    """
    pass


class TtlDbPg:
    """Wrapper for SQL db containing tokens with a TTL."""
    def __init__(self, name, TTL, PurgeInterval):
        self.dbLock = thread.allocate_lock()

        import pgsql
        self.dbapi = pgsql
        self.tablename = name
        self._connect()
        # The db will be scrubbed at the interval indicated in seconds.
        # All records older than the "TTL" number of seconds will be 
        # removed from the db.
        self.TTL = TTL
        self.PurgeInterval = PurgeInterval
        # A value of 0 will cause the db to purge the first time the 
        # purge() function is called.  After the first time, the db
        # will not be purged until the PurgeInterval has passed.
        self.LastPurged = 0

    def _connect(self):
        dbConfig = courier.config.getModuleConfig('TtlDb')
        try:
            self.db = self.dbapi.connect(user=dbConfig['user'],
                                         password=dbConfig['password'],
                                         host=dbConfig['host'],
                                         port=int(dbConfig['port']),
                                         database=dbConfig['db'])
        except:
            raise OpenError('Failed to open %s SQL db, check settings in pythonfilter-modules.conf' % (dbConfig['db']))
        try:
            try:
                c = self.db.cursor()
                c.execute('CREATE TABLE %s (id CHAR(64) NOT NULL, value BIGINT NOT NULL, PRIMARY KEY(id))' % self.tablename)
                self.db.commit()
            except:
                pass
        finally:
            c.close()

    def _dbExec(self, query, params=None, reconnect=True):
        try:
            c = self.db.cursor()
            c.execute(query, params)
        except:
            c.close()
            if reconnect:
                self._connect()
                c = self._dbExec(query, params, reconnect=False)
            else:
                raise
        return c

    def _dbRead(self, query, params=None):
        c = self._dbExec(query, params)
        r = c.fetchone()
        c.close()
        if r:
            return str(r[0])
        else:
            return None

    def _dbWrite(self, query, params=None):
        c = self._dbExec(query, params)
        self.db.commit()
        c.close()

    def lock(self):
        self.dbLock.acquire()

    def unlock(self):
        """Unlock the database"""
        self.dbLock.release()

    def purge(self):
        """Remove all keys who have outlived their TTL.
        
        Don't call this function inside a locked section of code.
        """
        self.lock()
        try:
            if time.time() > (self.LastPurged + self.PurgeInterval):
                # Any token whose value is less than "minVal" is no longer valid.
                minVal = int(time.time() - self.TTL)
                self._dbWrite('DELETE FROM %s WHERE value < $1' % self.tablename,
                              (minVal,))
                self.LastPurged = time.time()
        finally:
            self.unlock()

    def has_key(self, key):
        value = self._dbRead('SELECT value FROM %s WHERE id = $1' % self.tablename,
                             (key,))
        return bool(value)

    def __getitem__(self, key):
        value = self._dbRead('SELECT value FROM %s WHERE id = $1' % self.tablename,
                             (key,))
        return value

    def __setitem__(self, key, value):
        try:
            self._dbWrite('INSERT INTO %s VALUES ($1, $2)' % self.tablename,
                          (key, int(value)))
        except self.dbapi.ProgrammingError:
            self._dbWrite('UPDATE %s SET value=$2 WHERE id=$1' % self.tablename,
                          (key, int(value)))

    def __delitem__(self, key):
        self._dbWrite('DELETE FROM %s WHERE id = $1' % self.tablename,
                      (key,))


class TtlDbDbm:
    """Wrapper for dbm containing tokens with a TTL."""
    def __init__(self, name, TTL, PurgeInterval):
        self.dbLock = thread.allocate_lock()

        import anydbm
        dmbConfig = courier.config.getModuleConfig('TtlDb')
        dbmDir = dmbConfig['dir']
        try:
            self.db = anydbm.open(dbmDir + '/' + name, 'c')
        except:
            raise OpenError('Failed to open %s db in %s, make sure that the directory exists\n' % (name, dbmDir))
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
        self.db[key] = str(int(value))

    def __delitem__(self, key):
        del(self.db[key])


_dbmClasses = {'dbm': TtlDbDbm,
               'pg': TtlDbPg}


def TtlDb(name, TTL, PurgeInterval):
    """Wrapper for db containing tokens with a TTL.
    
    This is used when a db is required which simply tracks whether or not
    a token exists, and when it was last used.  Token values should be the
    value of time.time() when the token was last used.  The tokens will
    be removed from the db if their value indicates that they haven't been
    used within the TTL period.
    
    A TtlDb.OpenError exception will be raised if the db can't be opened.
    """
    dbConfig = courier.config.getModuleConfig('TtlDb')
    type = dbConfig['type']
    return _dbmClasses[type](name, TTL, PurgeInterval)

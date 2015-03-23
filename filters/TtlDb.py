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
    pass


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


class TtlDbSQL:
    """Wrapper for SQL db containing tokens with a TTL."""

    dbapi_name = None
    paramstyle = None
    create_statement = 'CREATE TABLE %s (id CHAR(64) NOT NULL, value BIGINT NOT NULL, PRIMARY KEY(id))'
    purge_statement = 'DELETE FROM %s WHERE value < $1'
    select_statement = 'SELECT value FROM %s WHERE id = $1'
    insert_statement = 'INSERT INTO %s VALUES ($1, $2)'
    update_statement = 'UPDATE %s SET value=$2 WHERE id=$1'
    delete_statement = 'DELETE FROM %s WHERE id = $1'

    def __init__(self, name, TTL, PurgeInterval):
        self.dbLock = thread.allocate_lock()

        if self.dbapi_name is None:
            raise OpenError('Do not use TtlDbSQL directly.  Subclass and define "dbapi".')
        self.dbapi = __import__(self.dbapi_name)
        # This allows a subclass to override the SQL module's own
        # paramstyle setting, especially for modules like MySQL
        # which support multiple styles.
        if self.paramstyle is None:
            self.paramstyle = self.dbapi.paramstyle
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
                c.execute(self.create_statement % self.tablename)
                self.db.commit()
            except:
                self.db.rollback()
        finally:
            c.close()

    def _dbExec(self, query, params=None, reconnect=True):
        exec_params = None
        if params:
            if self.paramstyle == 'numeric':
                exec_params = [x[1] for x in params]
            elif(self.paramstyle == 'pyformat'
                 or self.paramstyle == 'named'):
                exec_params = dict(params)
        try:
            c = self.db.cursor()
            c.execute(query, exec_params)
        except self.dbapi.OperationalError:
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
        try:
            c = self._dbExec(query, params)
        except:
            self.db.rollback()
            raise
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
                self._dbWrite(self.purge_statement % self.tablename,
                              (('value', minVal),))
                self.LastPurged = time.time()
        finally:
            self.unlock()

    def has_key(self, key):
        value = self._dbRead(self.select_statement % self.tablename,
                             (('id', key),))
        return bool(value)

    def __getitem__(self, key):
        value = self._dbRead(self.select_statement % self.tablename,
                             (('id', key),))
        return value

    def __setitem__(self, key, value):
        try:
            self._dbWrite(self.insert_statement % self.tablename,
                          (('id', key), ('value', int(value))))
        except (self.dbapi.ProgrammingError, self.dbapi.IntegrityError):
            self._dbWrite(self.update_statement % self.tablename,
                          (('id', key), ('value', int(value))))

    def __delitem__(self, key):
        self._dbWrite(self.delete_statement % self.tablename,
                      (('id', key),))


class TtlDbPg(TtlDbSQL):
    """Wrapper for SQL db containing tokens with a TTL."""

    dbapi_name = 'pgsql'


class TtlDbPsycopg2(TtlDbSQL):
    """Wrapper for SQL db containing tokens with a TTL."""

    dbapi_name = 'psycopg2'
    purge_statement = 'DELETE FROM %s WHERE value < %%(value)s'
    select_statement = 'SELECT value FROM %s WHERE id = %%(id)s'
    insert_statement = 'INSERT INTO %s VALUES (%%(id)s, %%(value)s)'
    update_statement = 'UPDATE %s SET value=%%(value)s WHERE id=%%(id)s'
    delete_statement = 'DELETE FROM %s WHERE id = %%(id)s'


class TtlDbMySQL(TtlDbPsycopg2):
    """Wrapper for SQL db containing tokens with a TTL."""

    dbapi_name = 'MySQLdb'
    paramstyle = 'pyformat'

    def _connect(self):
        dbConfig = courier.config.getModuleConfig('TtlDb')
        try:
            # MySQLdb requires a set of parameters different than PEP 249.
            self.db = self.dbapi.connect(user=dbConfig['user'],
                                         passwd=dbConfig['password'],
                                         host=dbConfig['host'],
                                         port=int(dbConfig['port']),
                                         db=dbConfig['db'])
        except:
            raise OpenError('Failed to open %s SQL db, check settings in pythonfilter-modules.conf' % (dbConfig['db']))
        try:
            try:
                c = self.db.cursor()
                c.execute(self.create_statement % self.tablename)
                self.db.commit()
            except:
                self.db.rollback()
        finally:
            c.close()


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
               'psycopg2': TtlDbPsycopg2,
               'pg': TtlDbPg,
               'mysql': TtlDbMySQL}


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

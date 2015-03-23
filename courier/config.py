#!/usr/bin/python
# courier.config -- python module for Courier configuration access
# Copyright (C) 2003-2008  Gordon Messmer <gordon@dragonsdawn.net>
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

import anydbm
import ConfigParser
import os
import socket
import sys

try:
    import DNS
except:
    DNS = None


prefix = '/usr/lib/courier'
exec_prefix = '/usr/lib/courier'
bindir = '/usr/lib/courier/bin'
sbindir = '/usr/lib/courier/sbin'
libexecdir = '/usr/lib/courier/libexec'
sysconfdir = '/etc/courier'
datadir = '/usr/lib/courier/share'
localstatedir = '/var/spool/courier'
mailuser = 'daemon'
mailgroup = 'daemon'
mailuid = '2'
mailgid = '2'
version = 'unknown'


def _setup():
    # Get the path layout for Courier.
    (chIn, chOut) = os.popen4('courier-config')
    chOutLine = chOut.readline()
    while chOutLine != '':
        try:
            (setting, valueN) = chOutLine.split('=', 1)
            value = valueN.strip()
        except:
            chOutLine = chOut.readline()
            continue
        if setting in ('prefix', 'exec_prefix', 'bindir', 'sbindir',
                       'libexecdir', 'sysconfdir', 'datadir', 'localstatedir',
                       'mailuser', 'mailgroup', 'mailuid', 'mailgid'):
            globals()[setting] = value
        chOutLine = chOut.readline()
    # Catch the exit of courier-config
    try:
        os.wait()
    except OSError:
        pass
    # Get the version of Courier currently running.
    (chIn, chOut) = os.popen4('%s/courier --version' % sbindir)
    chOutLine = chOut.readline()
    versOutput = chOutLine.split(' ')
    if versOutput[0] == 'Courier':
        global version
        version = versOutput[1]
    # Catch the exit of courier --version
    try:
        os.wait()
    except OSError:
        pass
    # Initialize the DNS module
    if DNS:
        DNS.DiscoverNameServers()


def isMinVersion(minVersion):
    """Check for minumum version of Courier.

    Return True if the version of courier currently installed is newer
    than or the same as the version given as an argument.

    """
    if version == 'unknown':
        return False
    cur = version.split('.')
    min = minVersion.split('.')
    return cur >= min


def read1line(file):
    try:
        cfile = open(sysconfdir + '/' + file, 'r')
    except IOError:
        return None
    return cfile.readline().strip()


def me(_cached = [None]):
    """Return Courier's "me" value.

    Call this function with no arguments.

    """
    # check the cache to see if "me" has been looked up already
    # next look at the "me" config file
    # otherwise use the value of gethostname()
    if _cached[0]:
        return _cached[0]
    val = read1line('me')
    if val:
        _cached[0] = val
        return val
    val = socket.gethostname()
    _cached[0] = val
    return val


def esmtphelo(connection=None):
    """Returns a fully qualified domain name.

    The value will be computed as documented by Courier's man page. The
    optional "connection" argument should be a socket object which is
    connected to an SMTP server.

    """
    val = read1line('esmtphelo')
    if not val:
        val = me()
    if val == '*':
        if connection is None or DNS is None:
            val = me()
        else:
            val = DNS.revlookup(connection.getsockname()[0])
    return val


def defaultdomain(_cached = [None]):
    """Return Courier's "defaultdomain" value.

    Call this function with no arguments.

    """
    # check the cache to see if "defaultdomain" has been looked up already
    # next look at the "defaultdomain" config file
    # otherwise use the value of me()
    if _cached[0]:
        return _cached[0]
    val = read1line('defaultdomain')
    if val:
        _cached[0] = val
        return val
    return me()


def dsnfrom(_cached = [None]):
    """Return Courier's "dsnfrom" value.

    Call this function with no arguments.

    """
    if _cached[0]:
        return _cached[0]
    val = read1line('dsnfrom')
    if val:
        _cached[0] = val
        return val
    return '"Courier mail server at %s" <@>' % me()


def locallowercase():
    """Return True if the locallowercase file exists, and False otherwise."""
    if os.access('%s/locallowercase' % sysconfdir, os.F_OK):
        return 1
    return 0


def isLocal(domain):
    """Return True if domain is "local", and False otherwise.

    See the courier(8) man page for more information on local domains.

    """
    try:
        locals = open('%s/locals' % sysconfdir)
    except IOError:
        if domain == me():
            return 1
        return 0
    for line in locals.readlines():
        if line[0] in '#\n':
            continue
        line = line.strip()
        if line[0] == '!' and line[1:] == domain:
            return 0
        if line[0] == '.' and domain.endswith(line):
            return 1
        if line == domain:
            return 1
    return 0


def isHosteddomain(domain):
    """Return True if domain is a hosted domain, and False otherwise.

    See the courier(8) man page for more information on hosted domains.

    """
    try:
        hosteddomains = anydbm.open('%s/hosteddomains.dat' % sysconfdir, 'r')
    except anydbm.error:
        return 0
    if hosteddomains.has_key(domain):
        return 1
    parts = domain.split('.')
    for x in range(1, len(parts)):
        domainSub = '.' + '.'.join(parts[x:])
        if hosteddomains.has_key(domainSub):
            return 1
    return 0


def getAlias(address):
    """Return a list of addresses to which the address argument will expand.

    If no alias matches the address argument, None will be returned.

    """
    if '@' in address:
        atIndex = address.index('@')
        domain = address[atIndex + 1:]
        if isLocal(domain):
            address = '%s@%s' % (address[:atIndex], me())
    else:
        address = '%s@%s' % (address, me())
    try:
        aliases = anydbm.open('%s/aliases.dat' % sysconfdir, 'r')
    except anydbm.error:
        return None
    if aliases.has_key(address):
        return aliases[address].strip().split('\n')
    return None


def smtpaccess(ip):
    """ Return the courier smtpaccess value associated with the IP address."""
    # First break the IP address into parts, either IPv4 or IPv6
    if '.' in  ip:
        ipsep = '.'
    elif ':' in ip:
        ipsep = ':'
    else:
        sys.stderr.write('Couldn\'t break %s into parts\n' % ip)
        return None
    # Next, open the smtpaccess database for ip lookups
    try:
        smtpdb = anydbm.open(sysconfdir + '/smtpaccess.dat', 'r')
    except:
        sys.stderr.write('Couldn\'t open smtpaccess.dat in %s\n' % sysconfdir)
        return None
    # Search for a match, most specific to least, and return the
    # first match.
    while ip:
        if ipsep == '.' and smtpdb.has_key(ip):
            return smtpdb[ip]
        elif ipsep == ':' and smtpdb.has_key(':' + ip):
            return smtpdb[':' + ip]
        # if the ip doesn't match yet, strip off another part
        try:
            ri = ip.rindex(ipsep)
            ip = ip[:ri]
        except:
            # separator wasn't found, we don't need to search any more
            return None


def getSmtpaccessVal(key, ip):
    """Return a string from the smtpaccess database.

    The value returned will be None if the IP is not found in the
    database, or if the database value doesn\'t contain the key
    argument.

    The value returned will be '' if the IP is found, and database
    value contains the key, but the key's value is empty.

    Otherwise, the value returned will be a string.

    """
    dbval = smtpaccess(ip)
    if dbval is None:
        return None
    keyeqlen = len(key) + 1
    keyeq = key + '='
    dbvals = dbval.split(',')
    for val in dbvals:
        if val == key:
            # This item in the db matches the key, but has no
            # associated value.
            return ''
        if val.startswith(keyeq):
            val = val[keyeqlen:]
            return val


def isRelayed(ip):
    """Return a true or false value indicating the RELAYCLIENT setting in
    the access db.
    """
    if getSmtpaccessVal('RELAYCLIENT', ip) is None:
        return 0
    else:
        return 1


def isWhiteblocked(ip):
    """Return a true or false value indicating the BLOCK setting in the
    access db.

    If the client ip is specifically whitelisted from blocks in the
    smtpaccess database, the return value will be true.  If the ip is
    not listed, or the value in the database is not '', the return
    value will be false.

    """
    if getSmtpaccessVal('BLOCK', ip) is '':
        return 1
    else:
        return 0


def getBlockVal(ip):
    """Return the value of the BLOCK setting in the access db.

    The value will either be None, '', or another string which will be
    sent back to a client to indicate that mail will not be accepted
    from them.  The values None and '' indicate that the client is not
    blocked.  The value '' indicates that the client is specifically
    whitelisted from blocks.

    """
    return getSmtpaccessVal('BLOCK', ip)


_standardConfigPaths = ['/etc/pythonfilter-modules.conf',
                        '/usr/local/etc/pythonfilter-modules.conf']
def getModuleConfig(moduleName):
    """Return a dictionary of config values.

    The function will attempt to parse "pythonfilter-modules.conf" in
    "/etc" and "/usr/local/etc", and load the values from the
    section matching the moduleName argument.  If the configuration
    files aren't found, or a name was requested that is not found in
    the config file, an empty dictionary will be returned.

    The values read from the configuration file will be passed to
    eval(), so they must be valid python expressions.  They will be
    returned to the caller in their evaluated form.

    """
    config = {}
    cp = ConfigParser.RawConfigParser()
    cp.optionxform = str
    try:
        cp.read(_standardConfigPaths)
        ci = cp.items(moduleName)
    except ConfigParser.NoSectionError:
        ci = {}
    except Exception, e:
        sys.stderr.write('error parsing config module: %s, exception: %s\n' % (moduleName, str(e)))
        ci = {}
    for i in ci:
        # eval the value of this item in a new environment to
        # avoid unpredictable side effects to this modules
        # namespace
        value = eval(i[1], {})
        config[i[0]] = value
    return config


def applyModuleConfig(moduleName, moduleNamespace):
    """Modify moduleNamespace with values from configuration file.

    This function will load configuration files using the
    getModuleConfig function, and will then add or replace any names
    in moduleNamespace with the values from the configuration files.

    """
    config = getModuleConfig(moduleName)
    for i in config.keys():
        moduleNamespace[i] = config[i]


# Call _setup to correct the module path values
_setup()

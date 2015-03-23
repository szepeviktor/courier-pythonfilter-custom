#!/usr/bin/python
# debug -- Courier filter which prints process info to logs
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

import os
import sys


def initFilter():
    # Record in the system log that this filter was initialized.
    sys.stderr.write('Initialized the "debug" python filter\n')


def doFilter(bodyFile, controlFileList):
    """Print debugging information to stderr."""

    sys.stderr.write('Debugging filter invoked:\n')
    sys.stderr.write('  PID: %s\n' % os.getpid())
    sys.stderr.write('  CWD: %s\n' % os.getcwd())
    sys.stderr.write('  EUID: %s\n' % os.geteuid())
    sys.stderr.write('  EGID: %s\n' % os.getegid())
    sys.stderr.write('  UID: %s\n' % os.getuid())
    sys.stderr.write('  GID: %s\n' % os.getgid())
    sys.stderr.write('  Additional groups: %s\n' % os.getgroups())
    sys.stderr.write('  Body: %s\n' % bodyFile)
    sys.stderr.write('    Raw stat: %s\n' % os.stat(bodyFile))
    for f in controlFileList:
        sys.stderr.write('  Control file: %s\n' % f)
        sys.stderr.write('    Raw stat: %s\n' % os.stat(f))
    # Return no decision.
    return ''

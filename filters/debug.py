#!/usr/bin/python
# debug -- Courier filter which prints process info to logs
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

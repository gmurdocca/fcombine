#!/usr/bin/python
############################################################################
#
# Fcombine - An enterprise grade automounter and file server
# Copyright (C) 2013 George Murdocca
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#############################################################################

import subprocess

class PopenResult:
    def __init__(self, stdout, stderr, returncode):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

def quick_popen(cmd, auto_exception=True):
    if len(cmd) < 1:
        raise ValueError("Must pass an array with at least one element")
        
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, \
            stdout=subprocess.PIPE)

    so, se = proc.communicate()

    if proc.returncode != 0 and \
            auto_exception == True:
        error = "%s failed, returncode = %d args = %s, stdout = %s, stderr = %s" % \
                (cmd[0], proc.returncode, str(cmd), so, se)
        raise Exception(error)

    return PopenResult(so, se, proc.returncode)

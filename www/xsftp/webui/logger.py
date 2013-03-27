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

import os
import sys
import syslog

# MK TODO: unify the two log functions
def log(message):
    '''
    Writes logs to Syslog
    '''
    frame = sys._getframe(1)
    funcName = frame.f_code.co_name
    moduleName = os.path.basename(frame.f_code.co_filename).split(".")[0] # XXX: can we get the whole dot-notation of the calling function down to the module name here?
    # log to Syslog.
    if not message == "\n":
        message = "%s.%s - %s\n" % (moduleName, funcName, message)
        syslog.syslog(message)


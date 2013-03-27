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
import time
import syslog
import traceback
import threading

from LoggerFile import LoggerFile
import xsftp.common.constants
from xsftp.common.Config import config
from xsftp.common.Singleton import Singleton


class Logger(Singleton):
    """Logger is a singleton class that basically
       writes specially formatted messages to syslog
       via the log() function"""

    def __init__(self):
        if config.conf == None:
            raise Exception("Config has not been initialized")

        # logfile lock for writes
        self.log_lock = threading.Lock()

        syslog.openlog("xsftpd", 0, syslog.LOG_LOCAL1)


    def stacktrace(self, level):
        for line in traceback.format_exc().splitlines():
            self.log(level, line)


    def log(self, level, message):
        """log writes messages to syslog.  We only use syslog
           as it's lightweight and works well for both the daemon
           and the ui"""

        if message == "\n":
            return


        # get caller function and line number and class
        frame = sys._getframe(1)
        func_name = frame.f_code.co_name
        line_num = frame.f_lineno

        func_name_line = "%s:%s" % (func_name, line_num)

        caller = None
        try:
            self_argument = frame.f_code.co_varnames[0]
            instance = frame.f_locals[self_argument]
            class_name = instance.__class__.__name__
            caller = "%s.%s" % (class_name, func_name_line)
        except:
            caller = func_name_line

        # if config.DEBUG is on
        if config.DEBUG == 1:
            self.log_lock.acquire()
            long_message = "[%d] %s %s" % (level, caller, message)
            syslog.syslog(long_message)
            self.log_lock.release()

    def redirect_output(self):
        sys.stdout = LoggerFile()
        sys.stderr = LoggerFile()




#class LogFile(object):
#    def __init__(self, logger):
#        self.logger = logger
#
#    def write(self, buf):
#        logger.log(1, buf)

logger = Logger()
log = logger.log
stacktrace = logger.stacktrace

# TODO: this was disabled for the daemon.  We need to
# figure out what implications it has for the web logging
#if xsftp.common.constants.LOG_STDOUT_STDERR == True:
#    sys.stdout = LogFile(logger)
#    sys.stderr = LogFile(logger)

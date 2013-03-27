#!/usr/bin/python
############################################################################
# FTP Client library 
# ##################  
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

from xsftp.common.Logger import log
from xsftp.common.models.DirectoryServer import DirectoryServer
from threading import Thread
import DirImporterFactory
import time

class DirImporterThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        log(1, "Initialized FcombineDaemon Directory Server Importer")

    def run(self):
        while True:
            for dir_server in DirectoryServer.objects.all():
                log(6, "processing dir_server: %s" % dir_server)
                # calculate time sice last run
                # compare to specified run frequency value. If we should run:
                    # get a directory server import handler via a factory
                    # spawn the import handler in a new thread
            time.sleep(600)



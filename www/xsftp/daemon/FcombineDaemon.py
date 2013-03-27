#!/usr/bin/python
############################################################################
# The xSFTP Daemon 
# ################    
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
import subprocess
from threading import Thread

import xsftp.common.constants
from UserDAO import UserDAO
from ServerDAO import ServerDAO
from xsftp.common import mountutil
from xsftp.common import popenutil
from xsftp.common.Logger import log
from xsftp.common.Config import config
from xsftp.common.SecureXMLRPCServer import SecureXMLRPCServer
from dirimporters.DirImporterThread import DirImporterThread

class XMLRPCThread(Thread):
    def __init__(self):
        Thread.__init__(self)

        log(1, "Initializing FcombineDaemon XML RPC server")
        key_file = "/etc/pki/tls/private/fcombine_xmlrpc.key"
        cert_file = "/etc/pki/tls/certs/fcombine_xmlrpc.crt"
        ca_file = "/etc/pki/tls/certs/fcombine_xmlrpc.crt"

        self.server = SecureXMLRPCServer(("localhost", 9999), key_file,
                cert_file, ca_file)
        log(1, "Done initializing FcombineDaemon XML RPC server")

    def run(self):
        log(1, "Now listening for requests on FcombineDaemon XML RPC server")

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            log(1, "FcombineDaemon stopping")

class FcombineDaemon:

    def main(self):
        # initialize the ramdisk where all the serverlinks will be mounted
        self.init_ramdisks()
        self.init_dirimporter()
        self.init_xml_rpc_server()

    def init_xml_rpc_server(self):
        self.xml_rpc_thread = XMLRPCThread()

        self.user_dao = UserDAO()
        self.server_dao = ServerDAO()

        # expose the demand mounter to the XML RPC server
        self.xml_rpc_thread.server.add_object(self.user_dao)
        self.xml_rpc_thread.server.add_object(self.server_dao)

        # start the XML RPC server
        self.xml_rpc_thread.start()

    def init_ramdisks(self):
        # create ramdisk for server mounts
        self.create_ramdisk(xsftp.common.constants.SERVER_DIR, \
                xsftp.common.constants.SERVER_RAMDISK_SIZE_MB)

        # create ramdisk for the source home directory (i.e. Bind mount points)
        # the automounter will create something that looks like a bind
        # mount from HOMEDIR_SOURCE to /home, but it allows us to intercept
        # operations
        self.create_ramdisk(xsftp.common.constants.HOMEDIR_SOURCE, \
                xsftp.common.constants.HOME_RAMDISK_SIZE_MB)

    def init_dirimporter(self):
        # start the worker thread that periodically imports user details from
        # any defined Directory Servers
        self.dir_importer_thread = DirImporterThread()
        self.dir_importer_thread.start()

    def create_ramdisk(self, mountpoint, size):
        # ensure serverdir exists
        if not os.path.exists(mountpoint):
            os.makedirs(mountpoint)

        # see if it's already mounted
        if mountutil.is_mounted(mountpoint) == True:
            log(2, "%s was already mounted, unmounting")
            mountutil.unmount(mountpoint)

        # create the ramdisk and mount it at SERVERDIR
        mount_cmd = ["mount", "-t", "tmpfs", "-o", \
                "size=" + str(size) + "M", "tmpfs", mountpoint]

        popenutil.quick_popen(mount_cmd)



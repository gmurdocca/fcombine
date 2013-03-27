#!/usr/bin/python
############################################################################
# The xSFTP AutoMountManager
# ##########################  
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

# FIXME remove from here
import sys
sys.path.append(".")
os.environ["DJANGO_SETTINGS_MODULE"] = "xsftp.settings"
# FIXME remove end here

from Logger import log
from xsftp.common import popenutil
import xsftp.common.constants
from AutoMounter import AutoMounter
from mounters.MounterFactory import MounterFactory
from xsftp.common.models.SSHFSServer import SSHFSServer

from xsftp.common.SecureXMLRPCServer import SecureXMLRPCServer
from xsftp.common.SecureXMLRPCServer import SimpleXMLRPCRequestHandler

class AutoMountManager(object):
    """This class manages the automounter.  Basically it's the glue
       between the automounter and the database.  We use this class
       to update the automounter and tell it what to do when certain
       events occur.  This is to keep the complexity of the
       AutoMounter down as it's a confusing bit of code"""

    def __init__(self):
        self.bmp_dir = "xsftp"
        self.home_source = "/tmp/ramdisk_home"
        self.server_root_mount_point = "/tmp/server_mount_point"

        self.servers = {}
        self.mounter_factory = MounterFactory()
        # These dictionaries contain servers/bmps that have
        # been mounted at some stage.  We cannot assume
        # that they are mounted just because they're in
        # these dicts as they could go away at any stage.
        # Therefore we need to check at each step to see
        # if they're still mounted or not
        self.mounted_servers = {}
        self.mounted_bind_mounts = {}

        log(1, "AutoMountManager started")

#    def run(self):

        # TODO: check that the directory we're going to fuse
        # mount to is not mounted already
        #self.auto_mounter.main()

    def explode(self, path):
        """Explode a path into all its little giblets.
           _path_ should ideally be normalized first"""
        log(6, "explode")
        gibs = []

        head = path
        while True:

            if head == "/":
                gibs.insert(0, head)
                break

            head, tail = os.path.split(head)
            gibs.insert(0, tail)

        return gibs

    def operation_callback(self, *args, **kwargs):
        operation = args[0]

        # this basically calls self.$operation with
        # arguments as if it was part of the AutoMounter class
        try:
            log(8, "Calling %s from callback" % operation)
            getattr(self, operation)(*args[1:], **kwargs)
        except AttributeError:
            log(1, "AutoMountManager.%s called, but no function exists" % \
                    (operation))
            return

    def readdir(self, path):
        """check to see whether the directory is a bind
           mount point.  if it is, trigger the mounting"""
        log(6, "operation_callback")
        parts = self.explode(os.path.normpath(path))
        # get rid of leading /
        parts.pop(0)

        if len(parts) >= 3:
            username = parts.pop(0)
            bmp_dir = parts.pop(0)
            server_name = parts.pop(0)

            log(3, "Checking: username = %s, bmp_dir = %s, server_name = %s" % \
                    (username, bmp_dir, server_name))

            # check to see if it's a bind mount point
            if bmp_dir == self.bmp_dir:
                server = None
                try:
                    # mount the server if neccessary
                    server = self.mount_server(server_name)
                except Exception, ex:
                    log(1, "Exception while mounting server: %s, error = %s" % \
                            (server_name, str(ex)))
                    return

                try:
                    # let's mount the mofo!
                    self.mount_bmp(username, server)
                except Exception, ex:
                    log(1, "Exception while bind mounting server: %s for user: %s, error: %s" % \
                            (server_name, username, str(ex)))

                    # see if we should unmount the server straight away
                    # due to no users
                    if len(server.bind_mounts) == 0:
                        log(3, "Unmounting %s from %s due to zero users" % \
                                (server.name, server.mount_point))
                        self.unmount(server.mount_point)

                    return



    def fsdestroy(self):
        """The fuse filesystem is being destroyed.
           This means we need to unmount everything"""
        log(6, "fsdestroy")

        try:
            self.unmount_all()

            log(1, "Finished unmounting all objects")
        except Exception, ex:
            log(1, "Exception while unmounting all: %s" % str(ex))

        log(0, "AutoMounterManager stopped")

    def unmount_all(self):
        # unmount all servers and their bind mounts
        # make a copy of the list to ensure we're not
        # mutating the items we're iterating over.
        # python 3.0 safe
        
        for server_name, server in list(self.mounted_servers.items()):
            log(2, "Unmounting all mountpoints for server %s" % \
                    server.name)

            # unmount bind mounts
            for username, bind_mount_point in list(server.bind_mounts.items()):
                log(2, "Unmounting bind mount %s for server %s" %
                        (bind_mount_point, server.name))
                self.unmount_bmp(bind_mount_point)

                del server.bind_mounts[username]

            # unmount the server itself
            log(2, "Unmounting server %s" % server.name)
            self.unmount_server(server)

            del self.servers[server_name]


    def is_mounted(self, mount_point):
        log(6, "is_mounted")
        # TODO: we should cache this once we start
        # looking for mount errors

        try:
            fh = open("/proc/mounts", "r")
            for line in fh:
                test_mount_point = line.split()[1]

                try:
                    if os.path.samefile(mount_point, test_mount_point) == True:
                        return True
                except OSError, ex:
                    # Permission denied.  Happens if we compare the file
                    # with a mountpoint we don't have permission to.
                    # The only instance I know where this is possible
                    # is with fuse mountpoints where allow_root is not
                    # enabled

                    # 13 = Permission denied
                    if ex.errno != 13:
                        # reraise the error
                        raise
        finally:
            fh.close()

        return False

    def mount_bmp(self, username, server):
        #_name, server_mount_point):
        log(6, "mount_bmp")
        bind_mount_point = os.path.join(self.home_source, \
                username, self.bmp_dir, server.name)

        if self.is_mounted(bind_mount_point) == True:
            log(3, "BMP already mounted: %s" % bind_mount_point)
            return

        cmd = ["mount", "-o", "bind", server.mount_point, \
              bind_mount_point]

        popenutil.quick_popen(cmd)

        server.add_bind_mount(username, bind_mount_point)

    def unmount_bmp(self, bind_mount_point):
        cmd = ["umount", "-l", "-f", bind_mount_point]

        popenutil.quick_popen(cmd)

    def mount_server(self, server_name):
        log(6, "mount_server")
        # get the server mounter for the server name
        if server_name not in self.servers:
            log(2, "Cannot mount server %s, don't know about it!" % (server_name))
            return

        server = self.servers[server_name]

        server.mount_point = os.path.join( \
                self.server_root_mount_point, server.name)

        if os.path.exists(server.mount_point) == False:
            os.makedirs(server.mount_point)

        if self.is_mounted(server.mount_point) == True:
            log(3, "Server already mounted: %s" % server.mount_point)
            return server

        # determine the type of mounter needed
        mounter_class = self.mounter_factory.get_mounter_class( \
                server.__class__)
        mounter = mounter_class()
        mounter.mount(server)

        self.mounted_servers[server_name] = server

        return server

    def unmount_server(self, server):
        mounter_class = self.mounter_factory.get_mounter_class( \
                server.__class__)
        mounter = mounter_class()
        mounter.unmount(server)


    def add_auto_mount(self, server):
        self.servers[server.name] = server


if __name__ == '__main__':
    from xsftp.common.models.SSHFSServer import SSHFSServer
    from xsftp.common.Config import config
    config.read_config(xsftp.common.constants.DEFAULT_CONF_FILE)


    amm = AutoMountManager()

    sshfs_server = SSHFSServer()
    sshfs_server.hostname = "karma"
    sshfs_server.username = "mark"
    sshfs_server.name = "karma"
    sshfs_server.port = 22
    sshfs_server.identity_file = "/home/mark/.ssh/id_rsa"
    sshfs_server.remote_path = "/home/mark/directory with spaces"

    amm.add_auto_mount(sshfs_server)

    #am.readdir("/tmp/home/mark/xsftp/karma", None)
    #amm.run()

    key_file = "/etc/pki/tls/private/nightcrawler.inet.mknowles.com.au.key"
    cert_file = "/etc/pki/tls/certs/nightcrawler.inet.mknowles.com.au.crt"

    server = SecureXMLRPCServer(("localhost", 9999), key_file, cert_file) #,
#            requestHandler=SimpleXMLRPCRequestHandler)
    server.register_instance(amm)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log(1, "AutoMountDaemon stopping")


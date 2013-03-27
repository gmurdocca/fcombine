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
import xmlrpclib

import xsftp.common.constants
from xsftp.common import mountutil
from xsftp.common import popenutil
from xsftp.common.Logger import log
from mounters.MounterFactory import MounterFactory
from xsftp.common.models.SSHFSServer import SSHFSServer
from xsftp.common.XMLRPCClient import XMLRPCClient

class InactivityWatcherThread:
    """This thread watches the mounted servers and
       unmounts them if they're inactive for a period
       of time"""
    pass


class MountedServer:
    """This class is used to track a server that is SLAM mounted and bind
       mounted at least once.  It provides an efficient way to look up
       both the server and user components of a path being accessed"""

    def __init__(self):
        self.server = None
        # we need to track which users have bind mounted this server
        self.bind_mount_points = {}



class DemandMounter:
    """This class manages the automounter.  Basically it's the glue
       between the automounter and the database.  We use this class
       to update the automounter and tell it what to do when certain
       events occur.  This is to keep the complexity of the
       AutoMounter down as it's a confusing bit of code"""

    BMP_DIR = "xsftp"

    def __init__(self):
        self.home_source = xsftp.common.constants.HOMEDIR_SOURCE
        self.server_root_mount_point = xsftp.common.constants.SERVER_DIR

        self.mounter_factory = MounterFactory()
        self.mounted_servers = {}
#        self.mounted_bind_mounts = {}

        self.init_xml_rpc()

        log(1, "AutoMountManager started")

    def init_xml_rpc(self):
        self.xml_rpc_server = XMLRPCClient(
                "https://admin:test@localhost:9999", allow_none=True)

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

    def check_path(self, path):
        """This is triggered whenever we suspect that we might need to
           do something in reaction to a user action/system call such as
           readdir(), open(), etc.  This gives us a chance to do things
           like populate the /home directory with users or do bind mounts."""

        log(6, "check_path")
        # the path given to us resembles that of an absolute path, relative
        # to /home
        # for example, if our fuse moudle is mounted at /home, then the path
        # we'll get is /.  It's like a chroot.
        parts = self.explode(os.path.normpath(path))
        # get rid of leading /
        parts.pop(0)

        # check to see if we've got enough path components to be in
        # a bind mount point i.e. /home/${user}/xsftp/${server}/......
        if len(parts) >= 3:
            username = parts.pop(0)
            bmp = parts.pop(0)
            server_name = parts.pop(0)

            log(3, "Checking: username = %s, bmp = %s, server_name = %s" % \
                    (username, bmp, server_name))

            # check to see if it's a bind mount point
            if bmp == self.BMP_DIR:
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
                    log(1, "Exception while bind mounting server: %s for user: \
                            %s, error: %s" % (server_name, username, str(ex)))

                    # see if we should unmount the server straight away
                    # due to no users
                    if len(server.bind_mounts) == 0:
                        log(3, "Unmounting %s from %s due to zero users" % \
                                (server.name, server.mount_point))
                        self.unmount_server(server.mount_point)

                    return

    def activity(self, server_name):
        """updates the activity timer for _server_name_"""
        pass
#        self.mounted_servers[server_name].last_activity = 
#                datetime.datetime.now()

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

            del self.mounted_servers[server_name]

    def mount_server(self, server_name):
        log(6, "mount_server")

        # check to see if the server is already mounted by checking the dict
        if server_name in self.mounted_servers:
            # we're already SLAM mounted, so nothing more to do
            return

        # We're not mounted, so we need to get the server object from the daemon
        server = None
        try:
            server = self.xml_rpc_server.get_server_by_name(server_name)
        except XMLRPCClient.dex("xsftp.common.models.Server.DoesNotExist"):
            log(2, "Cannot mount server %s, don't know about it!" %
                    (server_name))
            return

        server.mount_point = os.path.join( \
                self.server_root_mount_point, server.name)

        if os.path.exists(server.mount_point) == False:
            os.makedirs(server.mount_point)

        if mountutil.is_mounted(server.mount_point) == True:
            log(3, "Server already mounted: %s" % server.mount_point)
        else:
            # determine the type of mounter needed
            mounter_class = self.mounter_factory.get_mounter_class( \
                    server.type)
            mounter = mounter_class()
            mounter.mount(server)

        self.mounted_servers[server_name] = server
        
        return server

    def unmount_server(self, server):
        mounter_class = self.mounter_factory.get_mounter_class( \
                server.__class__)
        mounter = mounter_class()
        mounter.unmount(server)



    def mount_bmp(self, username, server):
        #_name, server_mount_point):
        log(6, "mount_bmp")
        bind_mount_point = os.path.join(self.home_source, \
                username, self.BMP_DIR, server.server_name)

        if mountutil.is_mounted(bind_mount_point) == True:
            log(3, "BMP already mounted: %s" % bind_mount_point)
            return

        cmd = ["mount", "-o", "bind", server.mount_point, \
              bind_mount_point]

        popenutil.quick_popen(cmd)

        server.add_bind_mount(username, bind_mount_point)

    def unmount_bmp(self, bind_mount_point):
        cmd = ["umount", "-l", "-f", bind_mount_point]

        popenutil.quick_popen(cmd)



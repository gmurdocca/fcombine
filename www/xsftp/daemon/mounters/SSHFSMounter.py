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

import grp
import pexpect
import xsftp.common.constants
from xsftp.common import popenutil

from Mounter import Mounter

class SSHFSMounter(Mounter):
    def mount(self, server, uid=0, gid=0):
        """Mount the SSHFSServer in _server_ to
           _server.mount_point_"""

        # TODO: if we can control the read/write from the Fuse module
        # Then we don't need this code
        # TODO: remove when we're confident we dont need this, put it
        # back if we do
        # gid = str(grp.getgrnam("x_%s" % sid)[2])

        # TODO: the purpose of this is to accept the initial host key
        # instead we should ajaxify the user interface and ask the
        # user whether the host key is correct
        do_strict_key_check = "no"
        for host in paramiko.util.load_host_keys(
                xsftp.common.constants.KNOWN_HOSTS_FILE).keys():
            components = host.split(':')
            host_name = components[0].replace("[","").replace("]","")
            if len(components) == 1:
                port = 22
            elif len(components) == 2:
                port = int(components[1])

            if server.address == host_name and server.port == port:
                log(4, "Found match for '%s:%s' in known_hosts," + 
                        " performing strict key check" % (address, port))
                do_strict_key_check = "yes"

        # All the parameters passed to -o
        params = {}
        # static params
        params["port"] = server.port
        params["compression"] = "yes"
        params["cache"] = "no"
        params["default_permissions"] = None
        params["umask"] = "002"
        params["nonempty"] = None
        params["reconnect"] = None
        params["allow_other"] = None
        params["ServerAliveInterval"] = 3
        # variable params
        params["uid"] = uid
        params["gid"] = gid
        params["UserKnownHostsFile"] = xsftp.common.constants.KNOWN_HOSTS_FILE
        params["IdentityFile"] = xsftp.webui.constants.KEY_FILE_LOCATION
        # TODO implement a pexpect wrapper around sshfs that takes into account
        # the below param "password" for interactive autentication
        params["password"] = None 
        params["StrictHostKeyChecking"] = do_strict_key_check


        # join the params into a string
        # converting it to an array is more efficient than just
        # catting the strings
        options = []
        for key, value in params.items():
            if value == None:
                options.append(key)
            else:
                options.append("%s=%s" % (key, str(value)))

        options_str = ",".join(options)

        uri = "%s@%s:%s" % (server.username, server.hostname, \
                server.remote_path)
        cmd = ["sshfs", "-o", options_str, uri, server.mount_point]

        popenutil.quick_popen(cmd)
        log(1, "Server Link '%s' successfully established." %
                server.server_name)


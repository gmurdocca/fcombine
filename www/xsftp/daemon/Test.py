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
sys.path.append(".")
from xsftp.common.XMLRPCClient import XMLRPCClient


class DemandMounter:

    def __init__(self):
        self.init_xml_rpc()

    def do_shit(self):
        print "Getting valid server"
        server = self.xml_rpc_server.get_server_by_server_name("centos_sftp")
        print server.server_name
        print type(server.server_name)

        print "Getting invalid server"
        try:
            server = self.xml_rpc_server.get_server_by_server_name("centos_sfshftp")
        except XMLRPCClient.dex("xsftp.common.models.Server.DoesNotExist"):
            print "yay"
        except Exception, ex:
            print ex.__repr__()
            print "ex = " + str(ex)

    def init_xml_rpc(self):
        self.xml_rpc_server = XMLRPCClient("https://admin:test@localhost:9999",
                allow_none=True)


if __name__ == "__main__":
    dm = DemandMounter()
    dm.do_shit()

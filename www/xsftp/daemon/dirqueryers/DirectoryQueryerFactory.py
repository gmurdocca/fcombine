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

from xsftp.daemon.dirqueryers.LDAPDirectoryQueryer import LDAPDirectoryQueryer
from xsftp.daemon.dirqueryers.DirectoryQueryer import NullDirectoryQueryer


class DirectoryQueryerFactory(object):

    def __init__(self):
        self.queryer_type_mappings = {}
        self.dirserver_type_mappings["LDAPDirectoryServer"] = \
                LDAPDirectoryQueryer
        self.dirserver_type_mappings["CSVDirectoryServer"] = \
                NullDirectoryQueryer
        self.dirserver_type_mappings["LocalDirectoryServer"] = \
                NullDirectoryQueryer

    def get_queryer(self, dir_server):
        dir_server_type = dir_server.__class__.__name__
        if self.dirserver_type_mappings.has_key(dir_server_type) == False:
            raise KeyError(("Cannot instantiate Directory Server Queryer "
                            "for unknown type %s") % dir_server_type)
        else:
            return self.dirserver_type_mappings[dir_server_type](dir_server)

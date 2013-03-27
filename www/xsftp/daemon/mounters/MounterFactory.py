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

from xsftp.daemon.mounters.SSHFSMounter import SSHFSMounter

class MounterFactory(object):
    def __init__(self):
        self.type_mappings = {}
        self.type_mappings["sftp"] = SSHFSMounter
        self.type_mappings["ftp"] = FTPMounter
        self.type_mappings["cifs"] = CIFSMounter

    def get_mounter_class(self, type_):
        if self.type_mappings.has_key(type_) == False:
            raise KeyError(("Cannot instantiate mounter "
                            "for unknown type %s") % type_)
        else:
            return self.type_mappings[type_]

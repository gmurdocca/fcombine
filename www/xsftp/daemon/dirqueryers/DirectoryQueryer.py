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

class DirectoryQueryer(object):

    def __init__(self, directory_server):
        self.directory_server = directory_server

    @staticmethod
    def create(directory_server):
        return MAPPINGS[directory_server.__class__.__name__](directory_server)

    def lookup(self, username, auth_result):
        """Look up the user in the directory and return a new UserProfile"""
        raise NotImplementedError()


class NullDirectoryQueryer(DirectoryQueryer):
    def lookup(self, username, auth_result):
        return None




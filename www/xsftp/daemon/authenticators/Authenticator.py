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

from xsftp.common.Logger import log
from django.contrib.auth.models import User

class Authenticator(object):
    """Authenticator is an abstract class used to make concrete classes
       that authenticate against particular auth systems.  For example,
       concrete classes might include a local authenticator, a RADIUS
       authenticator, an LDAP authenticator, etc..."""

    def __init__(self, auth_server):
        self.auth_server = auth_server

    def authenticate(self, username, password):
        raise NotImplementedError()

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

import re
import ldap
import time
import datetime
from string import Template
from django.contrib.auth.models import User

import exceptions
from xsftp.common import constants
from xsftp.common.Logger import log
from Authenticator import Authenticator
from AuthenticatorResult import AuthenticatorResult
from xsftp.common.models.UserProfile import UserProfile
from xsftp.common.models.Configuration import Configuration
from xsftp.daemon.dirqueryers.LDAPDirectoryQueryer import LDAPDirectoryQueryer


class LDAPAuthenticator(Authenticator):

    def __init__(self, auth_server):
        Authenticator.__init__(self, auth_server)

        # test if we've got the "Use above" option
        self.queryer = LDAPDirectoryQueryer(auth_server)

    def authenticate(self, username, password):
        return self.queryer.authenticate(username, password)



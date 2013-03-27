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

from django.db import models
from SubModel import SubModel
from DirectoryServer import DirectoryServer
from LDAPServer import LDAPServer

class AuthServer(SubModel):
    '''Superclass defining a generic authentication backend server against which
       Fcombine users can authenticate'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    directory_server = models.ForeignKey(DirectoryServer)


class LDAPAuthServer(AuthServer):
    '''Each instance of this class defines an LDAP backend server against which
       a Fcombine user can authenticate'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    ldap_server = models.ForeignKey(LDAPServer)

    def __str__(self):
        return str(self.ldap_server)


class RADIUSAuthServer(AuthServer):
    '''Each instance of this class defines an RADIUS backend server against
       which a Fcombine user can authenticate'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    radius_server = models.CharField(max_length=256, null=True, blank=True)
    radius_authport = models.IntegerField() #default is 1812
    radius_secret = models.CharField(max_length=256)

    def __str__(self):
        return "%s: %s:%s" % (self.__class__.__name__, self.radius_server, \
                self.radius_authport)


class LocalAuthServer(AuthServer):
    '''This is a placeholder class that defines the local Django authentication
       system against which a user can authenticate. This class exists simply
       for consistancy with our auth server data model, and there should only
       ever be one object for this model in the DB.'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    password_complexity = models.BooleanField(default=True)

    def __str__(self):
        return "%s: Singleton" % self.__class__.__name__

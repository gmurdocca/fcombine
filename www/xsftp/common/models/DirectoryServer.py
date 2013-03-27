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
from LDAPServer import LDAPServer

class DirectoryServer(SubModel):
    '''Superclass defining a generic directory server from which fcombine user
       attributes can be obtained'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    # this attribute tells things like the UserDAO whether we need to do
    # anything beyond checking that the user exists
    local = None


class LDAPDirectoryServer(DirectoryServer):
    '''Each instance of this class defines an LDAP backend server against which
       a Fcombine user can authenticate'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    ldap_server = models.ForeignKey(LDAPServer)

    # LDAP users are remote, so they need to be queried every time
    local = False

    def __str__(self):
        return str(self.ldap_server)


class CSVDirectoryServer(DirectoryServer):
    '''Each instance of this class defines a CSV file that contains fcombine
       users' properties '''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    path = models.CharField(max_length=4096, null=False, blank=False)
    # we store both the size and the hash of the file so we can quickly
    # determine whether the file has changed without necessarily
    # recalculating the hash
    size = models.IntegerField()
    hash = models.CharField(max_length=64, null=False, blank=False)

    # CSV users only need to be looked up in the database
    local = True

    def __str__(self):
        return str(self.ldap_server)


class LocalDirectoryServer(DirectoryServer):
    '''This is a placeholder class that defines the local Django authentication
       system against which a user can authenticate. This class exists simply
       for consistancy with our auth server data model, and there should only
       ever be one object for this model in the DB.'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    password_complexity = models.BooleanField(default=True)

    # Local users are always local
    local = True

    def __str__(self):
        return "%s: Singleton" % self.__class__.__name__

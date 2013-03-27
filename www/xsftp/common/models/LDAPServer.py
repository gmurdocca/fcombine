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

class LDAPServer(models.Model):
    '''Each instance of this class defines an LDAP backend server against which
       a Fcombine user can authenticate'''

    class Admin:
        pass

    class Meta:
        app_label = "webui"

    hostname = models.CharField(max_length=256)
    port = models.IntegerField()
    use_ssl = models.BooleanField(default=True)
    bind_dn = models.CharField(max_length=256)
    bind_password = models.CharField(max_length=256)
    base_dn = models.CharField(max_length=256)
    filter = models.CharField(max_length=256)
    accept_first_cert = models.BooleanField(default=True)
    verify_cert = models.BooleanField(default=True)
    ca_cert = models.TextField()
    ldap_type = models.CharField(max_length=64, null=True, blank=True)

    # Properties governing syncronisation of properties between LDAP users and
    # their associated Fcombine user accounts.
    sync_idle_period = models.IntegerField()
    # we store the last sync time just in case the daemon has been restarted
    last_sync = models.DateTimeField(null=True)
    username_attr = models.CharField(max_length=256, null=True, blank=True)
    first_name_attr = models.CharField(max_length=256, null=True, blank=True)
    last_name_attr = models.CharField(max_length=256, null=True, blank=True)
    email_attr = models.CharField(max_length=256, null=True, blank=True)
    comment_attr = models.CharField(max_length=256, null=True, blank=True)
    expiry_attr = models.CharField(max_length=256, null=True, blank=True)
    is_active_attr = models.CharField(max_length=256, null=True, blank=True)

    def __str__(self):
        return "%s: %s:%s" % self.__class__.__name__, hostname, port



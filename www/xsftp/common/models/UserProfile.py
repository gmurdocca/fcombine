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
from django.contrib.auth.models import User

from AuthServer import AuthServer
from DirectoryServer import DirectoryServer
from xsftp.common.constants import COMMENT_LENGTH
from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity



class UserProfile(models.Model):
    '''
    One to one extension of auth.Users for the webui Django application
    '''

    class Meta:
        app_label = "webui"

    # Attributes that exist in the linked User Object are
    # username     - 30 char string
    # first_name   - 30 char string
    # last_name    - 30 char string
    # email        - email field
    # password     - string in form algorithm$salt$hash
    # is_staff     - boolean ... Designates whether this user can access the
    #                built-in admin site, but we are leeching it to
    #                differentiate between admins and operators in xsftp (cos we
    #                will never use Django's builtin admin site).
    # is_active    - boolean
    # is_superuser - boolean ... Designates that this user has all permissions
    #                without explicitly assigning them. It is not used by
    #                Fcombine, only by the built-in Django admin site. As such
    #                we only bother seting it to true for the one and only built
    #                in, default, immutable Fcombine "admin" user, just in case
    #                it needs to be used for whatever reason.
    # last_login   - date time
    # date_joined  - date time
    # user_permissions = models.ManyToManyField(Permission, verbose_name= \
    #                        _('user permissions'), blank=True, \
    #                        filter_interface=models.HORIZONTAL)
    #                  - user_permissions attribute is not used on Fcombine.
    user = models.OneToOneField(User, unique=True, primary_key=True)
    comment = models.CharField(max_length=COMMENT_LENGTH, blank=True)
    expiry = models.DateField(null=True, blank=True)
    # set below to true if the user is a demo user which implies restrictions
    # on what can be done on fcombine if demo_mode = True
    is_demo_user = models.BooleanField(default=False) 
    # auth_server is the relationship to the Authenticaion Server object to be
    # queried when authenticating this user.
    auth_server = models.ForeignKey(AuthServer)
    # the below two attributes affect local users only
    # TODO: This needs to be implemented in PAM or similar
    last_password_change = models.DateTimeField(null=True, blank=True)
    change_password_next_login = models.BooleanField(default=False)

    def getAllReadServers(self):
        '''
        Returns a list of servers which the user can read from (including
        servers they can also write to), including read permissions granted
        by virtue of group membership.
        '''
        all_read_servers = self.getEffectiveReadServers() + \
                                self.getEffectiveWriteServers()
        return sorted(all_read_servers, key=lambda x: x.server_name.lower())

    def getEffectiveReadServers(self):
        '''
        Returns a list of servers which the user can read from and *NOT* write
        to, including read permissions granted by virtue of group membership.
        '''
        read_servers = list(self.user.read_servers.all()[:])
        for group in self.user.xgroup_set.all():
            for server in group.read_servers.all():
                if server not in read_servers:
                    read_servers.append(server)
        # now purge any writeservers
        effective_read_servers = []
        for server in read_servers:
            if server not in self.getEffectiveWriteServers():
                effective_read_servers.append(server)
        effective_read_servers = sorted(effective_read_servers, \
                                        key=lambda x: x.server_name.lower())
        return effective_read_servers

    def getEffectiveWriteServers(self):
        '''
        Returns a list of servers which the user can write to, including write
        permissions granted by virtue of group membership.
        '''
        write_servers = list(self.user.write_servers.all()[:])
        for group in self.user.xgroup_set.all():
            for server in group.write_servers.all():
                if server not in write_servers:
                    write_servers.append(server)
        return sorted(write_servers, key=lambda x: x.server_name.lower())

    def getEffectiveScripts(self):
        '''
        Returns a list of scripts which the user can execute, including scripts
        the user can execute by virtue of group membership.
        '''
        exec_scripts = list(self.user.script_set.all()[:])
        for group in self.user.xgroup_set.all():
            for script in group.script_set.all():
                if script not in exec_scripts:
                    exec_scripts.append(script)
        return sorted(exec_scripts, key=lambda x: x.script_name.lower())

    def is_expired(self):
        '''
        Returns True if the user's account has expired, False if it hasn't
        expired and None if there is no expiry
        '''
        if self.expiry is not None:
            result = datetime.datetime.combine(self.expiry, \
                     datetime.time(0,0,0)) < datetime.datetime.now()
            return result
        return False

    def save(self, synchronise=True):
        '''
        synchronise option specifies whether we need to do a dbCommit and
        checkJobSanity()
        '''
        self.user.save()
        super(UserProfile, self).save()
        if synchronise:
            dbCommit()
            checkJobSanity()

    def delete(self):
        super(UserProfile, self).delete()

    def getNameString(self):
        if self.user.first_name:
            name = "%s %s" % (self.user.first_name, self.user.last_name)
            name = name.strip()
        else:
            name = self.user.username
        return name

    def  __unicode__(self):
        return User.objects.get(id=self.user_id).username

    def __str__(self):
        return self.__unicode__()

    class Admin:
        pass


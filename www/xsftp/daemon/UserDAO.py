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
from Queue import Queue
from threading import Thread
from django.contrib.auth.models import User

import authenticators.exceptions
from xsftp.common.Logger import log
from xsftp.common.models.AuthServer import AuthServer
from authenticators.Authenticator import Authenticator
from xsftp.common.models.UserProfile import UserProfile
from authenticators.AuthenticatorResult import AuthenticatorResult
from authenticators.AuthenticatorFactory import AuthenticatorFactory
from dirqueryers.DirectoryQueryerFactory import DirectoryQueryerFactory


class AuthenticatorThread(Thread):
    def __init__(self, authenticator, auth_server_id, result_queue, username, \
                password):
        Thread.__init__(self)
        self.authenticator = authenticator
        self.auth_server_id = auth_server_id
        self.result_queue = result_queue
        self.username = username
        self.password = password

    def run(self):
        result = self.authenticator.authenticate(self.username, self.password)
        result.auth_server_id = self.auth_server_id
        result.authenticator = self.authenticator
        self.result_queue.put(result)


class UserDAO(object):
    FCOMBINE_AUTH_SUCCESS, FCOMBINE_AUTH_FAILED, \
            FCOMBINE_DAEMON_ERR = range(0, 3)

#class Passwd(object):
#    def __init__(self):
#        self.name = None
#        self.passwd = None
#        self.uid = None
#        self.gid = None
#        self.gecos = None
#        self.home_dir = None
#        self.shell = None
#
#class Shadow(object):
#    def __init__(self):
#        self.namp = None
#        self.pwdp = None
#        self.lstchg = None
#        self.min = None
#        self.max = None
#        self.warn = None
#        self.inact = None
#        self.expire = None
#
#class Group(object):
#    def __init__(self):
#        self.name = None
#        self.gid = None
#        self.passwd = None
#        self.mem = []

    def __init__(self):
        # indicies for the two get*ent functions
        self.pwent_index = 0
        self.grent_index = 0


        self.init_authenticators()

    def init_authenticators(self):
        self.authenticators = {}

        auth_factory = AuthenticatorFactory()
        auth_servers = AuthServer.objects.all()

        for auth_server in auth_servers:
            auth_server = auth_server.cast()
            authenticator = auth_factory.get_authenticator(auth_server)
            self.authenticators[auth_server.id] = authenticator

    def init_directory_queryers(self):
        self.directory_queryers = {}

        directory_servers = DirectoryServer.objects.all()
        
        for directory_server in directory_servers:
            directory_server = directory_server.cast()
            directory_queryer = \
                    DirectoryQueryerFactory.get_queryer(directory_server)
            self.directory_queryers[directory_server.id] = directory_queryer


    def authenticate_user(self, username, password):
        # This function will first try to authenticate the user.  If it's
        # successful, we will query the associated directory server to
        # pull down user details.  We don't care if the directory server
        # returns nothing as it's just pretty user details etc.

        # first see if we've already seen the user, that is, they are in
        # the Fcombine database
        try:
            user = User.objects.get(username=username)
            authenticator = self.authenticators[user.userprofile.auth_server.id]
            log(6, "User found in the database, authenticator = %d" % \
                    (user.userprofile.auth_server.id))
            result = authenticator.authenticate(username, password)

            # TODO: do we need to synchronize the user/userprofile objects
            # here?

            return result.code
        except User.DoesNotExist:
            pass

        # if we're here, it's possible the user does exist, but is not in the
        # database yet, ie, they are in the process of being imported into the
        # database which may be a slow operation as it is serialised.

        # authenticate the user against each server until we're successful with
        # one, or none. We handle potential duplication of usernames across
        # different directory servers at the import phase in that we raise an
        # error if an admin tries to import a user whos username already exists
        # on the Fcombine.

        result_queue = Queue()
        auth_threads = []
        for auth_server_id, authenticator in self.authenticators.items():
            log(6, "Thread count = %d" % len(auth_threads))

            # TODO: make sure this doesn't cause memory problems if a server
            # goes down.  We should probably track if a server is having
            # problems so we can rate limit authentication
            auth_thread = AuthenticatorThread(authenticator, auth_server_id, \
                    result_queue, username, password)
            auth_threads.append(auth_thread)
            auth_thread.start()


        failed = False
        user = User()
        user_profile = UserProfile()
        for i in xrange(len(auth_threads)):
            result = result_queue.get()
            log(6, "Got result from queue")

            if result.is_successful():
                # insert the user into our database now.
                # look up the auth server and directory server for this user
                auth_server = AuthServer.objects.get(id=result.auth_server_id)
                dir_server_id = auth_server.directory_server.id
                directory_queryer = self.directory_queryers[dir_server_id]

                # look up the user in the directory
                #user_profile = result.authenticator.to_user(result.entry)
                try:
                    user_profile = directory_queryer.lookup(result)

                    # save the user profile
                    user_profile.auth_server = auth_server
                    user_profile.user.save()
                    user_profile.save()
                except DirectoryQueryException, ex:
                    log(2, "DirectoryQueryException: %s" % str(ex))

                return result.code

            if result.is_failure() == False:
                failed = True

        # if one of the authenticators failed, we give them the benefit of the
        # doubt
        if failed == True:
            return AuthenticatorResult.AUTH_FAIL
        else:
            return AuthenticatorResult.AUTH_USER_NOT_FOUND


    ##### PAM FUNCTIONS

    def pam_authenticate(self, username, password):
        """This is called to authenticate a user via PAM"""

        log(6, "pam_authenticate")
 
        # get the user object from our DB
        try:
            result = self.authenticate_user(username, password)
            if result == AuthenticatorResult.AUTH_SUCCESS:
                return self.FCOMBINE_AUTH_SUCCESS
            else:
                return self.FCOMBINE_AUTH_FAILED
        except User.DoesNotExist:
            log(2, 'Authentication failed for user "%s": User Not Found' % \
                    username)
            return self.FCOMBINE_DAEMON_ERR
        

    ##### NSS PASSWD FUNCTIONS

    def nss_getpwnam(self, username):
        """This gets a password structure by name"""
        return self.users[0]

    def nss_getpwuid(self, uid):
        """This gets a password structure by uid"""
        return self.nss_getpwnam("test3") #FIXME test3?

    def nss_setpwent(self):
        """Start the getpwent session"""
        self.pwent_index = 0

    def nss_endpwent(self):
        """End the getpwent session"""
        pass

    def nss_getpwent(self):
        """Get the password entry for the current _pwent_index_"""

        if self.pwent_index == len(self.users):
            return None
        else:
            user = self.users.values()[self.pwent_index]
            self.pwent_index += 1
            return user


    ##### NSS SHADOW FUNCTIONS

    def nss_getspnam(self, username):
        """This gets a shadow structure by username"""
        s = Shadow()
        s.namp = username
        s.pwdp = ""
        s.lstchg = -1
        s.min = -1
        s.max = -1
        s.warn = -1
        s.inact = -1
        s.expire = -1

        return s


    ##### NSS GROUP FUNCTIONS

    def nss_getgrnam(self, group_name):
        """Get a group by the group name"""
        return self.groups[group_name]

    def nss_getgrgid(self, gid):
        """Get a group by gid"""
        for group_name in self.groups:
            group = self.groups[group_name]
            if group.gid == gid:
                return group

    def nss_setgrent(self):
        """Start the getgrent session"""
        self.grent_index = 0

    def nss_endgrent(self):
        """End the getgrent session"""
        pass

    def nss_getgrent(self):
        """Get the group entry for the current _grent_index_"""

        if self.grent_index == len(self.groups):
            return None
        else:
            group = self.groups.values()[self.grent_index]
            self.grent_index += 1
            return group


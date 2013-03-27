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

from django.contrib import auth
from django.contrib.auth.models import User

from xsftp.common.Logger import log
from Authenticator import Authenticator
from xsftp.common.models import UserProfile
from AuthenticatorResult import AuthenticatorResult



class LocalAuthenticator(Authenticator):
    """Authenticate users from the local user database"""

    def authenticate(self, username, password, save=None):

        # Retrieve the user object so we can query it further
        # TODO: test that the user.last_login field gets updated with this call
        user = auth.authenticate(username=username, password=password)

        # AUTH_INVALID_PASSWORD: if user is None, the authentication has failed
        # for some reason other than the user not existing
        if user != None:
            log(1, "Authentication success: LOCAL user '%s' logged in." % \
                    username)
            return AuthenticatorResult(code=AuthenticatorResult.AUTH_SUCCESS)

        # Auth has failed if we've got this far.  Find out why.

        # Ensure user exists
        try:
            self.user = User.objects.get(username=username)
        except User.DoesNotExist:
            log(1, "Authentication failed: username '%s' not found." % username)
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_USER_NOT_FOUND)

        # AUTH_USER_DISABLED: The user is disabled
        if not self.user.is_active:
            log(1, "Authentication failed: RADIUS user '%s' is disabled." \
                    % username)
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_USER_DISABLED)

        # AUTH_USER_EXPIRED: The User is expired
        if self.user.userprofile.is_expired():
            log(1, "Authentication failed: RADIUS user '%s' has expired." \
                    % username)
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_USER_EXPIRED)

        log(1, "Authentication failed: invalid password for LOCAL user '%s'." \
                % username)
        return AuthenticatorResult(
                code=AuthenticatorResult.AUTH_INVALID_PASSWORD)

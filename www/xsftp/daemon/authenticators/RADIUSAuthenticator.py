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

import pyrad.packet
from pyrad.client import Client
from django.contrib.auth.models import User
from pyrad.dictionary import Dictionary

from xsftp.common import constants
from xsftp.common.models.Configuration import Configuration
from xsftp.common.Logger import log, stacktrace
from Authenticator import Authenticator
from AuthenticatorResult import AuthenticatorResult
from xsftp.common.models.UserProfile import UserProfile


class RADIUSAuthenticator(Authenticator):
    """Authenticate users from a RADIUS user database"""

    def authenticate(self, username, password):
        log(6, "authenticate")

        server = self.auth_server.radius_server
        port = self.auth_server.radius_authport
        secret = self.auth_server.radius_secret

        # Attempt to autenticate against the configured RADIUS server
        try:
            radius_dictionary = Dictionary(constants.RADIUS_DICTIONARY)

            log(6, ("RADIUS module connecting to server: " \
                    "%s, authport: %s") % (server, port))

            srv = Client(server=server, authport=port, \
                    secret=secret.encode("ascii"), \
                    dict=radius_dictionary)

            req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest)
            req["User-Name"] = str(username)
            req["User-Password"] = req.PwCrypt(password.encode('ascii'))
            req["NAS-Identifier"] = "fcombine"

            log(6, "Senging RADIUS Access Request to server")
            reply = srv.SendPacket(req)
            log(6, "Received reply from RADIUS server, reply code was: %s" % \
                reply.code)

            if reply.code == pyrad.packet.AccessAccept:
                log(1, "Authentication success: RADIUS user '%s' logged in." % \
                        username)
                result = AuthenticatorResult()
                result.code = AuthenticatorResult.AUTH_SUCCESS
                result.entry = username
                return result

            elif reply.code == pyrad.packet.AccessReject:
                log(1, ("Authentication failed: Access rejected for " \
                        "RADIUS user '%s'.") % username)
                # This may not necessarily be caused by an invalid password, so
                # we are forced to return a general AUTH_FAIL here
                return AuthenticatorResult(
                        code=AuthenticatorResult.AUTH_FAIL)

            else:
                log(1, ("Authentication failed: Access request failed for"
                        " RADIUS user '%s'. RADIUS packet code was: %s") \
                        % reply.code)
                return AuthenticatorResult(
                        code=AuthenticatorResult.AUTH_FAIL)

        except pyrad.client.Timeout:
            log(1, "Radius server %s:%d down" % (server, port))
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_FAIL)

        except Exception, e:
            log(1, ("Authentication failed: Error authenticating RADIUS "
                    " user '%s'. Error Type: %s, Message: %s") % \
                    (username, type(e), e.message or None))
            stacktrace(3)
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_FAIL)


    def to_user(self, entry):
        """Creates a basic Fcombine UserProfile object based on credentials"""

        log(3, "RADIUS add user, entry=%s" % str(entry))

        userprofile = UserProfile()
        userprofile.user = User()

        userprofile.user.username = entry

        return userprofile


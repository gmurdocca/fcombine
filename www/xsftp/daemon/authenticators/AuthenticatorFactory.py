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

from xsftp.daemon.authenticators.LDAPAuthenticator import LDAPAuthenticator
from xsftp.daemon.authenticators.LocalAuthenticator import LocalAuthenticator
from xsftp.daemon.authenticators.RADIUSAuthenticator import RADIUSAuthenticator


class AuthenticatorFactory(object):

    def __init__(self):
        self.server_type_mappings = {}
        self.server_type_mappings["LocalAuthServer"] = LocalAuthenticator
        self.server_type_mappings["RADIUSAuthServer"] = RADIUSAuthenticator
        self.server_type_mappings["LDAPAuthServer"] = LDAPAuthenticator

    def get_authenticator(self, auth_server):
        auth_server_type = auth_server.__class__.__name__
        if self.server_type_mappings.has_key(auth_server_type) == False:
            raise KeyError(("Cannot instantiate authenticator "
                            "for unknown type %s") % auth_server_type)
        else:
            return self.server_type_mappings[auth_server_type](auth_server)


#    def get_authenticator_by_server(self, auth_server):
#        auth_server_type = auth_server.__class__.__name__
#        if self.server_type_mappings.has_key(auth_server_type) == False:
#            raise KeyError(("Cannot instantiate authenticator "
#                            "for unknown type %s") % auth_server_type)
#        else:
#            return self.server_type_mappings[auth_server_type](auth_server)

#    def get_authenticator_by_user(self, user):
#        auth_typpe = user.auth_type
#        if self.user_type_mappings.has_key(auth_type) == False:
#            raise KeyError(("Cannot instantiate authenticator "
#                            "for unknown type %s") % type_)
#        else:
#            return self.user_type_mappings[auth_typpe]

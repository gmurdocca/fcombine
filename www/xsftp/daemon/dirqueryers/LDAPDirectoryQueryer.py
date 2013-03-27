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
from DirectoryQueryer import DirectoryQueryer
from DirectoryQueryException import DirectoryQueryException
from xsftp.common.models.UserProfile import UserProfile
from xsftp.common.models.Configuration import Configuration

# TODO: We should replace the AuthenticatorResult error conditions
# with exceptions and place exceptions like this in a separate module
class MultipleUsersException(DirectoryQueryException):
    pass

class AttributeParser(object):

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name


class Mapper(object):

    COPY_ATTRS = {"username": ["sAMAccountName"],
            "first_name": ["givenName"],
            "last_name": ["sn"],
            "email": ["mail"],
            "comment": ["description"]}

    def __init__(self, entry_attrs):
        self.entry_attrs = entry_attrs

    def __getattr__(self, attr):
        if not attr.startswith("map_"):
            raise AttributeError()

        attr = attr.replace("map_", "")
        log(6, "Getting attribute: %s" % attr)

        value = None
        if attr in self.COPY_ATTRS:
            # this is a list of all the LDAP attributes that could potentially
            # be used to populate the fcombine attribute in user/userprofile
            dir_attrs = self.COPY_ATTRS[attr]

            # we search for the first non-blank/non-null attribute and use
            # that
            for dir_attr in dir_attrs:
                if dir_attr in self.entry_attrs:
                    value = self.entry_attrs[dir_attr][0]

                    # see if we need to parse the value at all
                    parse_fn_name = "parse_%s" % dir_attr.lower()
                    if hasattr(self, parse_fn_name) == True:
                        value = getattr(self, parse_fn_name)(value)
                        

                    if value != None and len(value) != 0:
                        log(6, ("Found LDAP attribute, mapping %s to %s,"
                                " value= %s") % (dir_attr, attr, value))
                        break

        else:
            raise AttributeError()

        return lambda: value


class ActiveDirectoryMapper(Mapper):

    def map_expiry(self):
        """Convert the ugly Windows account expiry value to a Python date"""

        value = int(self.entry_attrs["accountExpires"][0])

        if value == 0x7FFFFFFFFFFFFFFF:
           return None

        expiry_date = datetime.datetime(1601, 1, 1) + \
               datetime.timedelta(microseconds=(value / 10))

#        return datetime.datetime.strftime(expiry_date, "%Y-%m-%d")
        return expiry_date


    def map_is_active(self):
        '''Convert the Windows ACCOUNTDISABLE attribute of an AD user's
           UserAccountControl attribute bitmask to a Python boolean'''

        value = self.entry_attrs["userAccountControl"][0]
        mask = int(value)
        pwr = 24
        masklist = []
        while mask:
            while mask == mask % (2**pwr):
                pwr -= 1
            masklist.append(2**pwr)
            mask = mask % (2**pwr)
        if 2 in masklist:
            return False
        else:
            return True


class GenericLDAPMapper(Mapper):
    # LDAP attributes have a "name" and an "alias".  They are synonymous for
    # searching purposes.
    # For example, commonName and cn map to the same attribute and either
    # can be used to extract the value.  Note though that the "name" will be
    # returned (i.e. "cn", even if you ask for "commonName")

    COPY_ATTRS = {"username": ["uid", "sAMAccountName", "cn"],
            "first_name": ["givenName"],
            "last_name": ["sn"],
            "email": ["mail", "email", "rfc822Mailbox"],
            "comment": ["description"],
            "expiry": ["shadowExpire"],
            "is_active": []}


    def map_is_active(self):
        return True


    def parse_shadowexpire(self, value):
        """Returns a datetime object containing the date/time at which the
           account expires"""
        # shadowExpire is expressed as the number of days since the unix epoch
        # in UTC

        # convert the value into the number of seconds since the UTC epoch
        value = int(value) * 24 * 60 * 60

        if value == 0:
            return None

        # fromtimestamp creates a datetime from the number of seconds since the
        # epoch, which we just calculated
        return datetime.datetime.fromtimestamp(value)



class LDAPDirectoryQueryer(DirectoryQueryer):
    """Authenticate users from the LDAP user database"""

    USER_ATTRS = ["username", "first_name", "last_name", "email", "is_active"]
    USER_PROFILE_ATTRS = ["comment", "expiry"]

    # ldap_servers is a mapping of LDAPServer objects to LDAPDirectoryQueryers
    ldap_servers = {}

    def __new__(cls, server, *args, **kwargs):
        # This method allows us to manipulate what instance is returned.  We
        # can be passed an AuthServer or a DirectoryServer instance.  We
        # look up what ldap server is associated with the parameter and return
        # an existing version if an object for the ldap server is already
        # instantiated.

        if server.ldap_server not in cls.ldap_servers:
            new = super(LDAPDirectoryQueryer, cls).__new__(cls, *args, **kwargs)
            cls.ldap_servers[server.ldap_server] = new
            
        return cls.ldap_servers[server.ldap_server] 

    def __init__(self, *args, **kwargs):
        Authenticator.__init__(self, *args, **kwargs)

        self.ldap_conn = None

    def connect(self):
        """Connect and bind to the LDAP server"""

        # TODO
        log(1, "IMPLEMENT CA CERT VERIFICATION AND ACCEPT FIRST CERT")

        if self.auth_server.verify_cert == False:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        # bind as the service account
        self.ldap_conn = ldap.initialize(self.get_uri())
        self.ldap_conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self.ldap_conn.set_option(ldap.OPT_REFERRALS, 0)

        bind_dn = self.auth_server.bind_dn

        try:
            self.ldap_conn.simple_bind_s(bind_dn, \
                    self.auth_server.bind_password)
            log(3, "Successful service account bind to LDAP server: %s" % \
                    self.get_uri())
        except ldap.SERVER_DOWN:
            log(1, "LDAP server %s:%d down" % (self.auth_server.hostname, \
                    self.auth_server.port))
            raise exceptions.ServerDownException

    def authenticate(self, username, password):
        #XXX: check expiry, check disabled, if we want

        try:
            user_entry = self.get_ldap_entry(username)

        except MultipleUsersException, ex:
            log(2, "LDAP authentication failure: %s" % ex)
            return AuthenticatorResult(AuthenticatorResult.AUTH_MULTIPLE_USERS)

        except DirectoryQueryException, ex:
            log(2, "LDAP authentication failure: %s" % ex)
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_FAIL)

        if user_entry == None:
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_USER_NOT_FOUND)
        user_dn = user_entry[0]

        # rebind as the user
        try:
            self.ldap_conn.simple_bind_s(user_dn, password)
            log(2, "LDAP Authentication succeeded, user dn=%s" % user_dn)
            result = AuthenticatorResult()
            result.code = AuthenticatorResult.AUTH_SUCCESS
            result.entry = user_entry
            return result

        except ldap.INVALID_CREDENTIALS:
            log(2, "LDAP invalid password user=%s" % username)
            return AuthenticatorResult(
                    code=AuthenticatorResult.AUTH_INVALID_PASSWORD)

    def lookup(self, username, auth_result):
        if auth_result != None:
            entry = auth_result.entry
        else:
            entry = self.get_ldap_entry(username)

        return entry


    def get_ldap_entry(self, username):
        """Return the entry from the LDAP server.  Returns None if the
           user is not found"""

        # check the username is valid
        if self.is_valid_username(username) == False:
            log(5, "Invalid username")
            return None

        log(6, "Attempting to connect to server: %s" % self.get_uri())

        try:
            self.connect()
        except ldap.INVALID_CREDENTIALS:
            log(2, "Service account bind failed for dn: %s" % bind_dn)
            raise DirectoryQueryException("Invalid LDAP bind credentials")
        except exceptions.ServerDownException:
            raise DirectoryQueryException("LDAP server down")


        # now search for the user
        filter_template = Template(self.auth_server.filter)
        filter = filter_template.substitute(username=username)

        log(5, "Searching, using filter: %s" % filter)
        
        results = self.ldap_conn.search_s(self.auth_server.base_dn, \
                ldap.SCOPE_SUBTREE, filter) #, ["dn"])

        # filter out referrals
        results = self.filter_results(results)

        if len(results) == 0:
            log(2, "LDAP Auth: User not found: %s" % username)
            return None

        if len(results) > 1:
            raise MultipleUsersException(
                    "LDAP Auth: Multiple users found: %s" % username)

        user_entry = results[0]

        return user_entry

    def filter_results(self, original_results):
        """Filter out all the "referrals" that MS servers give us.
           Referrals are signified by a Null as the first element"""

        results = []
        for result in original_results:
            if not (len(result) > 0 and result[0] == None):
                results.append(result)
                
        return results

    def test_server(self):
        #TODO: This will be used once we're writing GUI code
        """This function tests that the server is ok and does whatever else
           needs to be done before something like a .save()"""

        #TODO: hypothetical code atm.
        try:
            self.connect()

            self.get_type()

        except:
            pass

    def get_server_type(self, redetect=False):
        """This determines what type of LDAP server we're dealing with"""

        log(3, "Detecting LDAP server type")

        if self.auth_server.ldap_type != None and redetect != True:
            return self.auth_server.ldap_type
            
        self.connect()
        results = self.ldap_conn.search_s("", ldap.SCOPE_BASE,
                "objectClass=*", ["vendorversion", "objectClass", \
                "isGlobalCatalogReady", "vendorname"])

        log(6, "LDAP query probe result: %s" % str(results))
        if len(results) <= 0 or len(results[0]) < 2:
            log(3, "Generic LDAP server detected")
            return "GenericLDAP"

        entry = results[0][1]
        if "isGlobalCatalogReady" in entry and \
                entry["isGlobalCatalogReady"] == ["TRUE"]:
            log(3, "Active Directory LDAP server detected")
            return "ActiveDirectory"

        log(3, "No specific type of LDAP server found, using GenericLDAP")
        return "GenericLDAP"

    def get_mapper(self, server_type):
        """Return the mapper class for the string _server_type_"""

        for subclass in Mapper.__subclasses__():
            if subclass.__name__ == "%sMapper" % server_type:
                return subclass

        raise Exception("Couldn't find mapper for server_type: %s" % \
                server_type)

    def to_user(self, result):
        '''Creates and returns a Fcombine UserProfile object based on the 
           user's attributes stored within the LDAP server'''

        log(3, "LDAP add user, entry=%s" % str(entry))
        entry = result.entry

        userprofile = UserProfile()
        userprofile.user = User()

        entry_attrs = entry[1]

        server_type = self.get_server_type()
        mapper = self.get_mapper(server_type)(entry_attrs)

        for attr in self.USER_PROFILE_ATTRS:
            value = getattr(mapper, "map_%s" % attr)()
            log(6, "Setting %s to %s" % (attr, value))
            setattr(userprofile, attr, value)


        for attr in self.USER_ATTRS:
            value = getattr(mapper, "map_%s" % attr)()
            log(6, "Setting %s to %s" % (attr, value))
            setattr(userprofile.user, attr, value)

        return userprofile


    def is_valid_username(self, username):
        return re.search(constants.USERNAME_PATTERN, username) != None

    def get_uri(self):
        if self.auth_server.use_ssl == True:
            proto = "ldaps"
        else:
            proto = "ldap"

        return "%s://%s:%d" % (proto, self.auth_server.hostname, \
                self.auth_server.port)

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
import sys
import httplib
import xmlrpclib
from httplib import HTTPS
from urlparse import urlparse
from xmlrpclib import Transport


class SaferTransport(Transport):
    """HTTPS transport that supports certificate authentication.  This
       subclasses the Transport class from xmlrpclib and uses SafeTransport
       as a basis."""

    def __init__(self, key_file, cert_file):
        Transport.__init__(self)
        self.key_file = key_file
        self.cert_file = cert_file

        # in pyth version 2.7 upwards, the xmlrpclib.Transport library seems
        # to re-use connections or for some other reason likes to store the
        # connection in self._connection.  This version is designed to work
        # with both without clobbering either.  This is potentially brittle
        # code, so we check the python version so we can revise things if
        # neccessary

        if sys.version_info[0] == 2 and sys.version_info[1] not in (6,7):
            sys.stderr.write("SaferTransport implementation has not been " + \
                    "checked in this version.  Please check to make sure " + \
                    "it still works\n")

        self._connection = (None, None)

    def make_connection(self, host):
        if self._connection and host == self._connection[0]:
            return self._connection[1]

        # note the use of HTTPS instead of HTTPSConnection.  At some stage
        # they'll probably remove the HTTPS class (please jesus)

        self._connection = host, HTTPS(host, None, self.key_file, \
                self.cert_file)
        return self._connection[1]




class DictWithAttributes(dict): 
    """This class takes a dict that is returned from an XML RPC call and turns
       it into an object with the same attributes.  This allows us to treat the
       returned dict like the objects that we feed in."""

    def __getattr__(self, attr):
        return self[attr]
 

class TidyXMLRPCCall(object):
    """This class takes a function.   What we end up with is an object
       that is callable.  This allows us to wrap the underlying function
       and tidy up the results it returns."""
   
    def __init__(self, function):
        self.function = function

    def __call__(self, *args, **kwargs):
        try:
            value = self.function(*args, **kwargs)
        except xmlrpclib.Fault, ex:
            # Format of an XML RPC Fault:
            # <class 'xsftp.common.models.Server.DoesNotExist'>:Server matching
            # query does not exist.

            re_raise = False
            try:
                match = re.match("<class '(.+)'>(:(.+))?", ex.faultString)

                exception_text = None
                if match.lastindex == 1:
                    exception_name = match.group(1)
                elif match.lastindex == 2:
                    exception_name = match.group(1)
                    exception_text = match.group(3)
                else:
                    raise

                raise XMLRPCClient.dex(exception_name)

            except re.error:
                re_raise = True

            if re_raise == True:
                raise


        if type(value).__name__ == "dict":
            return DictWithAttributes(value)
        else:
            return value

class CallableString:
    """This class creates a "callable" string.  It's just a way of creating
       a __str__ function basically for our dynamic exceptions"""
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class XMLRPCClient(object):
    exceptions = {}

    @staticmethod
    def dex(name):
        """dex stands for "Dynamic Exception".  We basically pass the string
           of an exception that would be thrown on the remote end to this
           function and it will create a unique exception class based on the
           name that can be caught and reused wherever by simply using the
           name.  For example:

           try:
                client.remote_call("hello")
           except XMLRPCClient.dex("RemoteException"):
               print "do something"
           """
            
        if name in XMLRPCClient.exceptions:
            return XMLRPCClient.exceptions[name]
        else:
            skel_exception = type(name, (Exception,),
                    {"__str__": CallableString(name)})
            skel_exception.__module__ = None
            XMLRPCClient.exceptions[name] = skel_exception

            return skel_exception

    def __init__(self, key_file=None, cert_file=None, *args, **kwargs):
        uri = args[0]
        uri_parts = urlparse(uri)

        args["transport"] = SaferTransport(key_file, cert_file)
        self.server_proxy = xmlrpclib.ServerProxy(*args, **kwargs)


    def __getattr__(self, attr):
        original_function = getattr(self.server_proxy, attr)
        return TidyXMLRPCCall(original_function)


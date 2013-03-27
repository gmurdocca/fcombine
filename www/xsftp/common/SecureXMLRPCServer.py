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
import ssl
import fcntl
import socket
import inspect
import SocketServer

import SocketServer
from OpenSSL import SSL
import SimpleHTTPServer
import BaseHTTPServer
import SimpleXMLRPCServer
from base64 import b64decode
from SocketServer import ThreadingMixIn
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler

from Logger import log, stacktrace


class LoggingRequestHandler(SimpleXMLRPCRequestHandler):
    """This request handler simply logs the peer details
       such as IP, port, cipher and certificate"""


    def parse_request(self):
        log(5, "XMLRPC Request, peer: %s, cipher: %s" % \
                (str(self.connection.getpeername()),
                str(self.connection.cipher())))

        log(6, "XMLRPC Request, Peer Cert: %s" % \
                str(self.connection.getpeercert()))

        if SimpleXMLRPCRequestHandler.parse_request(self):
            return True

        return True


class VerifyingRequestHandler(SimpleXMLRPCRequestHandler):
    """This request handler can be used to authenticate via
       username and password in conjunction with certificate
       based authentication.  If ever needed."""

    def parse_request(self):
        if SimpleXMLRPCRequestHandler.parse_request(self):
            if self.authenticate(self.headers):
                return True
            else:
                self.send_error(401, "Authentication Failed")
                return False

    def authenticate(self, headers):
        return True
        (basic, _, encoded) = headers.get("Authorization").partition(" ")
        assert basic == "Basic", "Only basic auth supported"

        encoded_byte_string = encoded.encode()
        decoded_string = b64decode(encoded_byte_string).decode()
        (username, _, password) = decoded_string.partition(":")

        if username == "testusername" and password == "testpassword":
            return True

        return False

class RequestDispatcher(object):
    def __init__(self):
        self.functions = {}

    def add_object(self, instance):
        # find all the functions in the object
        for member in inspect.getmembers(instance):
            if inspect.ismethod(member[1]):
                log(6, "XMLRPC Server Registered %s.%s" % \
                        (instance.__class__.__name__, member[0]))
                self.functions[member[0]] = member[1]

    def _dispatch(self, method, params):
        try:
            self.functions[method](*params)
        except Exception, e:
            stacktrace(1)
            # this exception will go to the client
            raise Exception("XMLRPC Exception, please contact support")



class SecureXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer.SimpleXMLRPCServer):
    """A SSL enabled XML RPC Server.  Note that we need the ThreadingMixIn
       to make the server multi-threaded.  Otherwise it will block until a
       single request completes."""

    def __init__(self, address, key_file, cert_file, ca_cert, \
            requestHandler=SimpleXMLRPCRequestHandler, \
            logRequests=True, allow_none=True, encoding=None, \
            bind_and_activate=True):

        if os.path.exists(key_file) == False:
            raise IOError("Key file %s does not exist" % key_file)

        if os.path.exists(key_file) == False:
            raise IOError("Cert file %s does not exist" % cert_file)

        self.logRequests = logRequests
        SimpleXMLRPCServer.SimpleXMLRPCDispatcher.__init__(self,
                allow_none, encoding)


        # if we want username/password authentication, pass in
        # VerifyingRequestHandler instead
        SocketServer.BaseServer.__init__(self, address, requestHandler)

        self.socket = ssl.wrap_socket(
                socket.socket(self.address_family, self.socket_type), \
                server_side=True, keyfile=key_file, certfile=cert_file, \
                cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1, \
                ca_certs=ca_cert)


        if bind_and_activate:
            self.server_bind()
            self.server_activate()

        # manage threads properly
        if fcntl is not None and hasattr(fcntl, "FD_CLOEXEC"):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)

        self.request_dispatcher = RequestDispatcher()
        self.register_instance(self.request_dispatcher)

    def add_object(self, instance):
        self.request_dispatcher.add_object(instance)



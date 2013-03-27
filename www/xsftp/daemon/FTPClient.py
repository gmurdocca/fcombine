#!/usr/bin/python
############################################################################
# FTP Client library 
# ##################  
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

import socket
from M2Crypto.SSL import Connection, Checker, Context, SSLError, SSLTimeoutError

################
## Constants
################

_GLOBAL_DEFAULT_TIMEOUT = 5

CRLF = '\r\n'

PORT_SOCKET_TIMEOUT = 10 #time in seconds to wait for active ftp servers to connect to our Port socket.

# Magic number from <socket.h>
MSG_OOB = 0x1                           # Process data out of band

# The standard FTP server control port
FTP_PORT = 21

# Exception raised when an error or invalid response is received
class Error(Exception): pass
class error_reply(Error): pass                  # unexpected [123]xx reply
class error_temp(Error): pass                   # 4xx errors
class error_perm(Error): pass                   # 5xx errors
class error_proto(Error): pass                  # response does not begin with [1-5]
class error_ssl(Error): pass                    # ssl protocol error (socket endpoint doesnt support ssl)
class error_timeout(Error): pass                # timeout waiting for response to an FTP command from endpoint
class error_wrong_service(Error): pass          # endpoint socket doesn't seem to serve FTP
class error_data_channel(Error): pass           # error establishing data channel
class error_bad_credentials(Error): pass        # bad credentials
class error_ftps_not_supported(Error): pass     # FTPS not supported (or wrong service)
class error_ftpes_not_supported(Error): pass    # FTPES not supported
class error_bad_remote_path(Error): pass        # CWD failed due to bad remote path
class error_ftpes_required(Error): pass         # ftp session requires FTPES
class error_ssl_error(Error): pass              # SSL error raised by M2Crypto.SSLError
class error_ssl_timeout(Error): pass            # SSL timeout

###########################
## Classes and Functions
###########################

class ssl_socket(socket.socket):

    def connect(self, addr, *args):
        self.addr = addr
        return super(ssl_socket, self).connect(addr, *args)

    def close(self):
        if hasattr(self, 'conn'):
            self.conn.close()
        super(ssl_socket, self).close()


class socket_wrapper(object):
    '''
    Used to wrap a socket object so that we can add the 'conn' attribute to it in the ssl function below.
    '''

    def __init__(self, socket):
        self._socket = socket 

    def __getattr__(self, var):
        return self._socket.__getattribute__(var)


def ssl(sock, verify=False):
    ctx = Context()
    sock.conn = Connection(ctx=ctx, sock=sock)
    sock.conn.setup_ssl()
    sock.conn.set_connect_state()
    try:
        sock.conn.connect_ssl()
    except SSLError, e:
        raise error_ssl, e
    except SSLTimeoutError, e:
        raise error_ssl_timeout, e
    if verify:
        sock.conn.addr = sock.addr
        check = getattr(sock.conn, 'postConnectionCheck', sock.conn.clientPostConnectionCheck)
        if check is not None:
            if not check(sock.conn.get_peer_cert(), sock.conn.addr[0]):
                raise Checker.SSLVerificationError, 'post connection check failed'
    return sock.conn

# clobber the below two labels, replacing them with our own stuff that we just defined
socket.socket = ssl_socket
socket.ssl = ssl


class FTP:

    debugging = 0
    host = ''
    port = FTP_PORT
    sock = None
    file = None
    welcome = None
    passiveserver = True

    def __init__(self, host, port=FTP_PORT, user='', passwd='', acct='',
                 timeout=_GLOBAL_DEFAULT_TIMEOUT, passive=True,
                 ssl=False, ssl_implicit=False):
        self.passiveserver = passive
        self.timeout = timeout
        self.user = user
        self.passwd = passwd
        self.acct = acct
        self.ssl = ssl
        self.ssl_implicit = ssl_implicit
        # establish the control channel connection
        self.connect(host, port)

    def create_connection(self, host_port, timeout):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(host_port)
        return sock

    def connect(self, host, port, timeout=-999):
        '''
        Creates the FTP CONTROL connection.
        '''
        self.host = host
        self.port = port
        if timeout != -999:
            self.timeout = timeout
        # this call can raise socket.gaierror or socket.error, each of which are handled in the xsftpd daemon
        self.sock = self.create_connection((self.host, self.port), self.timeout)
        self.af = self.sock.family
        if self.ssl and self.ssl_implicit:
            try:
                self.sock = socket.ssl(self.sock)
            except error_ssl, e:
                raise error_ftps_not_supported, e
        self.file = self.sock.makefile('rb')
        try:
            self.welcome = self.getresp()
        except error_timeout, e:
            raise error_wrong_service, e
        return self.welcome

    def login(self, user = '', passwd = '', acct = ''):
        if self.ssl and not self.ssl_implicit:
            self.auth()
        if not user:
            user = self.user or "anonymous"
        if not passwd:
            passwd = self.passwd or 'anonymous@example.com'
        try:
            resp = self.sendcmd('USER %s' % user)
        except error_perm, e:
            raise error_ftpes_required, e
        if resp[0] == '3':
            try:
                resp = self.sendcmd('PASS %s' % passwd)
            except error_perm, e:
                raise error_bad_credentials, e
        if resp[0] == '3': resp = self.sendcmd('ACCT ' + acct)
        if resp[0] != '2':
            raise error_reply, resp
        return resp

    def acct(self, password):
        '''Send new account name.'''
        cmd = 'ACCT ' + password
        return self.voidcmd(cmd)

    def auth(self):
        '''Set up secure control connection by using TLS/SSL.'''
        if not isinstance(self.sock, ssl_socket):
            raise ValueError("Already using TLS")
        if not self.ssl_implicit:
            try:
                resp = self.voidcmd('AUTH TLS')
            except Exception, e:
                raise error_ftpes_not_supported, e
        self.sock = socket.ssl(self.sock)
        self.file = self.sock.makefile(mode='rb')
        return resp

    def getwelcome(self):
        if self.debugging:
            print '*welcome*', self.sanitize(self.welcome)
        return self.welcome

    def set_debuglevel(self, level):
        '''Set the debugging level.
        The required argument level means:
        0: no debugging output (default)
        1: print commands and responses but not body text etc.
        2: also print raw lines read and sent before stripping CR/LF'''
        self.debugging = level

    def set_pasv(self, val):
        self.passiveserver = val

    # Internal: "sanitize" a string for printing, i.e. mask the passwd if any
    def sanitize(self, s):
        if s[:5] == 'pass ' or s[:5] == 'PASS ':
            i = len(s)
            while i > 5 and s[i-1] in '\r\n':
                i = i-1
            s = s[:5] + '*'*(i-5) + s[i:]
        return repr(s)

    # Internal: send one line to the server, appending CRLF
    def putcmd(self, line):
        line = line + CRLF
        if self.debugging > 1: print '*put*', self.sanitize(line)
        self.sock.sendall(line)

    # Internal: return one line from the server, stripping CRLF.
    # Raise EOFError if the connection is closed
    def getline(self):
        try:
            line = self.file.readline()
        # if endpoint doesnt respond to our FTP command within <global timeout> seconds...
        except SSLTimeoutError, e:
            raise error_timeout, e
        except socket.timeout, e:
            raise error_timeout, e
        except SSLError, e:
            raise error_ssl_error, e
        if self.debugging > 1:
            print '*get*', self.sanitize(line)
        if not line: raise EOFError
        if line[-2:] == CRLF: line = line[:-2]
        elif line[-1:] in CRLF: line = line[:-1]
        return line

    # Internal: get a response from the server, which may possibly
    # consist of multiple lines.  Return a single string with no
    # trailing CRLF.  If the response consists of multiple lines,
    # these are separated by '\n' characters in the string
    def getmultiline(self):
        line = self.getline()
        if line[3:4] == '-':
            code = line[:3]
            while 1:
                nextline = self.getline()
                line = line + ('\n' + nextline)
                if nextline[:3] == code and \
                        nextline[3:4] != '-':
                    break
        return line

    # Internal: get a response from the server.
    # Raise various errors if the response indicates an error
    def getresp(self):
        resp = self.getmultiline()
        if self.debugging: print '*resp*', self.sanitize(resp)
        self.lastresp = resp[:3]
        c = resp[:1]
        if c in ('1', '2', '3'):
            return resp
        if c == '4':
            raise error_temp, resp
        if c == '5':
            raise error_perm, resp
        raise error_proto, resp

    def voidresp(self):
        """Expect a response beginning with '2'."""
        resp = self.getresp()
        if resp[:1] != '2':
            raise error_reply, resp
        return resp

    def sendcmd(self, cmd):
        '''Send a command and return the response.'''
        self.putcmd(cmd)
        return self.getresp()

    def voidcmd(self, cmd):
        """Send a command and expect a response beginning with '2'."""
        self.putcmd(cmd)
        return self.voidresp()

    def sendport(self, host, port):
        '''Send a PORT command with the current host and the given
        port number.
        '''
        hbytes = host.split('.')
        pbytes = [repr(port//256), repr(port%256)]
        bytes = hbytes + pbytes
        cmd = 'PORT ' + ','.join(bytes)
        return self.voidcmd(cmd)

    def sendeprt(self, host, port):
        '''Send a EPRT command with the current host and the given port number.'''
        af = 0
        if self.af == socket.AF_INET:
            af = 1
        if self.af == socket.AF_INET6:
            af = 2
        if af == 0:
            raise error_proto, 'unsupported address family'
        fields = ['', repr(af), host, repr(port), '']
        cmd = 'EPRT ' + '|'.join(fields)
        return self.voidcmd(cmd)

    def makeport(self):
        '''Create a new socket and send a PORT command for it.'''
        msg = "getaddrinfo returns an empty list"
        sock = None
        for res in socket.getaddrinfo(None, 0, self.af, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                sock.bind(sa)
            except socket.error, msg:
                if sock:
                    sock.close()
                sock = None
                continue
            break
        if not sock:
            raise socket.error, msg
        sock.listen(1)
        port = sock.getsockname()[1] # Get proper port
        host = self.sock.getsockname()[0] # Get proper host
        if self.af == socket.AF_INET:
            resp = self.sendport(host, port)
        else:
            resp = self.sendeprt(host, port)
        return sock

    def makepasv(self):
        if self.af == socket.AF_INET:
            host, port = parse227(self.sendcmd('PASV'))
        else:
            host, port = parse229(self.sendcmd('EPSV'), self.sock.getpeername())
        return host, port

    def print_line(line):
        print line

    def retrlines(self, cmd, callback=None):
        """Retrieve data in line mode.  A new port is created for you.
        Args:
          cmd: A RETR, LIST, NLST, or MLSD command.
        Returns:
          The response code.
        """
        if callback is None: callback = print_line
        resp = self.sendcmd('TYPE A')
        conn = self.transfercmd(cmd)
        fp = conn.makefile('rb')
        while 1:
            line = fp.readline()
            if self.debugging > 2: print '*retr*', repr(line)
            if not line:
                break
            if line[-2:] == CRLF:
                line = line[:-2]
            elif line[-1:] == '\n':
                line = line[:-1]
            callback(line)
        fp.close()
        conn.close()
        return self.voidresp()

    def transfercmd(self, cmd, rest=None):
        """Like ntransfercmd() but returns only the socket."""
        return self.ntransfercmd(cmd, rest)[0]

    def ntransfercmd(self, cmd, rest=None):
        """Initiate a transfer over the data connection.

        If the transfer is active, send a port command and the
        transfer command, and accept the connection.  If the server is
        passive, send a pasv command, connect to it, and start the
        transfer command.  Either way, return the socket for the
        connection and the expected size of the transfer.  The
        expected size may be None if it could not be determined.

        Optional `rest' argument can be a string that is sent as the
        argument to a REST command.  This is essentially a server
        marker used to tell the server to skip over any data up to the
        given marker.
        """
        size = None
        if self.passiveserver:
            # request a secure data connection (via the control connection) if required
            if self.ssl:
                self.prot_p()
            host, port = self.makepasv()
            try:
                conn = self.create_connection((host, port), self.timeout)
            except socket.gaierror, e:
                raise error_data_channel, e
            except socket.error, e:
                raise error_data_channel, e
            try:
                if rest is not None:
                    self.sendcmd("REST %s" % rest)
                resp = self.sendcmd(cmd)
            except error_timeout, e:
                raise error_data_channel, e
            # Some servers apparently send a 200 reply to
            # a LIST or STOR command, before the 150 reply
            # (and way before the 226 reply). This seems to
            # be in violation of the protocol (which only allows
            # 1xx or error messages for LIST), so we just discard
            # this response.
            if resp[0] == '2':
                resp = self.getresp()
            if resp[0] != '1':
                raise error_reply, resp
        else:
            sock = self.makeport()
            # request a secure data connection (via the control connection) if required
            if self.ssl:
                self.prot_p()
            try:
                if rest is not None:
                    self.sendcmd("REST %s" % rest)
                resp = self.sendcmd(cmd)
            except error_timeout, e:
                raise error_data_channel, e
            # See above.
            if resp[0] == '2':
                resp = self.getresp()
            if resp[0] != '1':
                raise error_reply, resp
            sock.settimeout(PORT_SOCKET_TIMEOUT)
            try:
                conn, sockaddr = sock.accept()
            except socket.timeout, e:
                raise error_timeout("Server did not establish FTP DATA connection within %s seconds" % PORT_SOCKET_TIMEOUT) 
        if resp[:3] == '150':
            # this is conditional in case we received a 125
            size = parse150(resp)
        # secure the data connection if required
        if self.ssl:
            conn = socket_wrapper(conn)
            conn = socket.ssl(conn)
        return conn, size

    def cwd(self, dirname):
        '''Change to a directory.'''
        if dirname == '..':
            try:
                return self.voidcmd('CDUP')
            except error_perm, msg:
                if msg.args[0][:3] != '500':
                    raise error_bad_remote_path, msg
        elif dirname == '':
            dirname = '.'  # does nothing, but could return error
        cmd = 'CWD ' + dirname
        try:
            response = self.voidcmd(cmd)
        except Exception, e:
            raise error_bad_remote_path, e
        return response

    def pwd(self):
        '''Return current working directory.'''
        resp = self.sendcmd('PWD')
        return parse257(resp)

    def quit(self):
        '''Quit, and close the connection.'''
        resp = self.voidcmd('QUIT')
        self.close()
        return resp

    def prot_p(self):
        '''Set up secure data connection.'''
        # PROT defines whether or not the data channel is to be protected.
        # Though RFC-2228 defines four possible protection levels,
        # RFC-4217 only recommends two, Clear and Private.
        # Clear (PROT C) means that no security is to be used on the
        # data-channel, Private (PROT P) means that the data-channel
        # should be protected by TLS.
        # PBSZ command MUST still be issued, but must have a parameter of
        # '0' to indicate that no buffering is taking place and the data
        # connection should not be encapsulated.
        self.voidcmd('PBSZ 0')
        resp = self.voidcmd('PROT P')
        self._prot_p = True
        return resp

    def prot_c(self):
        '''Set up clear text data connection.'''
        resp = self.voidcmd('PROT C')
        self._prot_p = False
        return resp

    def close(self):
        '''Close the connection without assuming anything about it.'''
        if self.file:
            self.file.close()
            self.sock.close()
            self.file = self.sock = None


_150_re = None

def parse150(resp):
    '''Parse the '150' response for a RETR request.
    Returns the expected transfer size or None; size is not guaranteed to
    be present in the 150 message.
    '''
    if resp[:3] != '150':
        raise error_reply, resp
    global _150_re
    if _150_re is None:
        import re
        _150_re = re.compile("150 .* \((\d+) bytes\)", re.IGNORECASE)
    m = _150_re.match(resp)
    if not m:
        return None
    s = m.group(1)
    try:
        return int(s)
    except (OverflowError, ValueError):
        return long(s)


_227_re = None

def parse227(resp):
    '''Parse the '227' response for a PASV request.
    Raises error_proto if it does not contain '(h1,h2,h3,h4,p1,p2)'
    Return ('host.addr.as.numbers', port#) tuple.'''

    if resp[:3] != '227':
        raise error_reply, resp
    global _227_re
    if _227_re is None:
        import re
        _227_re = re.compile(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)')
    m = _227_re.search(resp)
    if not m:
        raise error_proto, resp
    numbers = m.groups()
    host = '.'.join(numbers[:4])
    port = (int(numbers[4]) << 8) + int(numbers[5])
    return host, port


def parse229(resp, peer):
    '''Parse the '229' response for a EPSV request.
    Raises error_proto if it does not contain '(|||port|)'
    Return ('host.addr.as.numbers', port#) tuple.'''

    if resp[:3] != '229':
        raise error_reply, resp
    left = resp.find('(')
    if left < 0: raise error_proto, resp
    right = resp.find(')', left + 1)
    if right < 0:
        raise error_proto, resp # should contain '(|||port|)'
    if resp[left + 1] != resp[right - 1]:
        raise error_proto, resp
    parts = resp[left + 1:right].split(resp[left+1])
    if len(parts) != 5:
        raise error_proto, resp
    host = peer[0]
    port = int(parts[3])
    return host, port


def parse257(resp):
    '''Parse the '257' response for a MKD or PWD request.
    This is a response to a MKD or PWD request: a directory name.
    Returns the directoryname in the 257 reply.'''

    if resp[:3] != '257':
        raise error_reply, resp
    if resp[3:5] != ' "':
        return '' # Not compliant to RFC 959, but UNIX ftpd does this
    dirname = ''
    i = 5
    n = len(resp)
    while i < n:
        c = resp[i]
        i = i+1
        if c == '"':
            if i >= n or resp[i] != '"':
                break
            i = i+1
        dirname = dirname + c
    return dirname


def print_line(line):
    '''Default retrlines callback to print a line.'''
    print line


#!/usr/bin/python
############################################################################
# SMB Client library 
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
import pexpect
import sys
import os
sys.path.append("/opt/fcombine/www")
os.environ["DJANGO_SETTINGS_MODULE"]="xsftp.settings"

prompt = r'smb:\s.*\>'
smbclient = "/usr/bin/smbclient"

class SMBClientException(Exception):
	pass

class SMBClient():

	def __init__(self, address, port, share, username="", password="", debug_verbosity=0):
		self.address = address
		self.port = port
		self.share = share
		self.username = username
		self.password = password
		self.connection = None
		self.debug_verbosity = debug_verbosity
		self.connect()

	def test_socket(self, address, port):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(5)
			s.connect((address, port))
			s.close()
		except socket.gaierror, e:
				if e[0] == -2:
						#can't resolve server name
						raise SMBClientException("can not resolve server name")
				else:
						raise SMBClientException("socket gaierror")
		except socket.error, e:
				if e[0] == 111:
						# Connection refused - host did a REJECT
						raise SMBClientException("connection refused")
				elif e[0] == 113:
						# no route to host
						raise SMBClientException("no route to host")
				elif str(e) == "timed out":
						# connection timed out. bad ip address, cable issue, firewall issue 
						raise SMBClientException("connection timed out")
				else:
						raise SMBClientException("socket error")

	def connect(self):
		if self.connection:
			self.debug(1, "testing socket...")
			self.connection.close()
			self.debug(1, "...done")
		# test the socket
		self.test_socket(self.address, self.port)
		# test the SMB session
		username = self.username.replace("'", '"').replace("%",r"\%")
		password = self.password.replace("'", '"').replace("%",r"\%")
		cmd = " ".join([smbclient, "'//%s/%s'" % (self.address, self.share), "-U '%s%%%s'" % (username, password), "-p %s" % self.port])
		self.debug(1, "Spawn command will be: %s" % cmd)
		self.connection = pexpect.spawn(cmd)
		try:
			responses = {	'ok': prompt,
							'server_timeout': 'server did not respond after 20000 milliseconds'
						}
			self.connection.expect (responses.values(), timeout=22)
			if responses['server_timeout'] in self.connection.after:
				# wrong service
				raise SMBClientException('wrong service')
		except pexpect.EOF:
			# client closed without sending a specified response. Read the responce and raise accordingly.
			output = self.connection.before
			if "NT_STATUS_LOGON_FAILURE" in output:
				# the credentials are bad
				self.close()
				raise SMBClientException('bad credentials')
			elif "failed (Call timed out: server did not respond after 20000 milliseconds)" in output or\
				"failed (Call returned zero bytes (EOF))" in output or\
				"failed (SUCCESS - 0)" in output or\
				"Invalid packet length" in output or\
				"Server stopped responding" in output or\
				"Connection reset by peer" in output or\
				"timeout read" in output:
				# the port is bad.
				self.close()
				raise SMBClientException('wrong service')
			elif "NT_STATUS_BAD_NETWORK_NAME" in output:
				# the share name is bad
				self.close()
				raise SMBClientException('bad share name')
			else:
				self.close()
				raise SMBClientException('smbclient error')
		except pexpect.TIMEOUT:
			self.close()
			raise SMBClientException('wrong service')

	def send_command(self, command):
		self.connection.sendline(command)
		self.connection.expect(prompt)
		return self.connection.before

	def is_dir(self, dir):
		output = self.send_command('cd "%s"' % dir)
		if	"NT_STATUS_OBJECT_NAME_NOT_FOUND" in output or\
			"NT_STATUS_OBJECT_NAME_INVALID" in output or\
			": not a directory" in output:
			return False
		else:
			return True

	def is_connected(self):
		if self.connection:
			return self.connection.closed
		else:
			return False

	def close(self, delete=True):
		self.connection.close()
		if delete:
			del(self.connection)

	def set_debug_verbosity(self, val):
		'''
		0 = silent, >0 = noise
		'''
		self.debug_verbosity = val

	def debug(self, val, msg):
		if val >= self.debug_verbosity:
			print msg


def usage():
	print '''"Usage:
%s address port share username password remote_dir
''' % sys.argv[0]
	sys.exit(1)

if __name__ == "__main__":
	try:
		address, port, share, username, password, remote_path = sys.argv[1:]
		port = int(port)
	except:
		usage()
	s = SMBClient(address, int(port), share, username, password)
	print "Remote path '%s' %s." % (remote_path, ["does NOT exist.", "exists."][s.is_dir(remote_path)])



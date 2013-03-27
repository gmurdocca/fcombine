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
from pyrad.dictionary import Dictionary
from xsftp.webui.models import User, Configuration
from xsftp.webui.logger import log

class RadiusBackend:
	"""
	Authenticate against a RADIUS Server.
	"""

	def authenticate(self, username=None, password=None):
		RADIUS_SERVER = Configuration.objects.all()[0].radius_server
		RADIUS_AUTHPORT = Configuration.objects.all()[0].radius_authport
		RADIUS_SECRET = str(Configuration.objects.all()[0].radius_secret)
		# if RADIUS isn't enabled, bail
		if not RADIUS_SERVER:
			return None
		try:
			user = User.objects.get(username=username)
		except User.DoesNotExist:
			return None
		if user.userprofile.internal_auth:
			log("Rejected RADIUS login for '%s': User is not configured for RADIUS authentication" % username)
			return None
		try:
			srv = Client(server=RADIUS_SERVER, authport=RADIUS_AUTHPORT, \
                    secret=RADIUS_SECRET, \
                    dict=Dictionary("/etc/raddb/dictionary"))
			req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest)
			req["User-Name"] = str(username)
			req["User-Password"] = req.PwCrypt(password.encode('ascii'))
			req["NAS-Identifier"] = "fcombine"
			reply=srv.SendPacket(req)
			if reply.code==pyrad.packet.AccessAccept:
				log("Accepted RADIUS login for '%s'" % username)
				return user
			else:
				log("Rejected RADIUS login for '%s': invalid username/password" % username)
				return None
		except Exception, e:
			log("Rejected RADIUS login for '%s' due to RADIUS Configuration Error. %s" % (username, e))
			return None

	def get_user(self, user_id):
		try:
			return User.objects.get(pk=user_id)
		except User.DoesNotExist:
			return None


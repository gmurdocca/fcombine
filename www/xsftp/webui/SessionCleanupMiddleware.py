#!/usr/bin/python
############################################################################
# Session Cleanup Middleware
# ##########################
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

from django.contrib.sessions.models import Session
from django.db import transaction
from datetime import datetime

class SessionCleanupMiddleware:
	def process_view(self, request, view_func, view_args, view_kwargs):
		''' Cleans out any expired sessions from the DB '''
		Session.objects.filter(expire_date__lt=datetime.now()).delete()
		transaction.commit_unless_managed()
		return None

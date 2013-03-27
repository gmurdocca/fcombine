#!/usr/bin/python
############################################################################
# Bread Crumb Middleware 
# ############################################
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
import random

class BreadCrumbMiddleware:
	def process_response(self, request, response):
		'''
		Appends ?bcid=x[&back=1] to all anchors, form actions and js link buttons to set the appropriate bcid identities of next pages.
		'''
		if response.has_header('Content-Disposition') and response['Content-Disposition'].find("attachment") != -1:
			return response
		# capture the weird AttributeError: 'WSGIRequest' object has no attribute 'session' when there isnt a "/" on the end of a URL.
		# the lack of a trailing "/" seemed to blow away the session. The below fixes it, but I dunno what is going on. Phil, anything?
		# if the view does not want a new bcid generated for this page
		try:
			if "breadCrumbs" not in request.session.keys() or not request.session["breadCrumbs"]:
				return response
		except AttributeError:
			return response
		bcid = request.session["breadCrumbs"][-1][2]
		# get previous_bcid to make back=1 work on the POST form method substitution below
		if len(request.session["breadCrumbs"]) > 1:
			prev_bcid = request.session["breadCrumbs"][-2][2]
		else:
			prev_bcid = bcid

		# ANCHOR MODIFICATEION
		a_pattern = re.compile(r'''\<a.*href=(?P<quote>["'])(?P<url>[^(?P=quote)]+)(?P=quote)(?!\sonclick).*\>''')
		# Go through the data in the response object and modify it
		content = response.content
		modifiedContent = ""
		while content:
			match = a_pattern.search(content)
			if match:
				modifiedContent += content[:match.start() + match.group(0).find(match.groupdict()["url"])]
				originalURL = match.groupdict()["url"]
				if originalURL.find("?") == -1:
					originalURL += "?"
				else:
					originalURL += "&"
				# now apend an additional get paramater
				newURL = originalURL + "bcid=%s" % bcid
				modifiedContent += newURL
				modifiedContent += content[match.start() + match.group(0).find(match.groupdict()["url"]) + len(match.groupdict()["url"]):match.end()]
				content = content[match.end():]
			else:
				modifiedContent += content
				content = ""

		# goToURL MODIFICATION (JavaScript Link Buttons)
		js_pattern = re.compile(r'''goToURL\((?P<quote>["'])(?P<url>[^'"].*?)(?P=quote)\)''')
		content = modifiedContent
		modifiedContent = ""
		while content:
			match = js_pattern.search(content)
			if match:
				modifiedContent += content[:match.start() + match.group(0).find(match.groupdict()["url"])]
				originalURL = match.groupdict()["url"]
				if originalURL.find("?") == -1:
					originalURL += "?"
				else:
					originalURL += "&"
				# now apend an additional get paramater
				newURL = originalURL + "bcid=%s" % bcid
				modifiedContent += newURL
				modifiedContent += content[match.start() + match.group(0).find(match.groupdict()["url"]) + len(match.groupdict()["url"]):match.end()]
				content = content[match.end():]
			else:
				modifiedContent += content
				content = ""
		response.content = modifiedContent

		# FORMS action="get" MODIFICATION
		forms_pattern = re.compile(r'''method=(?P<gquote>["'])(get|GET)(?P=gquote).*?action=(?P<aquote>["'])(?P<url>[^'"].*?)(?P=aquote)''')
		content = modifiedContent
		modifiedContent = ""
		while content:
			match = forms_pattern.search(content)
			if match:
				modifiedContent += content[:match.start() + match.group(0).find(match.groupdict()["url"])]
				originalURL = match.groupdict()["url"]
				if originalURL.find("?") == -1:
					originalURL += "?"
				else:
					originalURL += "&"
				# now apend an additional get paramater
				newURL = originalURL + "bcid=%s" % bcid
				modifiedContent += newURL
				modifiedContent += content[match.start() + match.group(0).find(match.groupdict()["url"]) + len(match.groupdict()["url"]):match.end()]
				content = content[match.end():]
			else:
				modifiedContent += content
				content = ""
		response.content = modifiedContent


		# FORMS action="post" MODIFICATION
		forms_pattern = re.compile(r'''method=(?P<gquote>["'])(post|POST)(?P=gquote).*?action=(?P<aquote>["'])(?P<url>[^'"].*?)(?P=aquote)''')
		content = modifiedContent
		modifiedContent = ""
		while content:
			match = forms_pattern.search(content)
			if match:
				modifiedContent += content[:match.start() + match.group(0).find(match.groupdict()["url"])]
				originalURL = match.groupdict()["url"]
				if originalURL.find("?") == -1:
					originalURL += "?"
				else:
					originalURL += "&"
				# now apend an additional get paramater and set back=1 since it is a post
				newURL = originalURL + "bcid=%s&back=1" % prev_bcid
				modifiedContent += newURL
				modifiedContent += content[match.start() + match.group(0).find(match.groupdict()["url"]) + len(match.groupdict()["url"]):match.end()]
				content = content[match.end():]
			else:
				modifiedContent += content
				content = ""
		response.content = modifiedContent

		# finally, return the response
		return response

	def process_view(self, request, view_func, view_args, view_kwargs):
		'''
		Splits the breadcrumb list appropriately based on what was passed in the get request.
		'''
		if "bcid" in request.GET.keys():
			try:
				# Get the current list of bcids recorded in the session
				bcids = [bc[2] for bc in request.session["breadCrumbs"]]
				# Get the index of the bcid that we just received in the list. This could throw KeyError if they didn't pass a bcid at all, or ValueError if the bcid doesn't exist
				matchingIndex = bcids.index(int(request.GET["bcid"]))
				if not "back" in request.GET.keys():
					if not matchingIndex == len(bcids) - 1:
						request.session["breadCrumbs"] = request.session["breadCrumbs"][:matchingIndex + 1]
				elif int(request.GET["back"]) == 1:
					request.session["breadCrumbs"] = request.session["breadCrumbs"][:matchingIndex]
				return None
			except (AttributeError, KeyError, ValueError), e:
				return None	
		else:
			return None


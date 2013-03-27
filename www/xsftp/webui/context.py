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

import time
import xsftp.webui.models
import xsftp.common.constants
from xsftp.common.Licenses import Licenses

def context_processor(request):
    context = dict()
    context["admin_links"] = [
            ("status", "Status", "/status/"),
            ("users", "Users", "/users/"),
            ("groups", "Groups", "/groups/"),
            ("serverlinks", "Server Links", "/serverlinks/"),
            ("scripts", "Scripts", "/scripts/"),
            ("alljobs", "Jobs", "/jobs/all/"),
#            ("reporting", "Reporting", "/reporting/"), #TODO implement in Gen2
            ("configuration", "Configuration","/configuration/"),
            ("systemlog", "System Log","/systemlog/"),
            ("subscriptions", "Subscriptions","/subscriptions/"),
            ]
    context["operator_links"] = [
            ("explorer", "File Explorer", "/explorer/"),
            ("myserverlinks", "My Server Links", "/myserverlinks/"),
            ("myscripts", "My Scripts", "/myscripts/"),
            ("myjobs", "My Jobs", "/jobs/"),
            ("mysshkeys", "My SSH Keys", "/mysshkeys/"),
            ("myprofile", "My Profile", "/myprofile/"),
        ]
    context["current_date"] = time.strftime("%a, %d %B %Y")
    context["current_year"] = time.strftime("%Y")
    context["xsftp_version"] = xsftp.common.constants.VERSION
    context["licenses"] = Licenses()
    context["devicename"] =    xsftp.webui.models.Configuration.objects.all()[0].get_device_name()
    if "breadCrumbs" in request.session.keys() and len(request.session["breadCrumbs"]) > 4:
        breadCrumbs = request.session["breadCrumbs"][-4:]
        breadCrumbs.insert(0, ("...", "", 0))
    elif "breadCrumbs" in request.session.keys():
        breadCrumbs = request.session["breadCrumbs"]
    else:
        breadCrumbs = []
    context["breadCrumbs"] = breadCrumbs
    if len(context["breadCrumbs"]) > 1:
        context["prevBreadCrumb"] =  request.session["breadCrumbs"][-2]
    return context


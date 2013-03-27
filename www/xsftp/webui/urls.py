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

from django.conf.urls.defaults import *

urlpatterns = patterns('xsftp.webui.views',

	# Login/Tool bar/Misc
	(r'^$','root'),
	(r'^login/$', 'login'),
	(r'^dologin/$', 'dologin'),
	(r'^dologout/$','dologout'),
	(r'^accounts/login/$', 'accountsLogin'),
	#(r'^help/$','help'), #TODO Gen2
	#(r'^reporting/$', 'reporting'), #TODO Gen2

	# Configuration
	(r'^configuration/$', 'configuration'),
	(r'^configuration/edit/$', 'editconfiguration'),
	(r'^configuration/getpublickey/(?P<keytype>[\w]+)/$', 'getpublickey'),
	(r'^configuration/testmail/$','testmail'),
    (r'^configuration/testsyslog/$','testsyslog'),
	(r'^configuration/restart/$','restart'),
	(r'^configuration/restartinprogress/$','restartinprogress'),

	# My Profile
	(r'^myprofile/$', 'myprofile'),
	#(r'^myprofile/edit/$', 'editprofile'), #TODO Gen2 - confirm new email address
	(r'^changemypass/$','changemypass'),

	# File Explorer
	(r'^explorer/$','explorer'),
	(r'^explorer/upload/$','explorer_upload'),

	# Status
	(r'^status/$', 'status'),
	(r'^status/start/$', 'servicestart'),
	(r'^status/stop/$', 'servicestop'),

	#System Log
	(r'^systemlog/$','systemlog'),
	(r'^systemlog/download/$','getsystemlog'),
	(r'^systemlog/archive/$','systemlogarchive'),
	(r'^systemlog/archive/(?P<filename>[\w.-]+)/$','getarchivedlog'),

	# Users
	(r'^users/$', 'users'),
	(r'^users/add/$','adduser'),
	(r'^users/view/(?P<userid>\d+)/$', 'viewuser'),
	(r'^users/edit/(?P<userid>\d+)/$', 'edituser'),
	(r'^users/changepassword/(?P<userid>\d+)/$', 'changeuserpass'),
	(r'^users/(?P<action>delete)/$','domodifyusers'),
	(r'^users/(?P<action>enable)/$','domodifyusers'),
	(r'^users/(?P<action>disable)/$','domodifyusers'),

	# Groups
	(r'^groups/$', 'groups'),
	(r'^groups/add/$','addgroup'),
	(r'^groups/view/(?P<groupid>\d+)/$','viewgroup'),
	(r'^groups/edit/(?P<groupid>\d+)/$', 'editgroup'),
	(r'^groups/(?P<action>delete)/$','domodifygroups'),
	
	# Serverlinks
	(r'^serverlinks/$', 'serverlinks'),
	(r'^serverlinks/add/$', 'addserverlink'),
	(r'^serverlinks/view/(?P<serverid>\d+)/$', 'viewserverlink'),
	(r'^serverlinks/edit/(?P<serverid>\d+)/$', 'editserverlink'),
	(r'^serverlinks/(?P<action>delete)/$','domodifyserverlinks'),
	(r'^serverlinks/(?P<action>enable)/$','domodifyserverlinks'),
	(r'^serverlinks/(?P<action>disable)/$','domodifyserverlinks'),
	(r'^serverlinks/(?P<action>erase identity)/$','domodifyserverlinks'),
	(r'^serverlinks/(?P<action>reset link)/$','domodifyserverlinks'),
	(r'^myserverlinks/$', 'myserverlinks'),
	(r'^myserverlinks/view/(?P<serverid>\d+)/$', 'viewmyserverlink'),

	# Jobs
	(r'^jobs/$', 'jobs'),
	(r'^jobs/add/$', 'addjob'),
	(r'^jobs/all/$', 'jobsAll'),
	(r'^jobs/(?P<allJobs>all/)?view/(?P<jobid>\d+)/$', 'viewjob'),
	(r'^jobs/(?P<allJobs>all/)?edit/(?P<jobid>\d+)/$', 'editjob'),
	(r'^jobs/(?P<allJobs>all/)?(?P<action>delete)/$','domodifyjobs'),
	(r'^jobs/(?P<allJobs>all/)?(?P<action>enable)/$','domodifyjobs'),
	(r'^jobs/(?P<allJobs>all/)?(?P<action>disable)/$','domodifyjobs'),
	(r'^jobs/(?P<allJobs>all/)?kill/(?P<jobid>\d+)/$', 'killjob'),
	(r'^jobs/(?P<allJobs>all/)?run/(?P<jobid>\d+)/$', 'runjob'),

	# Scripts
	(r'^scripts/$', 'scripts'),
	(r'^scripts/add/$','addscript'),
	(r'^scripts/view/(?P<scriptid>\d+)/$','viewscript'),
	(r'^scripts/edit/(?P<scriptid>\d+)/$', 'editscript'),
	(r'^scripts/(?P<action>delete)/$','domodifyscripts'),
	(r'^myscripts/$', 'myscripts'),
	(r'^scripts/get/(?P<scriptid>\d+)/$','getscript'),

	# My SSH keys
	(r'^mysshkeys/$','mysshkeys'),
	(r'^mysshkeys/(?P<action>delete)/$','domodifymysshkeys'),
	(r'^mysshkeys/import/$','importsshkeys'),
	(r'^mysshkeys/edit/(?P<key_id>\d+)/$','editsshkey'),

	# Subscriptions
	(r'^subscriptions/$','subscriptions'),
)


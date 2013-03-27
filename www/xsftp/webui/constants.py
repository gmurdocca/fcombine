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

import xsftp.common.constants

FCOMBINE_VERSION = "3.0.417"
KEY_FILE_LOCATION = "/etc/xsftp/keys/xsftp_key"
# At some stage, we may want to set a "base dir", and then record other paths as being relative to that dir
# set script path, ensure all paths have a training slash
TRANSIENT_KEY_PATH = xsftp.common.constants.APPDIR + "var/trans_keys/"
SCRIPT_PATH = xsftp.common.constants.APPDIR + "var/scripts/"
SYSLOG_CONF = "/etc/rsyslog.conf"
RESOLV_CONF = "/etc/resolv.conf"
IP_CONFIG = "/etc/sysconfig/network-scripts/ifcfg-eth0"
SYSLOG_LOG_FILE = "/var/log/fcombine.log"
SYSLOG_FACILITY = "local1" #Note: must also be configued above in syslog.openlog()
PAGE_TITLE = "Fcombine:"
PAM_RADIUS_CONFIG = "/etc/raddb/server"
PAM_RADIUS_USERS = "/opt/fcombine/var/radius_users"
SUBSCRIPTIONS_LINK = "https://fcombine.com/subscriptions"
DB_FILE = xsftp.common.constants.APPDIR + "www/xsftp/fcombine.sqlite3"
DB_EXPECTED_VERSION = 3

# server link button descriptions
BUTTON_DESCRIPTIONS = { "Disable":"disable",
                        "Enable":"enable",
                        "Delete":"delete",
                        "Erase Identity":"erase the stored identity of",
                        "Reset Link":"reset the connection to",}



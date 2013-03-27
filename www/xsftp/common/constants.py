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

import os.path

DEV_MODE = True

if DEV_MODE:
    HOMEDIR = "/tmp/home"
else:
    HOMEDIR = "/home"

VERSION = "0.1"
APPDIR = "/opt/fcombine/"
KNOWN_HOSTS_FILE = APPDIR + "etc/xsftp/known_hosts"
LICENSE_FILE = "/etc/xsftp/fcombine_subscriptions.key"
DEFAULT_CONF_FILE = "/etc/xsftp/xsftpd.conf"
SERVER_DIR = os.path.join(APPDIR, "var", "servers")
SERVER_RAMDISK_SIZE_MB = 256
HOMEDIR_SOURCE = os.path.join(APPDIR, "var", "home")
HOME_RAMDISK_SIZE_MB = 256
LOG_STDOUT_STDERR = True
COMMENT_LENGTH = 512
RADIUS_DICTIONARY="/opt/fcombine/etc/raddb/dictionary"

# FILENAME_PATTERN: max length 100 characters, no white space, min 1 character,
#                   can not start with a period
FILENAME_PATTERN = r"^[^\\\./:\*\?\"<>\|;'\s]{1}[^\\/:\*\?\"<>\|;'\s]{0,99}$"
# PATH_PATTERN: max length 512, valid chars are alphanumeric and . _ - / <space>
#               and must start and end with non white-space
PATH_PATTERN = (r"(^[/]$)|(^[a-zA-Z0-9_/\-\.]([\sa-zA-Z0-9_/\-\.])"
        r"{0,512}[a-zA-Z0-9_/\-\.])$")
# CRON_PATTERN: 5 chunks of anything separated by whitespace
CRON_PATTERN = r"^([\d\*/,-]+\s){4}[\d\*/,-]+\s*$"
# USERNAME_PATTERN: alphanumeric, underscore ok, 64 characters max
USERNAME_PATTERN = r"^[a-zA-Z0-9_]{1,63}$"
# GROUPNAME_PATTERN: like username but whitespace allowed except for first
#                    character
GROUPNAME_PATTERN = r"^[a-zA-Z0-9_][a-zA-Z0-9_\s]{0,63}$"
IP_ADDRESS_PATTERN = (r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
FQDN_PATTERN = (r"(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}"
        r"(?<!-)\.?)+(?:[a-zA-Z]{2,})$)")
DEVICENAME_PATTERN = r"^[a-zA-Z0-9_\.]{1,127}$"
EMAIL_ADDRESS_PATTERN = (r"^[a-zA-Z][\w\.-]*[a-zA-Z0-9]@[a-zA-Z0-9][\w\.-]*"
        r"[a-zA-Z0-9]\.[a-zA-Z][a-zA-Z\.]*[a-zA-Z]$")
CIFS_SHARE_PATTERN = r'^[a-zA-Z0-9_\-\.\s\$]*$'
SERVERLINKNAME_PATTERN = USERNAME_PATTERN
SCRIPTNAME_PATTERN = GROUPNAME_PATTERN
VALID_JOBNAME_PATTERN = GROUPNAME_PATTERN

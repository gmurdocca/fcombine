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

# TODO: remove me when ready
# TEMPORARY STUB for existing pages to import the individual model classes

import os, glob, pwd, grp
from django.db import models
from django.contrib.auth.models import User
from xsftp.common.Logger import log
import xsftp.webui.constants
import xsftp.common.constants
import datetime
from django.core.files.storage import FileSystemStorage
from xsftp.common.Licenses import Licenses

COMMENT_LENGTH = 512
# redirect string for os.system() calls
REDIRECTSTR = "> /dev/null 2>&1"


from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity

from xsftp.common.models.Job import Job
from xsftp.common.models.Glob import Glob
from xsftp.common.models.Script import Script
from xsftp.common.models.Server import Server
from xsftp.common.models.xGroup import xGroup
from xsftp.common.models.SSHFSServer import SSHFSServer
from xsftp.common.models.UserProfile import UserProfile
from xsftp.common.models.Configuration import Configuration



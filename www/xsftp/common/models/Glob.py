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

from django.db import models

from Job import Job
from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity

class Glob(models.Model):
    '''
    This object represents a single source file glob for Jobs.
    A Job object may reference many of these objects.
    '''

    class Meta:
        app_label = "webui"

    glob = models.CharField(max_length=255)
    job = models.ForeignKey(Job)

    def __unicode__(self):
        return self.glob

    def __str__(self):
        return self.__unicode__()

    class Admin:
        pass



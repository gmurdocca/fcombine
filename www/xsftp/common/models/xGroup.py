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

from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity

from django.contrib.auth.models import User
from xsftp.common.constants import COMMENT_LENGTH


class xGroup(models.Model):
    '''
    The xGroup object class
    '''

    class Meta:
        app_label = "webui"

    group_name = models.CharField(max_length=30)
    comment = models.CharField(max_length=COMMENT_LENGTH, blank=True)
    created = models.DateTimeField()
    users = models.ManyToManyField(User)
    alertable = models.BooleanField(default=False)

    def save(self):
        super(xGroup, self).save()
        # if alertable is false, remove group from any jobs that use group as an
        # alert target.
        modded_jobs = []
        if not self.alertable:
            for job in self.jobAlertSuccess.all():
                job.alert_groups_on_success.remove(self)
                modded_jobs.append(job.job_name)
            for job in self.jobAlertFail.all():
                job.alert_groups_on_fail.remove(self)
                if job.job_name not in modded_jobs:
                    modded_jobs.append(job.job_name)
        if modded_jobs:
            log("removed Group '%s' as an alert target from the " \
                "following %s job(s): %s" % (self.group_name, \
                len(modded_jobs), "'" + "', '".join(modded_jobs) + "'"))
        dbCommit()
        checkJobSanity()

    def delete(self):
        super(xGroup, self).delete()
        #log("deleted group: %s" % self.group_name)
        dbCommit()
        checkJobSanity()

    def __unicode__(self):
        return self.group_name

    def __str__(self):
        return self.__unicode__()

    class Admin:
        pass


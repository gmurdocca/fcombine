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

from xGroup import xGroup

import xsftp.common.constants
from xsftp.common.Licenses import Licenses
from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity


class Configuration(models.Model):
    '''
    Captures all system configuration settings, and is applied to the system by
    models.dbCommit() which is called by this class's .save() method.
    '''

    class Meta:
        app_label = "webui"


    # Device ID and network config
    device_name = models.CharField(max_length=30)
    ip_address = models.IPAddressField()
    subnet_mask = models.IPAddressField()
    default_gateway = models.IPAddressField(null=True, blank=True)
    primary_dns = models.IPAddressField(null=True, blank=True)
    secondary_dns = models.IPAddressField(null=True, blank=True)

    # SMTP config
    smtp_server = models.CharField(max_length=256, null=True, blank=True)
    smtp_port = models.IntegerField(default=25) #default is 25
    smtp_from_address = models.EmailField(null=True, blank=True)

    # Remote syslog config
    remote_syslog_server = models.CharField(max_length=256,
                                            null=True,
                                            blank=True)

    # Global config for email alerts

    # serverlink_alert_groups defines which groups of users will receive
    # email alerts related to serverlink health
    serverlink_alert_groups = models.ManyToManyField(
            xGroup,
            related_name="serverlink_alert_groups",
            null=True,
            blank=True)
    # groups that receive an email notification when any job completes
    # successfully.
    job_success_alert_groups = models.ManyToManyField(
            xGroup,
            related_name="job_success_alert_groups",
            null=True,
            blank=True)
    # groups that receive an email notification when any job fails.
    job_failure_alert_groups = models.ManyToManyField(
            xGroup,
            related_name="job_failure_alert_groups",
            null=True,
            blank=True)

    demo_mode = models.BooleanField(default=False)

    def get_device_name(self):
        licenses = Licenses(xsftp.common.constants.LICENSE_FILE)
        if licenses.is_subscribed():
            return licenses.devicename
        else:
            return self.device_name

    def save(self):
        #log("modified system-wide configuration")
        super(Configuration, self).save()
        dbCommit()

    def __unicode__(self):
        return self.get_device_name()

    def __str__(self):
        return self.__unicode__()

    class Admin:
        pass


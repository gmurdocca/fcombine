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
from django.contrib.auth.models import User

from Server import Server
from Script import Script
from xGroup import xGroup
from xsftp.common.constants import COMMENT_LENGTH
from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity


class Job(models.Model):
    '''
    Job object class
    '''

    class Meta:
        app_label = "webui"


    # GENERAL DETAILS
    job_name = models.CharField(max_length=60)
    owner = models.ForeignKey(User, blank=True, null=True)
    comment = models.CharField(max_length=COMMENT_LENGTH, blank=True)
    enabled = models.BooleanField(default=True)
    last_run_time = models.DateTimeField(blank=True, null=True)
    last_run_status = models.NullBooleanField(blank=True)
    last_run_duration = models.IntegerField(blank=True, null=True)
    running_now = models.NullBooleanField(blank=True, default=False) # True is running, False is not running, None is Terminating
    start_time = models.DateTimeField(blank=True, null=True)
    errorFlags = models.IntegerField() # bitmask describing the sanity of a job.
    timeLastSeenSane =  models.DateTimeField(blank=True, null=True, default=None) # seonds since job was last sane
    pid = models.IntegerField(blank=True, null=True) # pid of currently running jobrunner (which should exist if set but may not), or None of not running.
    message = models.CharField(max_length=1024)
    # SCHEDULE DETAILS
    schedule_type = models.IntegerField() # run_once, hourly, daily, weekly, monthly, yearly, or advanced (freeform cron style field) for presentation only
    run_at = models.DateTimeField(null=True, blank=True)
    minute = models.CharField(max_length=255)
    hour = models.CharField(max_length=255)
    day = models.CharField(max_length=255)
    month = models.CharField(max_length=255)
    dow = models.CharField(max_length=255)
    expiry = models.DateTimeField(null=True, blank=True)
    run_count = models.IntegerField(blank=True, null=True)
    # TASK DETAILS
    source_server = models.ForeignKey(Server, related_name="jobs_source", blank=True, null=True)
    dest_server = models.ForeignKey(Server, related_name="jobs_dest", blank=True, null=True)
    dest_path = models.CharField(max_length=256)
    delete_source = models.BooleanField(default=False)
    continue_on_error = models.BooleanField(default=False)
    exist_action = models.IntegerField(default=0) # 0:do nothing(fail), 1:do nothing(success), 2:overwrite(success), 3:increment name(success)
    use_pre_script = models.BooleanField(default=False)
    pre_script = models.ForeignKey(Script, related_name="jobs_pre", blank=True, null=True)
    use_post_script = models.BooleanField(default=False)
    post_script = models.ForeignKey(Script, related_name="jobs_post", blank=True, null=True)
    # ALERTING DETAILS
    alert_owner_on_success = models.BooleanField(default=False)
    alert_owner_on_fail = models.BooleanField(default=True)
    suppress_group_alerts = models.BooleanField(default=True)
    alert_groups_on_success = models.ManyToManyField(xGroup, related_name="jobAlertSuccess", blank=True, null=True)
    alert_groups_on_fail = models.ManyToManyField(xGroup, related_name="jobAlertFail", blank=True, null=True)

    def save(self, checkSanity=True):
        # convert unicode-specified datetime objects to python datetime ones, so that they get stored correctly in the database -
        # otherwise, if unicode is specified and seconds are ommited like "2008-05-05 12:45", then it is stored in the sqlite db
        # as such, and causes an index error since django expects there to be seconds when parsing it for conversion back into a
        # datetime object when queried.
        if type(self.expiry) == type(u''):
            self.expiry = datetime.datetime(*map(int, self.expiry.replace("-", " ").replace(":", " ").split()))
        if type(self.run_at) == type(u''):
            self.run_at = datetime.datetime(*map(int, self.run_at.replace("-", " ").replace(":", " ").split()))
        # purge microsecond value from datetime fields that get directly printed to the web gui
        if type(self.last_run_time) == type(datetime.datetime.now()):
            self.last_run_time = self.last_run_time.replace(microsecond=0)
        if type(self.timeLastSeenSane) == type(datetime.datetime.now()):
            self.timeLastSeenSane = self.timeLastSeenSane.replace(microsecond=0)
        super(Job, self).save()
        dbCommit()
        if checkSanity:
            checkJobSanity()

    def delete(self):
        super(Job, self).delete()
        #log("deleted job '%s'" % self.job_name)
        dbCommit()
        checkJobSanity()

    def scheduleTypeString(self):
        '''
        Returns a meaningful string reflecting the schedule type of a job
        '''
        return ["Run Once", "Hourly", "Daily", "Weekly", "Monthly", "Yearly", "Advanced"][self.schedule_type]

    def scheduleString(self):
        '''
        Returns an HTML formatted string reflecting the schedule details for presentation
        '''
        if self.schedule_type == 0:
            # run once
            scheduleString = "Run on %(weekday)s, %(dom)s %(month)s %(year)s at %(time)s" % {'weekday':self.run_at.strftime("%A"), 'dom':self.run_at.strftime("%d") ,'month':self.run_at.strftime("%B"), 'year':self.run_at.strftime("%Y"), 'time':self.run_at.strftime("%X")}
        elif self.schedule_type == 1:
            # run hourly
            minunteString = dict(xsftp.webui.forms.minuteChoices)[self.minute]
            scheduleString = "Run on the %s of every hour" % minunteString
        elif self.schedule_type == 2:
            # run daily
            if self.minute == '0': minuteString = "00"
            elif self.minute == '1': minuteString = "15"
            elif self.minute == '2': minuteString = "30"
            elif self.minute == '3': minuteString = "45"
            if len(self.hour) == 1: hourString = "0" + self.hour
            else: hourString = self.hour
            scheduleString = "Run at %(hour)s:%(min)s, every day" % {'min':minuteString, 'hour':hourString}
        elif self.schedule_type == 3:
            # run weekly
            if self.minute == '0': minuteString = "00"
            elif self.minute == '1': minuteString = "15"
            elif self.minute == '2': minuteString = "30"
            elif self.minute == '3': minuteString = "45"
            if len(self.hour) == 1: hourString = "0" + self.hour
            else: hourString = self.hour
            scheduleString = "Run at %(hour)s:%(min)s, every day" % {'min':minuteString, 'hour':hourString}
            weekdayString = dict(xsftp.webui.forms.dowChoices)[self.dow]
            scheduleString = "Run every %(weekday)s at %(hour)s:%(min)s" % {'weekday':weekdayString, 'min':minuteString, 'hour':hourString}
        elif self.schedule_type == 4:
            # run monthly
            if self.minute == '0': minuteString = "00"
            elif self.minute == '1': minuteString = "15"
            elif self.minute == '2': minuteString = "30"
            elif self.minute == '3': minuteString = "45"
            if len(self.hour) == 1: hourString = "0" + self.hour
            else: hourString = self.hour
            if self.day in ['1','21','31']: domString = self.day + "st"
            elif self.day in ['2','22']: domString = self.day + "nd"
            elif self.day in ['3','23']: domString = self.day + "rd"
            else: domString = self.day + "th"
            scheduleString = "Run on the %(dom)s of each month, at %(hour)s:%(min)s" % {'min':minuteString, 'hour':hourString, 'dom':domString}
        elif self.schedule_type == 5:
            # run yearly
            if self.minute == '0': minuteString = "00"
            elif self.minute == '1': minuteString = "15"
            elif self.minute == '2': minuteString = "30"
            elif self.minute == '3': minuteString = "45"
            if len(self.hour) == 1: hourString = "0" + self.hour
            else: hourString = self.hour
            if self.day in ['1','21','31']: domString = self.day + "st"
            elif self.day in ['2','22']: domString = self.day + "nd"
            elif self.day in ['3','23']: domString = self.day + "rd"
            else: domString = self.day + "th"
            monthString = dict(xsftp.webui.forms.monthChoices)[self.month]
            scheduleString = "Run once per year on the %(dom)s of %(month)s, at %(hour)s:%(min)s" % {'min':minuteString, 'hour':hourString, 'dom':domString, 'month':monthString}
        elif self.schedule_type == 6:
            scheduleString = "Run according to the cron formatted schedule: <b>%s</b>" % " ".join([self.minute, self.hour, self.day, self.month, self.dow])
        return scheduleString

    def existActionString(self):
        '''
        Returns a meaningful string reflecting the action to be taken if a destination file exists
        '''
        return ["Do nothing, mark job as FAIL", "Do nothing, mark job as SUCCESS", "Overwrite destination if possible", "Append incremental index number to new files"][self.exist_action]

    def sanityStrings(self):
        '''
        Returns a list of meningful strings describing the sanity (or lack thereof) of a job
        '''
        sanity = self.errorFlags
        pwr = 12 # 2**12 == 4096 == highest butmask value of insanity (adjust as more insanities are added)
        # populate masklist with bitmask values
        masklist = []
        while sanity:
            while sanity == sanity % (2**pwr):
                pwr -= 1
            masklist.append(2**pwr)
            sanity = sanity % (2**pwr)
        sanityStrings = []
        if masklist:
            for value in masklist:
                if value == 1: sanityStrings.append("Source Server Link does not exist")
                if value == 2: sanityStrings.append("Owner is not allowed to read from the Source Server Link")
                if value == 4: sanityStrings.append("Destinstion Server Link does not exist")
                if value == 8: sanityStrings.append("Owner is not allowed to write to the destination Server Link")
                if value == 16: sanityStrings.append("Pre-script does not exist")
                if value == 32: sanityStrings.append("Owner is not allowed to execute pre-script")
                if value == 64: sanityStrings.append("Post-script does not exist")
                if value == 128: sanityStrings.append("Owner is not allowed to execute post-script")
                if value == 256: sanityStrings.append("Source Server Link is disabled")
                if value == 512: sanityStrings.append("Destination Server Link is disabled")
                if value == 1024: sanityStrings.append("Owner is disabled")
                if value == 2048: sanityStrings.append("Owner does not exist")
                if value == 4096: sanityStrings.append("Job has expired")
        else:
            sanityStrings.append("Job is sane")
        return sanityStrings

    def __unicode__(self):
        return self.job_name

    def __str__(self):
        return self.__unicode__()

    class Admin:
        pass



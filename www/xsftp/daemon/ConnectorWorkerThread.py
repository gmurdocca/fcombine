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

# **************************************************************************************************
# Server health+status timer and remediation-thread-spawner (aka The Stopwatch+Clipboard Guy) thread
# **************************************************************************************************

import os
import time
import htmllib
import formatter
from threading import Thread

import xsftp.webui.models
from xsftp.common import email
from xsftp.daemon.Logger import log
from xsftp.common.Config import config
from RemediatorWorkerThread import RemediatorWorkerThread

class EmailTextParser(htmllib.HTMLParser):
    '''
    Simple object used to translate html to text (for email alerts)
    '''
    data = ""
    def handle_data(self, data):
        self.data += data

class Error(Exception):
    pass

class Email_Error(Error):
    pass

class ConnectorWorkerThread(Thread):
    '''
    ConnectorWorker Thread.
    Times ithe duration of unhealthy server links and spawns remediator threads and the alerting subsystem at appropriate times.
    '''

    # time in seconds the ConnectorWorkerThread 
    # (timer/repair+alert-spawner thread) sleeps for between
    # iterations
    CWT_SLEEP = 10
    
    def __init__(self, shared_vars, slam_manager, bmp_manager):
        Thread.__init__(self)
        self.shared_vars = shared_vars
        self.slam_manager = slam_manager
        self.bmp_manager = bmp_manager

        # Need to set this to true so that it will be killed
        # when other threads finish
        self.setDaemon(True)


    def run(self):

        while True:
            # get current self.shared_vars.serverStatusDict
            self.shared_vars.serverStatusDictLock.acquire()
            currentServerStatusDict = self.shared_vars.serverStatusDict.copy()
            # get current bmp's
            self.shared_vars.serverStatusDictLock.release()
            bmpList = currentServerStatusDict.keys()
            # for each bmp
            for bmp in bmpList:
                # log its state if not healthy
                if currentServerStatusDict[bmp][1]:
                    log(5, "connectorWorkerThread %s reports: - BMP %s has been in STATE %s for %s seconds." % (self.getName(), bmp, currentServerStatusDict[bmp][1], (int(time.time()) - currentServerStatusDict[bmp][2])))
                    log(3, "Server Link '%s' has been in unhealthy state %s for %s seconds" %( os.path.basename(bmp), currentServerStatusDict[bmp][1], (int(time.time()) - currentServerStatusDict[bmp][2])))
                # if server is unhealthy for over config.REPAIR_DELAY seconds,
                if currentServerStatusDict[bmp][1] != 0 and (int(time.time()) - currentServerStatusDict[bmp][3]) > config.REPAIR_DELAY:
                    # first, log how long this bmp has been unhealthy for, and low long it has been since it was last healthy.
                    log(3, "BMP Requires repair: BMP %s has been in current unhealthy state %s for over %s seconds, and has been unhealthy for %s seconds." % (bmp, currentServerStatusDict[bmp][1], (int(time.time()) - currentServerStatusDict[bmp][2]), (int(time.time()) - currentServerStatusDict[bmp][3])) )
                    # Check if this bindMountPoint is having its status determined
                    self.shared_vars.statChecksInProgressLock.acquire()
                    if bmp in self.shared_vars.statChecksInProgress:
                        self.shared_vars.statChecksInProgressLock.release()
                        log(3, "Not spawning a repair for BMP %s - Reason: BMP is currently having its status checked" % bmp)
                        continue
                    self.shared_vars.statChecksInProgressLock.release()
                    # Check if this allegedly damaged BMP is being or has been worked on:
                    self.shared_vars.serverRepairInProgressLock.acquire()
                    if self.shared_vars.serverRepairInProgress.count((bmp, False)):
                        # this BMP is currently being repaired, so do not spawn another rmediator thread for it.
                        log(3, "Not spawning a repair for BMP %s - Reason: Repair job already underway..." % bmp)
                    elif self.shared_vars.serverRepairInProgress.count((bmp, True)):
                        # an attempt at repairing this BMP has been completed, waiting for the statusWorkerThread to check its status
                        log(3, "Not spawning a repair for BMP %s - Reason: Repaired but check still pending..." % bmp)
                    else:
                        # add this bmp to the remediation job queue and spawn a remediator thread for it
                        # The job queue contains a tuple, the 1st value is the bmp to be repaired, and the second is a bool which is False if not yet repaired.
                        # Once repaired, the remediator thread will change this value to true, then a statWorkerThread will remove jobs from job queue which have 2nd value == True.
                        self.shared_vars.serverRepairInProgress.append((bmp, False))
                        remediatorThread = RemediatorWorkerThread(self.shared_vars, self.slam_manager, self.bmp_manager, bmp)
                        remediatorThread.start()
                        log(3, "BMP %s added to repair queue." % bmp)
                        log(3, "Attempting repair of Server Link: %s" % os.path.basename(bmp))
                    self.shared_vars.serverRepairInProgressLock.release()
                # if server has been unhealthy for config.ALERT_DELAY mins, then pass to alert subsystem
                if currentServerStatusDict[bmp][1] != 0 and (int(time.time()) - currentServerStatusDict[bmp][3]) > config.ALERT_DELAY:
                    # alert the specified people of a problem
                    log(3, "BMP %s has been unhealthy for over %s mins. Activating alert subsystem" % ( bmp, ((int(time.time()) - currentServerStatusDict[bmp][3]))/60 ) )
                    log(2, "Server link %s has been unhealthy for over %s mins. Activating alert subsystem" % ( os.path.basename(bmp), ((int(time.time()) - currentServerStatusDict[bmp][3]))/60 ) )
                    # fire up the alerting subsystem
                    self.raiseEmailAlert(bmp)
            time.sleep(self.CWT_SLEEP)


    def raiseEmailAlert(self, bmp):
        '''
        raises alerts to members of the the global serverlink_alert_groups when a bmpabspath is unhealthy, and emails them at the appropriate intervals.
        '''
        # get sid of specified bmpAbsPath
        try:
            self.shared_vars.serverStatusDictLock.acquire()
            sid = self.shared_vars.serverStatusDict[bmp][0]
            new_state = self.shared_vars.serverStatusDict[bmp][1]
            time_first_seen_in_new_state = self.shared_vars.serverStatusDict[bmp][2]
        except:
            # there was an error querying the server status dict for this bmpAbsPath - bailing out.
            self.shared_vars.serverStatusDictLock.release()
            return
        # if sid exists in the AlertTracker global dict, get its values
        self.shared_vars.serverStatusDictLock.release()
        value = None
        self.shared_vars.alertTrackerLock.acquire()
        if sid in self.shared_vars.alertTracker:
            value = self.shared_vars.alertTracker[sid]
        self.shared_vars.alertTrackerLock.release()
        if value:
            count = value[0]
            old_state = value[1]
            last_alert_time = value[2]
        else:
            count = 0
            old_state = None
            last_alert_time = None
        # if state has changed since last alert
        if old_state != new_state:
            # set count = 1, last alert time to now, and send alert
            count = 1
            last_alert_time = time.time()
            self.sendEmailAlert(sid, new_state, time_first_seen_in_new_state)
        else:
            if count == 1 and (time.time() - last_alert_time) > 1800: # 30 mins
                count = 2
                last_alert_time = time.time()
                self.sendEmailAlert(sid, new_state, time_first_seen_in_new_state)
            elif count == 2 and (time.time() - last_alert_time) > 3600: # 1 hour
                count = 3
                last_alert_time = time.time()
                self.sendEmailAlert(sid, new_state, time_first_seen_in_new_state)
            elif count == 3 and (time.time() - last_alert_time) > (3600 * 4): # 4 hours
                count = 4
                last_alert_time = time.time()
                self.sendEmailAlert(sid, new_state, time_first_seen_in_new_state)
            elif count > 3:
                if (time.time() - last_alert_time) > ((3600 * 24) * (count - 3)): # count - 3 days
                    count += 1
                    last_alert_time = time.time()
                    self.sendEmailAlert(sid, new_state, time_first_seen_in_new_state)
        #save new values
        self.shared_vars.alertTrackerLock.acquire()
        self.shared_vars.alertTracker[sid] = (count, new_state, last_alert_time)
        self.shared_vars.alertTrackerLock.release()


    #MK: Delete send_email from constants when it ends up in our branch
    #MK: Merge the two email functions
    def sendEmailAlert(self, sid, state, time_first_seen_in_new_state):
        '''
        Sends an email to everyone in  the global serverlink_alert_groups about the specified server-link's health problem.
        sid = sid of server which is unhealthy (int)
        state = int
        time = time first seen in this state (secs since epoc)
        '''
        recipients = []
        recipient_groups = xsftp.webui.models.Configuration.objects.all()[0].serverlink_alert_groups.all()
        for group in recipient_groups:
            for user in group.users.all():
                if user not in recipients:
                    recipients.append(user)
        email_addresses = [user.email for user in recipients if user.email]
        server_link = xsftp.webui.models.Server.objects.get(id=sid)
        server_link_name = server_link.server_name
        device_name = xsftp.webui.models.Configuration.objects.all()[0].device_name
        if not email_addresses:
            log(1, "Could not send Server Link Health warning email for Server '%s': No 'Server Link Health Global Alert Groups' have been specified." % server_link_name)
        # instantiate a new Server object, set its state, then extract its html details for that state.
        if server_link.status != state:
            server_link.status = state
        # generate text details, by converting the html healthstrings to text for email rendering.
        myWriter = formatter.DumbWriter()
        myFormatter = formatter.AbstractFormatter(myWriter)
        p = EmailTextParser(myFormatter)
        p.feed(server_link.healthStrings())
        # remove tab characters
        details = p.data.replace('\t','')
        # remove blank lines
        details = "\n".join([line for line in details.split("\n") if line != ''])
        p.close()
        #details = server_link.healthStrings()
        # generate time string
        total_seconds = int(time.time() - time_first_seen_in_new_state)
        days = total_seconds / 86400
        hours = total_seconds % 86400 / 3600
        minutes = total_seconds % 86400 % 3600 / 60
        seconds = total_seconds % 86400 % 3600 % 60
        time_string = "%s days, %s hours, %s minutes, %s seconds" % (days, hours, minutes, seconds)
        message = '''
    This is an automatic message from the Fcombine Device: %(device_name)s

    The Server Link '%(server_link_name)s' has been in unhealthy state %(state)s for %(time_string)s.

    arning - Jobs and Users may not be able to utilise this Server Link until it is repaired. See details below for help on remediating this issue.

    Details are:

    %(details)s
    ''' % {"device_name":device_name, "server_link_name":server_link_name, "state":state, "time_string":time_string, "details":details}
        try:
            email.send_email(subject="Fcombine Server Link Health warning for Server '%s'" % server_link_name, body=message, to=email_addresses)
        except Email_Error, e:
            log(1, "Could not send Server Link Health warning email for Server '%s': %s" % (server_link_name, e))



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

import os
import glob
import shutil

import xsftp.webui.models
import xsftp.common.constants
from xsftp.daemon.Logger import log
from xsftp.common.Config import config

class BmpManager:
    def __init__(self, shared_vars):
        self.shared_vars = shared_vars


    def initAllBindMounts(self): 
        '''
        # This function will bind mount all BMP's which are not already bind mounted.
        # We assume all required BMP's exist
        '''
        # get live bmp's
        liveBindMountPointDict = self.getLiveBindMountPoints()
        # extract users from live bmp's
        users = liveBindMountPointDict.keys()
        #for each user
        for user in users:
            # get user's bmp's
            bindMountPoints = liveBindMountPointDict[user]
            # for each of the user's bmp's
            for bindMountPoint in bindMountPoints:
                # assemble the bmpAbsPath
                bmpAbsPath = "/home/%s/xsftp/%s" % (user, bindMountPoint)
                # log bind mount attempt
                log(4, "Bindmounting %s" % (bmpAbsPath))
                # do the bind mount.
                self.doBindMount(bmpAbsPath)
        return

    def rmBindMount(self, sid): 
        '''
        unBindMounts and deletes all bind mount points for all Fcombine users for a given SID
        '''
        log(3, "performing rmbindMount(sid) against all BMP's for sid '%s'" % sid)
        # get server.name of server.sid
        try:
            serverName = xsftp.webui.models.Server.objects.get(id=sid).server_name
        except xsftp.webui.models.Server.DoesNotExist:
            log(3, "Found an unrecognised SID (%s) in the SLAMMount directory, so can't unBindMount it - skipping." % sid)
            return
        # get live bmp's
        liveBindMountPointsDict = self.getLiveBindMountPoints()
        # get user list
        users = liveBindMountPointsDict.keys()
        # for each user
        for user in users:
            # if user has a bmp reflecting specified sid
            if serverName in liveBindMountPointsDict[user]:
                # lazy unBindMount the bmp
                unBindMountCmd = "umount -l /home/" + user + "/xsftp/" + serverName + " > /dev/null 2>&1"
                rc = 0
                while not rc: rc = os.system(unBindMountCmd)
                # delete the bmp
                try:
                    os.remove("/home/%s/xsftp/%s/where_are_my_files.txt" % (user, serverName))
                except OSError:
                    # file "where_are_my_files.txt" erroniously did not exist, but safe to ignore and continue.
                    pass
                rmBindMountPoindCmd = "rmdir /home/" + user + "/xsftp/" + serverName + " > /dev/null 2>&1"
                os.system(rmBindMountPoindCmd)
        return


    def initBindMountPoints(self): 
        '''
        Creates and removes (cleans up) the Bind mount point dirs in each user's home dirs based on data from DB.
        If BMP is cleaned up, it's entry is also removed from the self.shared_vars.serverStatusDict dictionary.
        '''
        # get dict of expected bmp's
        allExpectedBindMountPoints = self.getExpectedBindMountPoints()
        # get dict of live bmp's
        allLiveBindMountPoints = self.getLiveBindMountPoints()
        # Find differences in live to expected bind mount points per user:
        users = allExpectedBindMountPoints.keys()
        # for each user
        for user in users:
            # get user's expected bmp list
            expectedBindMountPointList = allExpectedBindMountPoints[user]
            # get user's live bmp list
            liveBindMountPointList = allLiveBindMountPoints[user]
            # for each expected bmp
            for bindMountPoint in expectedBindMountPointList:
                # if bmp is not live
                if bindMountPoint not in liveBindMountPointList:
                    # create it.
                    bmpAbsPath = "/home/%s/xsftp/%s" % (user, bindMountPoint)
                    #mkBMPCmd = "umask 022; mkdir %s; chown %s:%s %s > /dev/null 2>&1" % (bmpAbsPath, user, user, bmpAbsPath)
                    mkBMPCmd = "umask 022; mkdir %s > /dev/null 2>&1" % (bmpAbsPath)
                    os.system(mkBMPCmd)
                    # Copy in a "where are my files" message text file
                    shutil.copy("%setc/xsftp/where_are_my_files.txt" % xsftp.common.constants.APPDIR, bmpAbsPath)
            # for each live bmp
            for bindMountPoint in liveBindMountPointList:
                # if bmp is not expected
                if bindMountPoint not in expectedBindMountPointList:
                    bmpAbsPath = "/home/%s/xsftp/%s" % (user, bindMountPoint)
                    # lazy unmount it
                    unmountBindMountPointCmd = "umount -l %s > /dev/null 2>&1" % bmpAbsPath
                    os.system(unmountBindMountPointCmd)
                    # delete it
                    try:
                        os.remove("%s/where_are_my_files.txt" % bmpAbsPath) # First delete the "where_are_my_files.txt"
                    except:
                        # file "where_are_my_files.txt" erroniously did not exist, but safe to ignore and continue.
                        pass
                    rmBindMountPoindCmd = "rmdir %s > /dev/null 2>&1" % bmpAbsPath
                    os.system(rmBindMountPoindCmd)
                    # remove BMP from the self.shared_vars.serverStatusDict if it exists
                    self.shared_vars.serverStatusDictLock.acquire()
                    if self.shared_vars.serverStatusDict.has_key(bmpAbsPath):
                        self.shared_vars.serverStatusDict.pop(bmpAbsPath)
                    self.shared_vars.serverStatusDictLock.release()

    def getExpectedBindMountPoints(self, bmpabspath=False): 
        '''
        Returns a dictionary of user.name:[server.name, ...] pairs which reflect expected bind mount points in user's home directories
        Disabled servers are omited from the dictionary.
        If argument bmpabspath = True, then a list of expected bmpAbsPaths are returned instead of a dictionary
        '''
        expectedBindMounts = {}
        for userObj in xsftp.webui.models.UserProfile.objects.all():
            expectedBindMounts[userObj.user.username] = [server.server_name for server in userObj.getAllReadServers() if server.enabled == True]
        if not bmpabspath:
            return expectedBindMounts
        # compile a list of bmpAbsPath's
        bmpAbsPaths = []
        for username in expectedBindMounts.keys():
            usersBMPs = [  "/home/%s/xsftp/%s" % (username, servername) for servername in  expectedBindMounts[username] ]
            bmpAbsPaths += usersBMPs
        return bmpAbsPaths

    def getLiveBindMountPoints(self): 
        '''
        Returns a dictionary of user.name:[server.name, ...] pairs which reflect live bind mount points in users home directories
        '''
        existingBindMountPoints = {}
        allUsers = [userObj.user.username for userObj in xsftp.webui.models.UserProfile.objects.all()]
        for user in allUsers:
            bindMountPoints = glob.glob("/home/" + user + "/xsftp/*")
            dirNames  = []
            for directory in bindMountPoints:
                dirNames.append(directory.split("/")[-1])
            existingBindMountPoints[user] = dirNames
        return existingBindMountPoints


    def doBindMount(self, bmpAbsPath):
        '''
        Atempts to bind-mount a server referenced by the specified bmpAbsPath.
        If server is already bind mounted, we just return successfully.
        This function references the specified server's record in the Django for mount parameters.
        '''
        # get server's name
        name = bmpAbsPath.split("/")[-1]
        # get user's name
        user = bmpAbsPath.split("/")[2]
        # check if already bind mounted
        liveBindMounts = self.getLiveBindMounts()
        if liveBindMounts.has_key(user) and name in liveBindMounts[user]:
            log (4, "BMP %s is already bind mounted, skipping doBindMount." % bmpAbsPath)
            return
        # perform the bind mount
        # get sid of server
        sid = xsftp.webui.models.Server.objects.get(server_name=name).id
        # get ismbAbsPath
        smbAbsPath = "%s%s" % (xsftp.common.constants.SERVERDIR, sid)
        # log attempt
        log(4, "Bind mounting %s to %s" % (smbAbsPath, bmpAbsPath))
        bindMountCmd = "mount --bind %s %s > /dev/null 2>&1" % (smbAbsPath, bmpAbsPath)
        os.system(bindMountCmd)
        return


    def unBindMount(self, bmpAbsPath):
        '''
        Performs a lazy unmount on specified bmpAbsPath
        '''
        log(4,"Doing unBindMount('%s')..." % bmpAbsPath)
        name = bmpAbsPath.split("/")[-1]
        if name not in self.getLiveBindMountList():
            log (5, "BMP %s is not bind mounted, skipping unBindMount." % bmpAbsPath)
            return
        unBindMountCmd = "umount -l %s > /dev/null 2>&1" % bmpAbsPath
        os.system(unBindMountCmd)
        return

    def getLiveBindMountList(self): 
        '''
        Basic utility function which returns a list of server.server_name's which are currently bind mounted
        '''
        dupesList = ";".join([";".join(value) for value in self.getLiveBindMounts().values()]).split(";") #implies that a ';' char is illegal in a Server.server_name (validated in django forms)
        uniqueList = []
        for item in dupesList:
            if item not in uniqueList:
                uniqueList.append(item)
        return uniqueList

    def getLiveBindMounts(self): 
        '''
        Returns a dictionary of live bind mounts as { user.name : [server.name] } pairs according /etc/mtab
        '''
        f = file("/etc/mtab")
        mounts = f.readlines()
        f.close()
        bindMounts = {}
        for line in mounts:
            lineParts = line.strip().split()
            # for each relevant line, i.e. the ones which contain "rw,bind"
            if lineParts[3] == "rw,bind":
                user = lineParts[1].split("/")[2] # The third part of '/home/<user>/xsftp/<server_name>', if you split it on '/'s
                serverName = lineParts[1].split("/")[-1] # The last part of the above
                if bindMounts.has_key(user):
                    bindMounts[user].append(serverName)
                else:
                    bindMounts[user] = [serverName]
        return bindMounts

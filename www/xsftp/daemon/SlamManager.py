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
from django.db.models import Q
from xsftp.daemon.Logger import log
from xsftp.common.Config import config


class SlamManager:
    def __init__(self, shared_vars, bmp_manager):
        self.shared_vars = shared_vars
        self.bmp_manager = bmp_manager

        # umount everything in xsftp.common.constants.SERVERDIR
        # XXX why do we do this? Is there a problem once with maintaining server
        # links across daemon process instances?
        for sid in self.getLiveSLAMMountPoints():
            self.unSLAMMount(sid)


    def initSLAMMountPoints(self): 
        '''
        Creates and removes (cleans up) the SLAM mount point directories in xsftp.common.constants.SERVERDIR based on data from the DB.
        '''

        # Get list of expected SLAM mount points
        expectedSLAMMountPoints = self.getExpectedSLAMMountPoints()
        log(4, "Expected SLAM Mount Points are ... %s" % expectedSLAMMountPoints)
        # Get list of live SLAM mount points
        liveSLAMMountPoints = self.getLiveSLAMMountPoints()
        log(4, "Live SMPs are ... %s" % [int(i) for i in liveSLAMMountPoints])
        # Create dir's for each sid which doesnt exist in liveSLAMMountPoints
        for sid in [str(x) for x in expectedSLAMMountPoints]:
            if not sid in liveSLAMMountPoints:
                # mount point for this server doesnt exist, create directory:
                newDir = xsftp.common.constants.SERVERDIR + str(sid)
                mkdirCmd = "mkdir " + newDir + " > /dev/null 2>&1"
                os.system(mkdirCmd)
                # Copy in a "where are my files" text message
                shutil.copy("%setc/xsftp/where_are_my_files.txt" % xsftp.common.constants.APPDIR, newDir)
        # Delete dir's for each sid which does not exist in expectedSLAMMountPoints
        for sid in liveSLAMMountPoints:
            if not sid in [str(x) for x in expectedSLAMMountPoints]:
                # lazy un-Bind-Mount and delete the server's associated bind mount points
                self.bmp_manager.rmBindMount(sid)
                # lazy un-mount the SMP
                #unmountSLAMMountPointCmd = "fusermount -uz " + xsftp.common.constants.SERVERDIR + sid + " > /dev/null 2>&1"
                unmountSLAMMountPointCmd = "umount -l " + xsftp.common.constants.SERVERDIR + sid + " > /dev/null 2>&1"
                rc = 0
                while not rc: rc = os.system(unmountSLAMMountPointCmd)
                #  delete the SLAM mount point
                rmSshfsMountPointCmd = "rm -f " + xsftp.common.constants.SERVERDIR + sid + "/where_are_my_files.txt; rmdir " + xsftp.common.constants.SERVERDIR + sid + " > /dev/null 2>&1"
                os.system(rmSshfsMountPointCmd)
        return

    def getExpectedSLAMMountPoints(self): 
        '''
        Returns a list of SIDs which should reflect actual SLAM mount points in the xsftp.common.constants.SERVERDIR directory according to the DB (omits disabled servers).
        '''
        return [s.id for s in xsftp.webui.models.Server.objects.filter(enabled=True)]


    def getLiveSLAMMountPoints(self, type='all'): #XXX what about type='ftp'?
        '''
        Returns a list of SIDs which reflect actual existing SLAM mount points in the xsftp.common.constants.SERVERDIR directory.
        type must be either 'sftp' 'cifs' or 'all'
        '''
        allDirs  = []
        globDir = xsftp.common.constants.SERVERDIR + "*"
        SLAMMountPoints = glob.glob(globDir)
        for directory in SLAMMountPoints:
            dirName = directory.split("/")[-1]
            if dirName != "lost+found":
                allDirs.append(dirName)
        if type == 'all':
            return allDirs
        # differentiate between sftp and cifs SMP's
        if type == 'sftp':
            sftp_q_object = Q(type__contains='sftp')
            sftpSLs = xsftp.webui.models.Server.objects.filter(sftp_q_object)
            sftpDirs = [ sftpSL.id for sftpSL in sftpSLs if str(sftpSL.id) in allDirs ]
            return sftpDirs
        elif type == 'cifs':
            cifs_q_object = Q(type__contains='cifs')
            cifsSLs = xsftp.webui.models.Server.objects.filter(cifs_q_object)
            cifsDirs = [ cifsSL.id for cifsSL in cifsSLs if str(cifsSL.id) in allDirs ]
            return cifsDirs

    def unSLAMMount(self, sid):
        '''
        Unmounts the SM related to the specified sid, as well as the related BM's.
        '''
        smpAbsPath = xsftp.common.constants.SERVERDIR + str(sid)
        try:
            while xsftp.webui.models.Server.objects.get(id=int(sid)).server_name in self.bmp_manager.getLiveBindMountList():
                os.system("umount -l %s > /dev/null 2>&1" % smpAbsPath)
        finally:
            rc = 0
            while not rc: rc = os.system("umount -l %s > /dev/null 2>&1" % smpAbsPath)
            return
        return

    def getLiveSLAMMounts(self):
        '''
        Returns a list of SID's for sshfs mounted servers
        '''
        f = file("/etc/mtab")
        mounts = f.readlines()
        f.close()
        # extract the SID from each sshfs mount point
        SLAMMounts = []
        # for each mount point line in mtab
        for line in mounts:
            fs_type = line.split()[2]
            # if it starts with "sshfs"
            if fs_type in ["fuse.sshfs", "cifs"]:
                # append the SID to SLAMMounts.
                SLAMMounts.append(line.split()[1].split("/")[-1])
        return SLAMMounts


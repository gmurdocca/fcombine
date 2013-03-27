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
import time
import threading
from threading import Thread

import xsftp.webui.models
from xsftp.daemon.Logger import log
from StatWorkerThread import StatWorkerThread

class RemediatorWorkerThread(Thread):
    '''
    Thread object spawned by connectorWorkerThread which attempts to repair a non-helthy connection (BindMountPoint) to a endpoint server.
    Takes in a single argument being the absolute path of the BMP as a string.
    '''
    
    def __init__(self, shared_vars, slam_manager, bmp_manager, bmpAbsPath):
        Thread.__init__(self)
        self.name = bmpAbsPath.split("/")[-1]
        self.shared_vars = shared_vars
        self.bmpAbsPath = bmpAbsPath
        self.slam_manager = slam_manager
        self.bmp_manager = bmp_manager
        self.server = xsftp.webui.models.Server.objects.get(server_name=self.name)
        self.sid = self.server.id

        # locks for calling the initMounts functions since they change the local filesystem
        self.initBindMountsLock = threading.Lock()
    
    def run(self):
        # get the current state of this BMP
        self.shared_vars.serverStatusDictLock.acquire()
        currentServerStatus = self.shared_vars.serverStatusDict[self.bmpAbsPath]
        self.shared_vars.serverStatusDictLock.release()
        state = currentServerStatus[1]
        # setup a shorthand reference to the statWorkerThread class for state name references below
        swt = StatWorkerThread 
        # attempt to remediate this server based on its state
        if state == swt.MPSTATE_OK:
            # this bmp is in state 0: Healthy. Do nothing, purge this job from the self.shared_vars.serverRepairInProgress global job queue and return
            # this condition should never happen, but process it just incase it does - maybe a bmp transitions from unhealthy to healthy in the split second it takes for this thread to fire up for example...
            log(3, "Finished repair attempt: BMP=%s State=0:MPSTATE_OK (nothing to do, as it was healthy on arrival)" % self.bmpAbsPath)
            return
        elif state in [ swt.MPSTATE_BM_BROKEN,
                        swt.MPSTATE_SM_BROKEN,
                        swt.MPSTATE_BM_AND_SM_BROKEN,
                        swt.MPSTATE_BM_UNREATTACHED,
                        swt.MPSTATE_NO_ROUTE_TO_HOST,
                        swt.MPSTATE_CONNECTION_REFUSED,
                        swt.MPSTATE_CONNECTION_TIMEOUT,
                        swt.MPSTATE_KEY_MISMATCH,
                        swt.MPSTATE_KEYFILE_MISSING,
                        swt.MPSTATE_WRONG_SERVICE,
                        swt.MPSTATE_PUBLIC_KEY_NOT_ALLOWED,
                        swt.MPSTATE_AUTH_FAILED,
                        swt.MPSTATE_KEY_REQUIRES_PASSPHRASE,
                        swt.MPSTATE_BAD_REMOTE_PATH,
                        swt.MPSTATE_SOCKET_ERROR,
                        swt.MPSTATE_CIFS_BAD_SHARE_NAME,
                        swt.MPSTATE_CIFS_ERROR,
                        swt.MPSTATE_FTP_DATA_CHANNEL_ERROR,
                        swt.MPSTATE_FTP_FTPS_NOT_SUPPORTED,
                        swt.MPSTATE_FTP_FTPES_NOT_SUPPORTED,
                        swt.MPSTATE_FTP_FTPES_REQUIRED,
                      ]:
            # FIX:(1) BRING UP THE SMP (IF NECESSARY), RIP DOWN THE BINDMOUNT (IF IT EXISTS), AND BRING UP THE BIND MOUNT
            self.slam_manager.doSLAMMount(self.sid)
            self.bmp_manager.unBindMount(self.bmpAbsPath)
            self.bmp_manager.doBindMount(self.bmpAbsPath)
            log(3, "Finished repair attempt: BMP=%s State=%s" % (self.bmpAbsPath, state))
        elif state in [ swt.MPSTATE_SM_DISCONNECTED_AND_BM_BROKEN,
                        swt.MPSTATE_SM_DISCONNECTED,]:
            # FIX:(2) (WAIT FOR THE CONNECTION TO BE RE-ESTABLISHED NATURALLY - SSHFS.C / mount.cifs / curlftpfs WILL FIX IT)
            log(3, "BMP %s has been in state %s (DISCONNECTED) for %s seconds - awaiting self-heal" % (self.bmpAbsPath, state, (int(time.time()) - currentServerStatus[2]) ) )
        elif state == swt.MPSTATE_BMP_DOESNT_EXIST:
            # FIX:(3) REINIT ALL BMP'S, AND BRING UP THE BIND MOUNT
            self.bmp_manager.initBindMountPoints()
            self.bmp_manager.doBindMount(self.bmpAbsPath)
            log(3, "Finished repair attempt: BMP=%s State=%s:MPSTATE_BMP_DOESNT_EXIST" % (self.bmpAbsPath, state) )
        elif state == swt.MPSTATE_SMP_DOESNT_EXIST:
            # FIX:(5) INIT ALL SMP'S, THEN RUN FIX(1)
            self.slam_manager.initSLAMMountPoints()
            self.slam_manager.doSLAMMount(self.sid)
            self.bmp_manager.unBindMount(self.bmpAbsPath)
            self.bmp_manager.doBindMount(self.bmpAbsPath)
            log(3, "Finished repair attempt: BMP=%s State=%s:MPSTATE_SMP_DOESNT_EXIST" % (self.bmpAbsPath, state) )
        else: # state will be swt.MPSTATE_ERROR1, swt.MPSTATE_ERROR2, swt.MPSTATE_ERROR3, swt.MPSTATE_ERROR4, swt.MPSTATE_FTP_ERROR, or -10 (server link unused), etc...
            # FIX:(4) CATCHALL. PULL DOWN ALL BM'S FOR THIS SM, PULL DOWN SM, BRING UP SM, BRING UP ALL BM'S FOR THIS SM
            self.slam_manager.unSLAMMount(self.sid)
            self.slam_manager.doSLAMMount(self.sid)
            self.initBindMountsLock.acquire()
            self.bmp_manager.initAllBindMounts()
            self.initBindMountsLock.release()
            # Log repair attempt.
            log(3, "Finished repair attempt: BMP=%s State=%s:MPSTATE_ERROR%s" % (self.bmpAbsPath, state, state) )

        # Mark BMP's entry in the repairInProgress job queue as completed.
        self.shared_vars.serverRepairInProgressLock.acquire()
        self.shared_vars.serverRepairInProgress.remove((self.bmpAbsPath, False))
        self.shared_vars.serverRepairInProgress.append((self.bmpAbsPath, True))
        self.shared_vars.serverRepairInProgressLock.release()
        # remove BMP's entry in the self.shared_vars.pendingRepair queue
        self.shared_vars.pendingRepairLock.acquire()
        self.shared_vars.pendingRepair.pop(self.bmpAbsPath)
        self.shared_vars.pendingRepairLock.release()
        log(6, "Repair worker removed bmp %s from self.shared_vars.pendingRepair queue" % self.bmpAbsPath)
        log(3, "Completed repair attempt for Server Link: %s" % os.path.basename(self.bmpAbsPath))
        return



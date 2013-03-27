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

# **********************************************************************************************
#          StatWorkerThread (The Inspector's assistant, the actual brains of the operation)
# **********************************************************************************************
import os
import time
import stat
import socket
import paramiko
from threading import Thread

import xsftp.daemon.SMBClient
import xsftp.common.constants
from xsftp.daemon import FTPClient
from xsftp.daemon import SMBClient
from xsftp.daemon.Logger import log
from xsftp.common.Config import config

class StatWorkerThread(Thread):
    '''
    Profiles each Bind Mount Point (BMP) via a "stat" check (and others), and assignes a status to each BMP based ireflecting the result, which is then saved to self.shared_vars.serverStatusDict.
    Takes a bmpAbsPath as a single argument, updates the bmpAbsPath's status entry in self.shared_vars.serverStatusDict, then returns.
    '''
    # time in seconds that a StatWorkerThread will
    # wait for a socket to be opened to an endpoint
    #server before bailing in error
    STWT_SOCKET_TIMEOUT = 5

    MPSTATE_OK                             = 0      # OK (Healthy)
    MPSTATE_BM_BROKEN                      = 1      # The bind mount is not set up
    MPSTATE_SM_BROKEN                      = 2      # THe SLAM mount is not set up, and the bind mount may or may not be, but in any case it will have to be re set up
    MPSTATE_BM_AND_SM_BROKEN               = 3      # The SLAM mount is not set up, the bind mount is not set up
    MPSTATE_SM_DISCONNECTED                = 4      # CIFS/SSHFS Mount is disconnected (eg network issues or service is down), but the bindMount is correctly set up
    MPSTATE_SM_DISCONNECTED_AND_BM_BROKEN  = 5      # SLAM Mount is disconnected, and the bindMount is non-existant
    MPSTATE_BM_UNREATTACHED                = 6      # The Bind mount was once attached to a SLAM mount which has since died. There may or may not be a new SLAM mount.
    MPSTATE_BMP_DOESNT_EXIST               = 7      # The BMP doesn't exist
    MPSTATE_SMP_DOESNT_EXIST               = 8      # The SMP doesn't exist
    MPSTATE_CANT_RESOLVE_HOSTNAME          = 9      # Can't resolve the server name of the specified back-end server
    MPSTATE_NO_ROUTE_TO_HOST               = 10     # No route to host
    MPSTATE_CONNECTION_REFUSED             = 11     # Connection refused
    MPSTATE_CONNECTION_TIMEOUT             = 12     # Connection timed out
    MPSTATE_KEY_MISMATCH                   = 13     # SSH host fingerprints no longer match!
    MPSTATE_KEYFILE_MISSING                = 14     # Cant open the private key file referenced by config.KEYFILE variable in xsftpd.conf
    MPSTATE_WRONG_SERVICE                  = 15     # Something other than an SSH daemon or CIFS service is listening on the remote port
    MPSTATE_PUBLIC_KEY_NOT_ALLOWED         = 16     # Public key auth is disallowed on the end-point server preventing us from connecting
    MPSTATE_AUTH_FAILED                    = 17     # authentication failed - public key may not be configured on endpoint server or incorrect username
    MPSTATE_KEY_REQUIRES_PASSPHRASE        = 18     # for some reason, our DSS key wants a passphrase to unlock it. Should never happen.
    MPSTATE_BAD_REMOTE_PATH                = 19     # The specified remote path does not exist
    MPSTATE_SOCKET_ERROR                   = 20     # Unexpected error occured during socket operation
    MPSTATE_CIFS_BAD_SHARE_NAME            = 21     # specified CIFS share name does not exist
    MPSTATE_CIFS_ERROR                     = 22     # Unknown CIFS Error occured
    MPSTATE_FTP_DATA_CHANNEL_ERROR         = 23     # failed to create FTP data channel
    MPSTATE_FTP_FTPS_NOT_SUPPORTED         = 24     # FTPS (implicit) not supported, or wrong service.
    MPSTATE_FTP_FTPES_NOT_SUPPORTED        = 25     # FTPES not supported.
    MPSTATE_FTP_FTPES_REQUIRED             = 26     # FTPES required.
    MPSTATE_FTP_ERROR                      = 27     # Generic FTP error, see logs for details
    MPSTATE_ERROR1                         = -1     # Error1 occurred
    MPSTATE_ERROR2                         = -2     # Error2 occurred
    MPSTATE_ERROR3                         = -3     # Error3 occurred
    MPSTATE_ERROR4                         = -4     # The fourth error condition we thought might possibly occur occurred
    MPSTATE_NOT_IN_USE                     = -10    # PLACEHOLDER ONLY. State = -10 is set by models.Server.save() (indicating not in use) if there are no users associated with a server link

    def __init__(self, shared_vars, bmpAbsPath):
        Thread.__init__(self)
        self.shared_vars = shared_vars
        self.bmpAbsPath = bmpAbsPath
    
    def run(self):
        status = -999 # catch all, but it will get overwritten.
        # get the server object referred to in the specified bmpAbsPath
        server = xsftp.webui.models.Server.objects.get(server_name=self.bmpAbsPath.split("/")[-1])
        # derive the smpAbsPath of the specified bmpAbsPath
        smpAbsPath = xsftp.common.constants.SERVERDIR + str(server.id)
        try:
            # stat the bmp to see how it is
            bmpStat = os.stat(self.bmpAbsPath) # returns a stat object
            # if we get here without invoking an exception ...
            # stat the associated smpAbsPath to see how it is
            smpStat = os.stat(smpAbsPath)
            # stat the root partition (this should never fail, but catch it in any case
            rootStat = os.stat(xsftp.common.constants.SERVERDIR)
            # If we get here, then all stat commands have completed SUCCESSFULLY
            # Now do some comparisons 
            # if the bmp device is the same as the smp device, and different to the root device:
            if (bmpStat.st_dev == smpStat.st_dev != rootStat.st_dev):
                # everything is OK
                status = self.MPSTATE_OK
            # elif the bmp device is the same as the smp device and the same as the root device:
            elif (bmpStat.st_dev == smpStat.st_dev == rootStat.st_dev):
                # the SLAM mount does not exist. Try find out why.
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.STWT_SOCKET_TIMEOUT)
                if server.type == 'sftp':
                    log(4, "Testing SFTP-specific health for BMP: %s" % self.bmpAbsPath)
                    s.connect((server.address, server.port)) # this can throw several errors that we handle below, which divulge status info
                    t = paramiko.Transport(s)
                    t.connect()    # this will throw if something other than an SSH daemon is listening on the remote port (banner error) because it happens pre-auth.
                    remoteFingerPrint = t.get_remote_server_key().get_fingerprint()
                    try:
                        localFingerPrint = paramiko.util.load_host_keys(os.path.expanduser(xsftp.common.constants.KNOWN_HOSTS_FILE))[server.address]['ssh-rsa'].get_fingerprint() # raises IOError if file doesnt exist or KeyError if server not a known_host yet
                    except:
                        localFingerPrint = None
                    # if keys dont match...
                    if localFingerPrint and not localFingerPrint == remoteFingerPrint:
                        # The remote fingerprint has changed! could be man-in-the-middle, etc.
                        status = self.MPSTATE_KEY_MISMATCH
                    else:
                        # the fingerprints are fine, continue the checks
                        key = paramiko.DSSKey.from_private_key_file(str(config.KEYFILE)) # could raise "IOError: [Errno 2] No such file or directory:" in event of missing key
                        t.auth_publickey(server.remote_user, key) #can throw several errors which divulge status info
                        # establish a client session to the endpoint to stat the specified remote_dir and ensure it exists
                        c = t.open_sftp_client()
                        st = c.stat(server.remote_path) # this raises IOError: [Errno 2] No such file on error
                        # if the specified remote path isnt a directory
                        if not stat.S_ISDIR(st.st_mode):
                            # then the specified remote path is invalid
                            status = self.MPSTATE_BAD_REMOTE_PATH
                        else:
                            #if we get this far, then there is nothing wrong with the SSH layer and below (physical, etc), so to remediate we can initialise the SMP.
                            status = self.MPSTATE_SM_BROKEN
                elif server.type == 'cifs':
                    log(4, "Testing CIFS-specific health for BMP: %s" % self.bmpAbsPath)
                    s.connect((server.address, server.cifs_port))
                    # if we get here, the target is listening and allowing connections on the specified port.
                    # test for CIFS related errors
                    s = SMBClient.SMBClient(server.address, server.cifs_port, server.cifs_share, username=server.remote_user, password=server.cifs_password)
                    if server.remote_path and not s.is_dir(str(server.remote_path)):
                        status = self.MPSTATE_BAD_REMOTE_PATH
                    else:
                        # if we get here, the cifs stuff looks good, set status to the CIFS catch all
                        status = self.MPSTATE_CIFS_ERROR
                    s.close()
                elif server.type == 'ftp':
                    log(4, "Testing FTP-specific health for BMP: %s" % self.bmpAbsPath)
                    f = FTPClient.FTP(server.address, port=server.ftp_port, passive=server.ftp_passive, user=str(server.remote_user), passwd=str(server.ftp_password), ssl=server.ftp_ssl, ssl_implicit=server.ftp_ssl_implicit)
                    f.login()
                    f.retrlines('LIST', callback=lambda msg: None)
                    f.cwd(str(server.remote_path))
            # elif the bmp device is different to the smp device which is in turn different to the root device
            elif bmpStat.st_dev != smpStat.st_dev != rootStat.st_dev:
                # The SSHFS mount is correct, and the bindmount isn't
                status =  self.MPSTATE_BM_BROKEN 
            # elif the bmp device is different to the smp device which is in turn the same as the root device
            elif bmpStat.st_dev != smpStat.st_dev == rootStat.st_dev:
                # both the BM and SM are broken
                status = self.MPSTATE_BM_AND_SM_BROKEN
            else:
                # The catch-the-rest
                log(1, "Unexpected Server Link error, resetting Server Link %s:'%s'." % (server.server_name, server.id))
                status = self.MPSTATE_ERROR1
        # Catch exceptions for the above checks
        except FTPClient.error_wrong_service, e:
            status = self.MPSTATE_WRONG_SERVICE
        except FTPClient.error_data_channel, e:
            status = self.MPSTATE_FTP_DATA_CHANNEL_ERROR
        except FTPClient.error_bad_credentials, e:
            status = self.MPSTATE_AUTH_FAILED
        except FTPClient.error_ftps_not_supported, e:
            status = self.MPSTATE_FTP_FTPS_NOT_SUPPORTED
        except FTPClient.error_ftpes_not_supported, e:
            status = self.MPSTATE_FTP_FTPES_NOT_SUPPORTED
        except FTPClient.error_bad_remote_path, e:
            status = self.MPSTATE_BAD_REMOTE_PATH
        except FTPClient.error_ftpes_required, e:
            status = self.MPSTATE_FTP_FTPES_REQUIRED
        except FTPClient.Error, FTPClientExceptionText:
            status = self.MPSTATE_FTP_ERROR
            log(2, "Server Link '%s' (type FTP) in unhealthy state MPSTATE_FTP_ERROR, error message is: %s" % (server.server_name, FTPClientExceptionText))
        except SMBClient.SMBClientException, e:
            e = str(e)
            if e == "bad share name":
                status = self.MPSTATE_CIFS_BAD_SHARE_NAME
            elif e == "bad credentials":
                status = self.MPSTATE_AUTH_FAILED
            elif e == "wrong service":
                status = self.MPSTATE_WRONG_SERVICE
            else:
                log(1, "CIFS health error: %s" % e)
                status = self.MPSTATE_CIFS_ERROR
        except socket.gaierror, e:
            if e[0] == -2:
                #can't resolve server name
                status = self.MPSTATE_CANT_RESOLVE_HOSTNAME
            else:
                status = self.MPSTATE_SOCKET_ERROR
        except socket.error, e:
            if e[0] == 111:
                # Connection refused - host did a REJECT
                status = self.MPSTATE_CONNECTION_REFUSED
            elif e[0] == 113:
                # no route to host
                status = self.MPSTATE_NO_ROUTE_TO_HOST
            elif str(e) == "timed out":
                # connection timed out. bad ip address, cable issue, firewall issue 
                status = self.MPSTATE_CONNECTION_TIMEOUT
            else:
                status = self.MPSTATE_SOCKET_ERROR
        except paramiko.BadAuthenticationType:
            # occurs if public-key authentication isn't allowed by the endpoint server
            status = self.MPSTATE_PUBLIC_KEY_NOT_ALLOWED
        except paramiko.PasswordRequiredException:
            # occurs when a password is needed to unlock a private key file - should never happen.
            status = self.MPSTATE_KEY_REQUIRES_PASSPHRASE
        except paramiko.AuthenticationException:
            # occurs if the authentication failed
            status = self.MPSTATE_AUTH_FAILED
        except paramiko.SSHException:
            # should occur iff something other than an SSH daemon is listening on the remote port.
            status = self.MPSTATE_WRONG_SERVICE
        except IOError, e:
            if e.strerror == 'No such file':
                # remote path doesnt exist
                status = self.MPSTATE_BAD_REMOTE_PATH
            else:
            # Unable to open host keys file
                status = self.MPSTATE_KEYFILE_MISSING
        except OSError, e:
            # check that the Exception has an Error Number associated with it (ie does it have a "errno" attribute)
            if hasattr(e, "errno") and hasattr(e, "filename"):
                # if this was raised by the BMP stat
                if e.filename == self.bmpAbsPath:
                    # errno 5 | 112 --> IO Error
                    if e.errno == 5 or e.errno == 112:
                        status = self.MPSTATE_SM_DISCONNECTED # FIX:(2) (WAIT FOR THE CONNECTION TO BE RE-ESTABLISHED NATURALLY - sshfs WILL FIX IT (but curlftpfs might not!))
                    # errno 107 --> Endpoint Transport Disconnected
                    elif e.errno == 107:
                        status = self.MPSTATE_BM_UNREATTACHED # FIX:(1)
                    # errno 2 --> File not found
                    elif e.errno == 2:
                        # the bind Mount Point does not exist
                        status = self.MPSTATE_BMP_DOESNT_EXIST # FIX:(3) REINIT ALL BMP'S, AND BRING UP THE BIND MOUNT
                    else:
                        log(3, "Error MPSTATE_ERROR1: Got OSError when running stat command on Bind Mount point: FILE=%s, BMP=%s,  ErrorNo=%s, Desc=%s" % (e.filename, self.bmpAbsPath, e.errno, e.strerror))
                        status = self.MPSTATE_ERROR1 # FIX:(4) CATCHALL. PULL DOWN ALL BM'S FOR THIS SM, PULL DOWN SM, BRING UP SM, BRING UP ALL BM'S FOR THIS SM
                # elif this was raised by the SMP stat
                elif e.filename == smpAbsPath:
                    # errno 5 --> IO Error
                    if e.errno == 5:
                        status = self.MPSTATE_SM_DISCONNECTED_AND_BM_BROKEN # FIX:(1)
                    # errno 2 --> File not found
                    elif e.errno == 2:
                        # the sshfs Mount Point does not exist
                        status = self.MPSTATE_SMP_DOESNT_EXIST # FIX:(5) INIT ALL SMP'S, THEN RUN FIX(1)
                    else:
                        log(3, "Got unexpected OSError when running stat command on SLAM mount point: FILE=%s, BMP=%s, ErrorNo=%s, Desc=%s" % (e.filename, self.bmpAbsPath, e.errno, e.strerror))
                        status = self.MPSTATE_ERROR2 # FIX:(4)
                # else this was raised by the root stat, or something else weird is happening
                else:
                    log(3, "Got unexpected OSError when running stat command on %s: BMP=%s, ErrorNo=%s, Desc=%s" % (e.filename, self.bmpAbsPath, e.errno, e.strerror))
                    status = self.MPSTATE_ERROR3 # FIX:(4)
            else:
                log(3, "Got unexpected OSError when running stat command on %s. OSError is: %s" % (e.filename, e))
                status = self.MPSTATE_ERROR4 # FIX:(4)
        # Close the sftp_client and ssh_transport and socket objects (in that order) if they were opened.
        try: c.close()
        except: pass
        try: t.close()
        except: pass
        try: s.close()
        except: pass
        try: f.quit()
        except: pass
        # call setStatus to set the status
        self.setStatus(self.bmpAbsPath, status)
        # if state is not healthy
        if status:
            # then append this bmp to the self.shared_vars.pendingRepair global dict
            self.shared_vars.pendingRepairLock.acquire()
            self.shared_vars.pendingRepair[self.bmpAbsPath] = status
            self.shared_vars.pendingRepairLock.release()
            log(6, "Stat worker added bmp %s to the self.shared_vars.pendingRepair queue" % self.bmpAbsPath)
        # Remove the entry from the self.shared_vars.statChecksInProgress table
        self.shared_vars.statChecksInProgressLock.acquire()
        self.shared_vars.statChecksInProgress.remove(self.bmpAbsPath)
        log(5, "Removed %(bmp)s from the statCheck job queue. statCheck job queue length is %(jobQueueLength)s" % {"threadNumber":self.getName(), "bmp":self.bmpAbsPath, "jobQueueLength":len(self.shared_vars.statChecksInProgress)})
        self.shared_vars.statChecksInProgressLock.release()
        # if it exists, remove this remediation job that which is marked Completed (second val in tuple == True) in the self.shared_vars.serverRepairInProgress job queue:
        self.shared_vars.serverRepairInProgressLock.acquire()
        currentServerRepairInProgress = self.shared_vars.serverRepairInProgress[:]
        for item in currentServerRepairInProgress:
            if item[0] == self.bmpAbsPath and item[1] == True:
                self.shared_vars.serverRepairInProgress.remove(item)
        self.shared_vars.serverRepairInProgressLock.release()


    def setStatus(self, bmpAbsPath, state):
        '''
        Sets status values of a specified BMP in the serverStatusDict dictionary, which is of the form:
        {BMP : ('sid', state, timeSinceEpocFirstSeenInCurrentState, timeSinceEpocLastSeenHealthy)}

        Takes in two arguments:
            bmpAbsPath (string) is the BMP's absolute path as a string
            state (int) is the state value to assign to the specified BMP
        
        * If BMP has never been healthy, timeSinceEpocLastSeenHealthy value will be set to the time the daemon started.
        '''
        # if there is no entry in the serverStatusDict for this bmp, and it's state is initially not zero (ie. it is unhealthy) then set this value to -1
        self.shared_vars.serverStatusDictLock.acquire()
        # if BMP has no entry in the serverStatusDict, set timeSinceLastHealthy value to the current time.
        if not self.shared_vars.serverStatusDict.has_key(bmpAbsPath):
            timeSinceLastHealthy = int(time.time())
        else:
        # assign it's new timeSinceLastHealthy value to that which it was previously.
            timeSinceLastHealthy = self.shared_vars.serverStatusDict[bmpAbsPath][3]
        self.shared_vars.serverStatusDictLock.release()
        # if the status value for the BMP given in this functions second argumen't is 0 (healthy)
        if state == 0:
            # set the timeSinceLastHealthy to now:
            timeSinceLastHealthy = int(time.time())
        # save the values to the tuples in the serverStatusDict dictionary.
        self.shared_vars.serverStatusDictLock.acquire()
        # if dicrt does not yet contain status for this bmp, or status has changed
        if not self.shared_vars.serverStatusDict.has_key(bmpAbsPath) or self.shared_vars.serverStatusDict[bmpAbsPath][1] != state:
            # we have detected a status change, set timeFirstSeenInCurrentState
            timeFirstSeenInCurrentState = int(time.time())
            log(3, "State Change: Found "  + bmpAbsPath + " in state " + str(state))
            log(2, "State Change: Found Server Link '"  + os.path.basename(bmpAbsPath) + "' in %s state " % ['unhealthy','healthy'][state==0] + str(state))
        else:
            # preserve timeFirstSeenInCurrentState
            timeFirstSeenInCurrentState = self.shared_vars.serverStatusDict[bmpAbsPath][2]
        # save the values
        sid = xsftp.webui.models.Server.objects.get(server_name=bmpAbsPath.split("/")[-1]).id
        self.shared_vars.serverStatusDict[bmpAbsPath] = (sid, state, timeFirstSeenInCurrentState, timeSinceLastHealthy)
        self.shared_vars.serverStatusDictLock.release()
        # if state is healthy, remove this bmp's entry in the global alertTracekr dict
        self.shared_vars.alertTrackerLock.acquire()
        if state == 0 and sid in self.shared_vars.alertTracker:
            self.shared_vars.alertTracker.pop(sid)
        self.shared_vars.alertTrackerLock.release()


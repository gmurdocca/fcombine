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

# ***********************************************************
#          StatusWorkerThread (The Inspector)
# ***********************************************************
import os
import grp
import time
import shlex
import datetime
import paramiko
import threading
import subprocess
from binascii import hexlify
from threading import Thread

import xsftp.common.constants
from xsftp.daemon import FTPClient
from xsftp.daemon import SMBClient
from xsftp.daemon.Logger import log
from xsftp.common.Config import config
from StatWorkerThread import StatWorkerThread

class StatusWorkerThread(Thread):
    '''
    This (solitary) thread:
    - profiles each Bind Mount Point (BMP), assignes a status to each BMP based on it's profile and saves the status in a dict called self.shared_vars.serverStatusDict
    - removes any jobs in the remediation job queue if the job has been marked "repair attempt complete" by it's assigned rememdiator.
    - updates the Django DB with server statuses.
    - synchronises the key_fingerprint value in server objects in the Django DB with those in known_hosts
    - synchronises the running_now status of job objects in the Django DB with what really happening on the system
    Note: self.shared_vars.serverStatusDict is a dict of the form {BMP : ('sid', state, FirstSeenInCurrentState, LastSeenHealthy)}
    '''


    # time in seconds the StatusWorkerThread (inspector)
    # sleeps for between iterations
    SWT_SLEEP = 20
    
    def __init__(self, shared_vars, slam_manager, bmp_manager):
        Thread.__init__(self)
        self.setDaemon(True)
        self.shared_vars = shared_vars
        self.slam_manager = slam_manager
        self.bmp_manager = bmp_manager

        # A dict and associated lock for mounting SSHFS mounts
        self.SLAMMountsInProgress = {}
        self.SLAMMountsInProgressLock = threading.Lock()

    def run(self):
        '''    
        Each iteration of this perpetual loop will profile every BMP and update the self.shared_vars.serverStatusDict with its status.
        It will also clear any jobs marked as completed from the remediation thread's job queue.
        '''
        while True:
            #log(6, "Number of objects = %s" % len(gc.get_objects()))
            self.initAllMountPoints()
            # cleanup self.shared_vars.serverStatusDict of any entries that should not ne in there (failsafe against memory leaks on self.shared_vars.serverStatusDict)
            exptectdBMPList = self.bmp_manager.getExpectedBindMountPoints(bmpabspath=True)
            self.shared_vars.serverStatusDictLock.acquire()
            currentServerStatusDict = self.shared_vars.serverStatusDict.copy()
            for key in currentServerStatusDict.keys():
                if key not in exptectdBMPList:
                    log(6, "removing bmpAbsPath: '%s' from the self.shared_vars.serverStatusDict as it no longer requires health checking." % key)
                    self.shared_vars.serverStatusDict.pop(key)
            self.shared_vars.serverStatusDictLock.release()
            # profile each BMP for its status.
            # get all expected BMP's:
            bindMountPointsDict = self.bmp_manager.getExpectedBindMountPoints()
            # for each user's BMP
            for user in bindMountPointsDict.keys():
                for bindMountPoint in bindMountPointsDict[user]:
                    # set bmpAbsPath
                    bmpAbsPath = "/home/%s/xsftp/%s" % (user, bindMountPoint)
                    # if this bmp's status is still being worked on by a statWorkerThread (spawned by a previous iteration of this loop in this thread)
                    self.shared_vars.statChecksInProgressLock.acquire()
                    if self.shared_vars.statChecksInProgress.__contains__(bmpAbsPath):
                        self.shared_vars.statChecksInProgressLock.release()
                        log(5, "%s's status is still being profiled, skipping this status update iteration." % bmpAbsPath)
                        # then skip attempt to update status again
                        continue
                    else:
                        # if it is pending repair
                        self.shared_vars.pendingRepairLock.acquire()
                        if bmpAbsPath in self.shared_vars.pendingRepair.keys():
                            log(5, "%s's is marked as repair pending, skipping this status update iteration." % bmpAbsPath)
                            self.shared_vars.pendingRepairLock.release()
                            self.shared_vars.statChecksInProgressLock.release()
                            # then skip attempt to update status until repair is done
                            continue
                        # otherwise, check its status
                        self.shared_vars.pendingRepairLock.release()
                        self.shared_vars.statChecksInProgress.append(bmpAbsPath)
                        # spawn a statWorkerThread for this BMP to determine status
                        statThread = StatWorkerThread(self.shared_vars, bmpAbsPath)
                        statThread.start()
                    self.shared_vars.statChecksInProgressLock.release()
            # write to the logs a table of statuses for each bmp.
            self.shared_vars.serverStatusDictLock.acquire()
            for key in self.shared_vars.serverStatusDict.keys():
                log(6, "*** self.shared_vars.serverStatusDict entry: %s : %s" % (key, str(self.shared_vars.serverStatusDict[key])))
            # Now update the Django database with the latest info from the ServerStatusDict
            # ConsolidatedServerStatusDict - a dictionary of server_names:(state, timeFirstSeenInCurrentState, timeLastSeenHealthy)
            consolidatedServerStatusDict = dict()
            # For each bind_mount in the ServerStatusDict
            for bmp in self.shared_vars.serverStatusDict.keys():
                # Get the associated server and other details
                (sid, currentState, timeFirstSeenInCurrentState, timeLastSeenHealthy) = self.shared_vars.serverStatusDict[bmp]
                # If the Server doesn't exist in ConsolidatedServerStatusDict
                if sid not in consolidatedServerStatusDict.keys():
                    # Then add all the details in to ConsolidatedServerStatusDict from the current 
                    consolidatedServerStatusDict[sid] = (currentState, timeFirstSeenInCurrentState, timeLastSeenHealthy)
                # Elif this bind_mount is healthy and existing_entry is healthy:
                elif currentState == 0 and consolidatedServerStatusDict[sid][0] == 0:
                    # use the values from the one with the oldest (lowest) timeFirstInCurrentState
                    if timeFirstSeenInCurrentState < consolidatedServerStatusDict[sid][1]:
                        consolidatedServerStatusDict[sid] = (currentState, timeFirstSeenInCurrentState, timeLastSeenHealthy)
                # Elif this bind mount is unhealthy and the existing entry is healthy:
                elif currentState != 0 and consolidatedServerStatusDict[sid][0] == 0:
                    # Then add all the details in to ConsolidatedServerStatusDict from the current bind_mount
                    consolidatedServerStatusDict[sid] = (currentState, timeFirstSeenInCurrentState, timeLastSeenHealthy)
                # Elif this bind mount is unhealthy:
                elif currentState != 0:
                    # use the values from the one with the newest (highest) timeFirstSeenInCurrentState value
                    if timeLastSeenHealthy > consolidatedServerStatusDict[sid][1]:
                        consolidatedServerStatusDict[sid] = (currentState, timeFirstSeenInCurrentState, timeLastSeenHealthy)
            self.shared_vars.serverStatusDictLock.release()
            # For each server in ConsolidatedServerStatusDict:
            for sid in consolidatedServerStatusDict.keys():
                # print sid, consolidatedServerStatusDict[sid]
                # Grab the server from the database
                server = xsftp.webui.models.Server.objects.get(id=sid)
                # Update its details
                server.status = consolidatedServerStatusDict[sid][0]
                server.timeFirstSeenInCurrentState =  datetime.datetime.fromtimestamp(consolidatedServerStatusDict[sid][1])
                server.timeLastSeenHealthy =  datetime.datetime.fromtimestamp(consolidatedServerStatusDict[sid][2])
                server.time_last_checked = datetime.datetime.now()
                # Save the server
                server.save(synchronise=False)
            # Check that all servers which have a key_fingerprint value have an equivalent entry in KNOWN_HOSTS, if not, nullify their key_fingerprint in the DB.
            f = file(xsftp.common.constants.KNOWN_HOSTS_FILE, 'r')
            f.close()
            knownHostAddresses = [host.split(':')[0].replace("[","").replace("]","") for host in paramiko.util.load_host_keys(os.path.expanduser(xsftp.common.constants.KNOWN_HOSTS_FILE)).keys()]
            for server in [serverObj for serverObj in xsftp.webui.models.Server.objects.all() if serverObj.key_fingerprint]:
                if server.address not in knownHostAddresses:
                    server.key_fingerprint = None
                    server.save(synchronise=False)
            #add fingerprints to sftp-type server objs that dont have one in django but do have one in known_hosts
            for server in [serverObj for serverObj in xsftp.webui.models.Server.objects.all() if serverObj.type == "sftp" and not serverObj.key_fingerprint]:
                # get the key fingerprint from the known_hosts file
                fingerPrint = self.get_key_fingerprint(server.address, server.port, write_log=False)
                if fingerPrint:
                    server.key_fingerprint = fingerPrint
                    server.save(synchronise=False)
            # Check for jobs that look like they are running (ie pid != None), and check that there is the associated process for it. If not, clean up the job's attributes
            jobs = xsftp.webui.models.Job.objects.all()
            running_jobs = list()
            for job in jobs:
                if job.pid:
                    # append running job
                    running_jobs.append(job)
                else:
                    # job isn't running, ensure its running_now value is sane (must not be None (terminating..) or True (running now))
                    if job.running_now != False:
                        job.running_now = False
                        job.save()
            for job in running_jobs:
                try:
                    # we call getpgid, and if the process doesn't exist, an Exception is raised
                    os.getpgid(job.pid)
                except OSError:
                    # The process doesn't exist, so clean up the job
                    job.running_now = False
                    job.pid = None
                    job.save()
            # now sleep for set time
            time.sleep(self.SWT_SLEEP)


    def get_key_fingerprint(self, address, port, write_log=True):
        # get the key fingerprint from the known_hosts file
        if str(port) == '22':
            kh_key = address
        else:
            kh_key = "[%s]:%s" % (address, port)
        fingerPrint = None
        try:
            fingerPrint = hexlify(paramiko.util.load_host_keys(os.path.expanduser(xsftp.common.constants.KNOWN_HOSTS_FILE))[kh_key]['ssh-rsa'].get_fingerprint())
        except IOError:
            if write_log:
                log(4, "fingerprint check for endpoint server at address '%s' failed: Known hosts file does not exist!" % address)
        except KeyError:
            if write_log:
                log(4, "fingerprint check for endpoint server at address '%s' failed: Address not found in known hosts file." % address)
        return fingerPrint

    def doSLAMMount(self, sid): 
        '''
        Atempts to mount a server referenced by the specified sid.
        If server is already sshfs mounted, we just return successfully.
        '''
        # check if sshfs mount is already being worked on
        self.SLAMMountsInProgressLock.acquire()
        log(6, "Acquired self.SLAMMountsInProgressLock")
        if sid not in self.SLAMMountsInProgress.keys():
            log(5, "No other threads are working on this Server Link %s, I will assume responsiblity." % sid)
            self.SLAMMountsInProgress[sid] = threading.Condition(self.SLAMMountsInProgressLock)
            log(6, "About to release the self.SLAMMountsInProgressLock")
            self.SLAMMountsInProgressLock.release()
        else:
            log(5, "Server Link %s is already being worked on - waiting for it to be fixed" % sid)
            self.SLAMMountsInProgress[sid].wait()
            log(5, "This thread got woken up - Server Link %s has been marked as fixed (and waiting for check)" % sid)
            self.SLAMMountsInProgressLock.release()
            return
        # This next bit checks whether the sshfs mount is already mounted, which can happen if some other thread fixed just before we did.
        # Additionally, while we were getting here, a few threads on our tail may have already come in and joined the wait queue,
        # so we need to wake them up and then we can all bail out of here.
        if str(sid) in self.slam_manager.getLiveSLAMMounts():
            log (5, "Server Link %s is already mounted, skipping." % sid)
            self.SLAMMountsInProgressLock.acquire()
            condition = self.SLAMMountsInProgress.pop(sid)
            condition.notifyAll()
            self.SLAMMountsInProgressLock.release()
            return

        ###################################
        ### SERVER LINK MOUNTING BEGINS ###

        # get server object referenced by sid in argument
        serverObj = xsftp.webui.models.Server.objects.get(id=sid)

        # ================
        # SSHFS MOUNT CODE
        # ================

        if serverObj.type == 'sftp':
            # get server_name
            server_name = serverObj.server_name
            # get GID for this server's linux write group
            gid = str(grp.getgrnam("x_%s" % sid)[2])
            # get server's address
            address = serverObj.address
            # get port number
            port = int(serverObj.port)
            # get keyfile location
            key = serverObj.key_file
            # get remoteuser
            remoteuser = serverObj.remote_user
            # get remote path
            remotepath = serverObj.remote_path
            log(4, "Mounting %s (type: sftp): SID=%s  ADDRESS=%s PORT=%s writeGroupName=x_%s GID=%s KEY=%s USERNAME=%s REMOTE_PATH=%s" % (server_name, sid, address, port, sid, gid, key, remoteuser, remotepath))
            # if this server's address is NOT in the known_hosts file, or the file doesnt exist, add the StrictHostKeyChecking=no option to suppress interactive yes/no ssh confirmation
            doStrictKeyCheck = False
            for host in paramiko.util.load_host_keys(xsftp.common.constants.KNOWN_HOSTS_FILE).keys():
                components = host.split(':')
                host_name = components[0].replace("[","").replace("]","")
                if len(components) == 1:
                    port = 22
                elif len(components) == 2:
                    port = int(components[1])

                if server.address == host_name and server.port == port:
                    log(4, "Performing strict key check for server link %s since I found its matching hostname '%s:%s' in known_hosts" % (server_name, address, port))
                    doStrictKeyCheck = True

            if doStrictKeyCheck == True:
                mountCmd = "sshfs -o UserKnownHostsFile=%s,StrictHostKeyChecking=yes,compression=yes,cache=no,default_permissions,uid=0,gid=%s,umask=002,nonempty,reconnect,allow_other,IdentityFile=%s,ServerAliveInterval=3,port=%s %s@%s:'%s' %s%s > /dev/null 2>&1" % (xsftp.common.constants.KNOWN_HOSTS_FILE, gid, key, port, remoteuser, address, remotepath, xsftp.common.constants.SERVERDIR, sid)
                log(6, "sshfsmount command is: %s" % mountCmd)
            else:
                log (4, "omitting strict key check for server link %s since I could not find a matching hostname '%s' in known_hosts" % (server_name, address))
                mountCmd = "sshfs -o UserKnownHostsFile=%s,StrictHostKeyChecking=no,compression=yes,cache=no,default_permissions,uid=0,gid=%s,umask=002,nonempty,reconnect,allow_other,IdentityFile=%s,ServerAliveInterval=3,port=%s %s@%s:'%s' %s%s > /dev/null 2>&1" % (xsftp.common.constants.KNOWN_HOSTS_FILE, gid, key, port, remoteuser, address, remotepath, xsftp.common.constants.SERVERDIR, sid)
                log(6, "sshfsmount command is: %s" % mountCmd)
            result = os.system(mountCmd)
            if result:
                # log failed sshfs mount attempt
                log(2, "Server Link (type: sftp) establishment attempt for server '%s' failed. Return code was %s" % (server_name, result))
            else:
                # log successful sshfs mount attempt
                log(4, "Success: sshfs mount to %s:%s established." % (address, port))
                log(1, "Server Link '%s' successfully established." % server_name)
                # get the key fingerprint from the known_hosts file
                fingerPrint = self.get_key_fingerprint(address, port)
                # save fingerprint to django models.Server
                if serverObj.key_fingerprint != fingerPrint:
                    log(4, "Got new/different fingerprint %s for Server Link '%s'" % (fingerPrint, server_name))
                    serverObj.key_fingerprint = fingerPrint
                    serverObj.save(synchronise=False)

        # ===============
        # CIFS MOUNT CODE
        # ===============

        elif serverObj.type == 'cifs':
            argDict = { 'sid':serverObj.id,
                        'name':serverObj.server_name,
                        'address': serverObj.address,
                        'cifs_port':serverObj.cifs_port,
                        'cifs_share': serverObj.cifs_share,
                        'remote_path': serverObj.remote_path,
                        'mount_point': "%s%s" % (xsftp.common.constants.SERVERDIR, sid),
                        'remote_user': serverObj.remote_user,
                        'cifs_password': serverObj.cifs_password,
                        'gid': str(grp.getgrnam("x_%s" % serverObj.id)[2])
                        }
            mountCmd = "/sbin/mount.cifs //%(address)s/'%(cifs_share)s'/'%(remote_path)s' %(mount_point)s -o user='%(remote_user)s',pass='%(cifs_password)s',uid=0,gid=%(gid)s,rw,dir_mode=0775,file_mode=0775,port=%(cifs_port)s > /dev/null 2>&1" % argDict
            # If the specified remote path points to a file instead of a dir, the mount command will still work and the mount point will appear as that file. Ensure this does not happen.
            remote_path_ok = True
            SMBClientExceptionText = "unknown"
            try:
                s = SMBClient.SMBClient(serverObj.address, serverObj.cifs_port, serverObj.cifs_share, username=serverObj.remote_user, password=serverObj.cifs_password)
                if serverObj.remote_path:
                    remote_path_ok = s.is_dir(str(serverObj.remote_path))
                    SMBClientExceptionText = "bad remote path"
            except Exception, SMBClientExceptionText:
                remote_path_ok = False
            try:
               s.close()
            except:
                pass
            if remote_path_ok:
                log(4, "Mounting %(name)s (type: cifs): SID=%(sid)s  ADDRESS=%(address)s PORT=%(cifs_port)s GID=%(gid)s USERNAME=%(remote_user)s SHARE_NAME=%(cifs_share)s REMOTE_PATH=%(remote_path)s" % argDict)
                log(6, "cifs mount command is: %s" % mountCmd.replace("pass='%s'" % serverObj.cifs_password, "pass=<HIDDEN>"))
                p = subprocess.Popen(mountCmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                rc = os.waitpid(p.pid, 0)[1]
                if rc:
                    log(2, "Server Link (type: cifs) establishment attempt for server '%s' failed. Return code was %s" % (serverObj.server_name, rc))
                else:
                    log(2, "Server Link '%s':'%s' (type: cifs) successfully established." % (serverObj.address, serverObj.server_name))
            else:
                log(2, 'Server Link (type: cifs) "%s" failed pre-checks (Error: %s), skipping establishment.' % (serverObj.server_name, SMBClientExceptionText))

        # ==============
        # FTP MOUNT CODE
        # ==============

        elif serverObj.type == 'ftp':
            # set variables (to prevent raciness)
            address = serverObj.address
            ftp_port = serverObj.ftp_port
            ftp_passive = serverObj.ftp_passive
            remote_user = str(serverObj.remote_user)
            ftp_password = str(serverObj.ftp_password)
            ftp_ssl = serverObj.ftp_ssl
            ftp_ssl_implicit = serverObj.ftp_ssl_implicit
            remote_path = str(serverObj.remote_path)
            server_name = serverObj.server_name
            id = serverObj.id
            # perform pre-checks
            do_ftp_mount = True
            log(6,"performing FTP pre-checks for server link %s" % server_name)
            try:
                f = FTPClient.FTP(address, port=ftp_port, passive=ftp_passive, user=remote_user, passwd=ftp_password, ssl=ftp_ssl, ssl_implicit=ftp_ssl_implicit)
                f.login()
                f.retrlines('LIST', callback=lambda msg: None)
                f.cwd(remote_path)
            except Exception, FTPClientExceptionText:
                do_ftp_mount = False
            try: f.quit()
            except: pass
            # perform actual ftp mount
            if do_ftp_mount:
                log(6,"performing FTP mount for server link %s" % server_name)
                # XXX note the use of the -f switch to curlftpfs below, which forces it not to daemonize and instead run in the foreground. If we don't do this, then for some reason some FTPES mounts (to Win2k8 IIS servers) won't work (the mount appears to work and the underlying FTP session is successfully established but trying to open the mountpoint for reading produces an IOError). Investigate this, nothing that we use our own slighly customized curlftpfs - check our RPM build dir for the source and patches.
                mountCmd = "curlftpfs -f -o transform_symlinks,connect_timeout=5,allow_other,default_permissions,uid=0,umask=002,nonempty,cache=no,ftp_timeout=10"
                if ftp_ssl:
                    mountCmd += ",ssl,no_verify_peer,no_verify_hostname"
                if not ftp_passive:
                    mountCmd += ",ftp_port=-,disable_epsv"
                ftp_credentials = ",user='%s:%s'" % (remote_user, ftp_password) #.replace(":",r"\:"))
                mountCmd += ftp_credentials
                mountCmd += ",gid=%s" % str(grp.getgrnam("x_%s" % id)[2])
                if ftp_ssl and ftp_ssl_implicit:
                    mountCmd += " ftps://"
                else:
                    mountCmd += " ftp://"
                mountCmd += "%s:%s" % (address, ftp_port)
                if serverObj.remote_path:
                    mountCmd += "%s%s" % (['/', ''][remote_path.startswith('/')], remote_path)
                mountCmd += " %s%s" % (xsftp.common.constants.SERVERDIR, sid)
                #mountCmd += " > /dev/null 2>&1"
                log(6, "ftp mount command for server link '%s' is: %s" % (server_name, mountCmd.replace(ftp_credentials, ",user='%s:<HIDDEN>'" % remote_user)))
                #result = os.system(mountCmd)
                args = shlex.split(str(mountCmd))
                mnt_process = subprocess.Popen(args)
                log(6, "ftp mount command for server link '%s' issued, reading return result if available..." % server_name)
                time.sleep(1) #XXX the above subprocess will not return (due to the fact we use the -f switch with curlftpfs), unless there is an error in whcih case it should hopefully return within this 1 second. If it takes longer than this to error out, the below check will not pickup the return code and therefore assume it went ok. In the case it is not ok, the stat health checking system will pickup the failed mount and attempt to remediate. Note that we do not call os.wait() to get this process' return code in the event that curlftpfs inadvertantly dies or if we kill it via unmount, but we've registerd a SIGCHLD handler to call os.waitpid() in a non-blocking way on any children who are waiting to have their return code read (ie. our zombie children) if and when this happens. Mmmmmmm braaaaaains.
                result = mnt_process.poll()
                if result:
                    # log failed ftp mount attempt
                    log(2, "Server Link (type: ftp) establishment attempt for server '%s' failed. Return code was %s" % (server_name, result))
                else:
                    # log successful ftp mount attempt
                    log(4, "Success: ftp mount to %s:%s established." % (address, ftp_port))
                    log(1, "Server Link '%s' successfully established." % server_name)
            else:
                error_string = ""
                FTPClientExceptionText = str(FTPClientExceptionText)
                if FTPClientExceptionText:
                    error_string = " (FTP error message: %s)" % FTPClientExceptionText
                log(2, 'Server Link (type: ftp) "%s" failed pre-checks%s, skipping establishment.' % (server_name, error_string))


        ### END OF SERVER LINK MONUTING ###
        ###################################

        self.SLAMMountsInProgressLock.acquire()
        log(6, "Acquired self.SLAMMountsInProgressLock after fixing Server link %s" % sid)
        condition = self.SLAMMountsInProgress.pop(sid)
        log(5, "Notifying any other threads that the job is done for Server Link %s" % sid)
        condition.notifyAll()
        log(6, "Releasing the lock for self.SLAMMountsInProgressLock")
        self.SLAMMountsInProgressLock.release()
        return

    def initAllMountPoints(self): 
        '''
        Initializes all xSFTP mount points on the system as per the data in the DB.
        '''
        self.slam_manager.initSLAMMountPoints()
        self.bmp_manager.initBindMountPoints()
        return

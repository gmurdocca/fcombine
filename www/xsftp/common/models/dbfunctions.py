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

from django.contrib.auth.models import User

#from xsftp.common.models.Job import Job
#from xsftp.common.models.Script import Script
#from xsftp.common.models.Server import Server
#from xsftp.common.models.Configuration import Configuration

def dbCommit():
    '''
    Synchronises Django DB with Linux User DB
    '''
    # FIXME FSCKING REPLACE THIS PILE OF SHIT FUNCTION
    return
    # When adding a linux user, add 'xsftp user' in the comment/gekos field
    # ************* SYNCHRONISE USER ACCOUNTS
    # get all usernames from Django
    djangoUsers = [x.username for x in User.objects.all()]
    linuxUsers = [user[0] for user in  pwd.getpwall() if user[4] == 'xsftp user']
    # for each django user
    for djangoUser in djangoUsers:
        # if the user is not in linux
        if djangoUser not in linuxUsers:
            # add user to linux (and restore their ~/.ssh directory if a backup exists)
            addUserCmd = 'sudo %swww/xsftp/webui/privexec.py --createuser=%s %s' % (xsftp.common.constants.APPDIR, djangoUser, REDIRECTSTR)
            os.system(addUserCmd)
            #log("created new user '%s'" % djangoUser)
    # for each linux user
    for linuxUser in linuxUsers:
        # if the user is not in the DB
        if linuxUser not in djangoUsers:
            # Delete the user from linux (lazily unmounting everything in users ~/xsftp/ dir)
            delUserCmd = 'sudo %swww/xsftp/webui/privexec.py --deleteuser=%s %s' % (xsftp.common.constants.APPDIR, linuxUser, REDIRECTSTR)
            os.system(delUserCmd)
            #log("deleted user '%s'" % linuxUser)
    # ************* SYNCHRONISE SERVERS IN DB WITH GROUP ACCOUNT EXISTENCE IN LINUX
    # get a list of servers (id's) from the DB
    djangoServerObjs = Server.objects.all()
    djangoServers = [str(x.id) for x in djangoServerObjs]
    # get a list of xsftp server groups from linux
    linuxGroups = [group[0][2:] for group in grp.getgrall() if group[0].startswith("x_")]
    # for each DB server
    for djangoServer in djangoServers:
        # if the DB server doesn't have a corresponding linux group
        if djangoServer not in linuxGroups:
            # create the group in linux
            addGroupCmd = 'sudo %swww/xsftp/webui/privexec.py --groupadd=%s %s' % (xsftp.common.constants.APPDIR, djangoServer, REDIRECTSTR)
            os.system(addGroupCmd)
            #log("added perms framework group for server with link id '%s'" % djangoServer)
    # for each linux server group
    for linuxGroup in linuxGroups:
        # if the server group doesn't have a corresponding server in DB
        if linuxGroup not in djangoServers:
            # delete the group from linux
            delGroupCmd = 'sudo %swww/xsftp/webui/privexec.py --groupdel=%s %s' % (xsftp.common.constants.APPDIR, linuxGroup, REDIRECTSTR)
            os.system(delGroupCmd)
            #log("deleted perms framework for server link with id '%s'" % linuxGroup)
    # ************* SYNCHRONISE GROUP MEMBERSHIP
    # Generate a dict with {sid:[username, ...]} entries reflecting a server's write users according to the linux group file.
    allLinuxGroups = dict([(g[0][2:],g[3]) for g in [group for group in grp.getgrall() if group[0].startswith("x_")]])
    print str(allLinuxGroups)
    # for each serverObj from DB
    for djangoServerObj in djangoServerObjs:
        # get a list of effective write userObjs according to DB
        djangoWriteUserObjs = djangoServerObj.getEffectiveWriteUsers()

        # get a list of effective write userObjs according to linux
        linuxWriteUsernames = allLinuxGroups[str(djangoServerObj.id)]
        for djangoWriteUserObj in djangoWriteUserObjs:
            # if the user is not in the list obtained from Linux
            if djangoWriteUserObj.username not in linuxWriteUsernames:
                # re-sync the user's group membership in linux
                addUserToGroupCmd = 'sudo %swww/xsftp/webui/privexec.py --sync=%s %s' % (xsftp.common.constants.APPDIR, djangoWriteUserObj.username, REDIRECTSTR)
                os.system(addUserToGroupCmd)
                log("added write permission for user '%s' on server link '%s'" % (djangoWriteUserObj.username, djangoServerObj.server_name))
        # for each user in the list from Linux
        for linuxWriteUsername in linuxWriteUsernames:
            # if the user (from linux) is not in the list from the DB
            if linuxWriteUsername not in [writeUser.username for writeUser in djangoWriteUserObjs]:
                # re-sync the user's group membership in linux
                delUserFromGroupCmd = 'sudo %swww/xsftp/webui/privexec.py --sync=%s %s' % (xsftp.common.constants.APPDIR, linuxWriteUsername, REDIRECTSTR)
                os.system(delUserFromGroupCmd)
                log("removed write permission for user '%s' on server link '%s'" % (linuxWriteUsername, djangoServerObj.server_name))
    # ************* SYNCHRONISE SCRIPTS IN LINUX WITH THOSE WHICH EXIST IN THE DB
    allScriptFiles = glob.glob(xsftp.webui.constants.SCRIPT_PATH + "*")
    dbScriptFiles = [script.file.path for script in Script.objects.all()]
    for filename in allScriptFiles:
        if filename not in dbScriptFiles:
            delScriptCmd = 'sudo %swww/xsftp/webui/privexec.py --erasescript=%s %s' % (xsftp.common.constants.APPDIR, os.path.basename(filename), REDIRECTSTR)
            os.system(delScriptCmd)
            #log("removed script with filename '%s'" % filename)
    #************* Apply changes to linux land from Configuration model if necessary ********
    # REMOTE SYSLOG SERVER CONFIG
    # get linux remote log server
    f = file(xsftp.webui.constants.SYSLOG_CONF, "r")
    syslogConfLines = f.readlines()
    f.close()
    xsftpLines = [line for line in syslogConfLines if line.startswith(xsftp.webui.constants.SYSLOG_FACILITY + ".")]
    networkLogTarget = "".join([line.split()[-1] for line in xsftpLines if line.split()[-1].startswith("@")])[1:] or ""
    # if there is no target for the Fcombine's faciliy, or if remote log server is different to the one specified in configuration
    if not xsftpLines or networkLogTarget != Configuration.objects.all()[0].remote_syslog_server:
        # modify SYSLOG_CONF file so they match.
        modLogTargetCmd = 'sudo %swww/xsftp/webui/privexec.py --remotelog %s' % (xsftp.common.constants.APPDIR, REDIRECTSTR)
        os.system(modLogTargetCmd)
        log("modified remote syslog server to: %s" % (Configuration.objects.all()[0].remote_syslog_server or "<none>"))
    # IP ADDRESS, SUBNET MASK, DEFAULT GW, DNS1, DNS2
    # get linux settings
    f = file(xsftp.webui.constants.IP_CONFIG, "r")
    ipLines = f.readlines()
    f.close()
    ipaddr = netmask = gateway = dns1 = dns2 = None
    for line in ipLines:
        if line.startswith("IPADDR"):
            ipaddr = line.split("=")[1].strip() or None
        if line.startswith("NETMASK"):
            netmask = line.split("=")[1].strip() or None
        if line.startswith("GATEWAY"):
            gateway = line.split("=")[1].strip() or None
        if line.startswith("DNS1"):
            dns1 = line.split("=")[1].strip() or None
        if line.startswith("DNS2"):
            dns2 = line.split("=")[1].strip() or None
    # compare with configuration, and update linux if necessary
    ipaddrConfig = Configuration.objects.all()[0].ip_address or None
    netmaskConfig = Configuration.objects.all()[0].subnet_mask or None
    gatewayConfig = Configuration.objects.all()[0].default_gateway or None
    dns1Config = Configuration.objects.all()[0].primary_dns or None
    dns2Config = Configuration.objects.all()[0].secondary_dns or None
    if not ipaddr == ipaddrConfig or not netmask == netmaskConfig or not gateway == gatewayConfig or not dns1 == dns1Config or not dns2 == dns2Config:
        modNetworkCmd = 'sudo %swww/xsftp/webui/privexec.py --netupdate %s' % (xsftp.common.constants.APPDIR, REDIRECTSTR)
        os.system(modNetworkCmd)
        log("modified network parameters: IP_ADDRESS=%s SUBNET_MASK=%s GW=%s DNS1=%s DNS2=%s" % (ipaddrConfig, netmaskConfig, gatewayConfig, dns1Config, dns2Config))
    # update the cron file for jobs using privexec
    regenCronCmd = 'sudo %swww/xsftp/webui/privexec.py --regencron %s' % (xsftp.common.constants.APPDIR, REDIRECTSTR)
    os.system(regenCronCmd)
    # update pam_radius configuration file
    f = file(xsftp.webui.constants.PAM_RADIUS_CONFIG, "r")
    radiusLines = f.readlines()
    f.close()
    radiusServer = radiusSecret = radiusAuthport = radiusTimeout = None
    lineCount = 0
    for line in radiusLines:
        if not line.strip():
            continue
        if line.strip().startswith("#"):
            continue
        lineCount += 1
        radiusServer, radiusSecret, radiusTimeout = line.strip().split()
        if ":" in radiusServer:
            radiusServer, radiusAuthport = radiusServer.split(":")
    radiusServerConfig = Configuration.objects.all()[0].radius_server or None
    radiusSecretConfig = Configuration.objects.all()[0].radius_secret or None
    radiusAuthportConfig = Configuration.objects.all()[0].radius_authport or None
    if (not radiusServerConfig and (lineCount or radiusServer or radiusSecret or radiusAuthport or radiusTimeout)) or (radiusServerConfig and (lineCount != 1 or radiusServerConfig != radiusServer or radiusSecretConfig != radiusSecret or str(radiusAuthportConfig) != radiusAuthport or radiusTimeout != "3")):
        modRadiusConfigCmd = 'sudo %swww/xsftp/webui/privexec.py --radupdate %s' % (xsftp.common.constants.APPDIR, REDIRECTSTR)
        os.system(modRadiusConfigCmd)
        log("modified RADIUS config parameters: Server=%s, AuthPort=%s" % (radiusServerConfig, radiusAuthportConfig))
    # update pam's system-auth file
    modPAMConfigCmd = 'sudo %swww/xsftp/webui/privexec.py --pamupdate %s' % (xsftp.common.constants.APPDIR, REDIRECTSTR)
    os.system(modPAMConfigCmd)
    # sync the radius_users file
    radius_users = [u.username for u in User.objects.filter(userprofile__internal_auth=False)]
    if radius_users:
        if not os.path.isfile(xsftp.webui.constants.PAM_RADIUS_USERS):
            open(xsftp.webui.constants.PAM_RADIUS_USERS, 'w')
        radius_users_in_file = [u.strip() for u in open(xsftp.webui.constants.PAM_RADIUS_USERS, 'r').readlines()]
        radius_users_to_append = []
        for u in radius_users:
            if u not in radius_users_in_file:
                radius_users_to_append.append(u)
        if radius_users_to_append:
            open(xsftp.webui.constants.PAM_RADIUS_USERS, 'a').write("%s\n" % "\n".join(radius_users_to_append))


            

def checkJobSanity():
    '''
    Sets the errorFlags value (a bitmask) on every job object according the table below.
    Also returns a tuple containing two n-tuples:
            - the first n-tuple contains jobObjects who's sanity has changed from insane to sane (alphabetically ordered on job_name)
            - the second n-tuple contains jobObjects those sanity has changed from sane to insane (alphabetically ordered on job_name)

    errorFlags value is constructed thusly:

        0        job is sane
        +1        sourceServer does not exist
        +2        insufficient permissions on sourceServer
        +4        destServer does not exist
        +8        insufficient permissions on destServer
        +16        preScript does not exist
        +32        insufficient permissions on preScript
        +64        postScript does not exist
        +128    Insufficient persmissions on postScript
        +256    sourceServer is disabled
        +512    destServer is disabled
        +1024    owner is disabled
        +2048    owner does not exist
        +4096    job has expired
        
        or:
        
        -1         job just got created, and was assigned this value in the form's save() method. It will be calculated and assigned to its proper value above now.


    NB: a value of errorFlags = -10 is set by the Server.save() method if the server has no BMP's associated with it.
    '''

    # FIXME to remove circular dependencies
    from xsftp.common.models.Job import Job

    allJobs = Job.objects.all()
    saneJobs = ()
    insaneJobs = ()
    for job in allJobs:
        currentSanity = job.errorFlags
        sanity = 0
        # Check if job has an expiry date set, and if so, that it has expired
        if job.expiry and job.expiry < datetime.datetime.today():
            sanity += 4096
        # Check if the owner exists
        if not job.owner:
            sanity += 2048
        # Check if the source server exists
        if not job.source_server:
            sanity += 1
        # Check if the dest server exists
        if not job.dest_server:
            sanity += 4
        # Check if the pre_script exists
        if job.use_pre_script and not job.pre_script:
            sanity += 16
        # Check if the post_script exists
        if job.use_post_script and not job.post_script:
            sanity += 64
        # If the owner exists
        if job.owner:
            # If thesource server exists
            if job.source_server:
                # Check if the owner can read from the source server
                if job.owner not in job.source_server.getAllReadUsers():
                    sanity += 2
            # If the dest server exists
            if job.dest_server:
                # Check if the owner can write to the dest server
                if job.owner not in job.dest_server.getEffectiveWriteUsers():
                    sanity += 8
            # If the pre_script exists
            if job.pre_script:
                # Check if the owner can execute the pre_script
                if job.owner not in job.pre_script.getEffectiveUsers():
                    sanity += 32
            # If the post_script exists
            if job.post_script:
                # Check if the owner can execute the post_script
                if job.owner not in job.post_script.getEffectiveUsers():
                    sanity += 128
            # Check if owner is enabled
            if not job.owner.is_active:
                sanity += 1024
        if job.source_server:
            # Check if source server is enabled
            if not job.source_server.enabled:
                sanity += 256
        if job.dest_server:
            # Check if dest server is enabled
            if not job.dest_server.enabled:
                sanity += 512
        # Compare sanity to current (previous?) sanity
        if sanity != currentSanity:
            if currentSanity != 0 and sanity == 0:
                # job was insane and now is sane
                saneJobs += job,
                job.timeLastSeenSane = datetime.datetime.now()
            elif currentSanity == 0 and sanity != 0:
                # job was sane and is now insane
                insaneJobs += job,
                job.timeLastSeenSane = datetime.datetime.now()
            job.errorFlags = sanity
            job.save(checkSanity = False)
    changedJobs = (saneJobs, insaneJobs)
    # log changed jobs.
    if insaneJobs:
        log("detected %s Job(s) previously SANE but now INSANE: %s" % (len(insaneJobs), [str(job.job_name) for job in insaneJobs]))
    if saneJobs:
        log("detected %s Job(s) previously INSANE but now SANE: %s" % (len(saneJobs), [str(job.job_name) for job in saneJobs]))
    return changedJobs



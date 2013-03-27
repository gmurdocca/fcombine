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

#### IMPORTS ####
import getopt, sys, os, glob, signal, subprocess
import pickle
sys.path.append("/opt/fcombine/www")
os.environ["DJANGO_SETTINGS_MODULE"]="xsftp.settings"
import xsftp.webui.models
import xsftp.webui.constants
from xsftp.webui.forms import parse_pubkey
import grp
import time
import pwd
import stat
import fsutil
import tempfile
import xsftp.common.constants
from xsftp.common.Config import Config

config = Config()
config.read_config(xsftp.common.constants.DEFAULT_CONF_FILE)


#### UTILITY FUNCTIONS ####


def usage():
    print """===================================================================
 PrivExec v1.0 The Fcombine Fcombine Priveleged Utility Runner
===================================================================
Usage:
%s [OPTION]
Options are:
 --help | -h
    This help page
 --mklogdir | -l
    Create log directory specified in xSFTP settings
 --setlogperm | -q
    Sets daemon syslog file ownership to root:apache and permission 640
 --createuser=<username> | -c <username>
    Creates a new xsftp user and restores (and removes) that user's SSH RSA key backup if one exists
 --deleteuser=<username> | -d <username>
    Deletes an xsftp user, first lazily unmounting all bind mount points in the user's ~/xsftp/ directory
 --groupadd <server_id> |  -g <server_id>
    Creates an xsftp server group for the specified <server_id>
 --groupdel <server_id> |  -r <server_id>
    Deletes the xsftp server group for the specified <server_id>
 --password=<username>,<password> |  -p <username>,<password>
    Sets/resets an xsftp user's linux-land password
 --sync=<username> | -s <username>
    Re-synchronises an xsftp user's linux group membership based on their write permissions on server links.
 --backup=<old_username>,<new_username> | -b <old_username>,<new_username>
    Create a backup of a user's SSH RSA keys (intended for use during a username change)
 --erasescript=<script_file_name> | -e <script_file_name>
    Deletes <script_file_name> from the xsftp scripts directory
 --reset=<server_id> | -t <server-id> 
    Resets the Server Link identified by <server_id>
 --remotelog | -m
    Modifies syslog.conf for remote loging of xSFTP logs to the syslog server specified in the xSFTP configuration
 --netupdate | -i
    Updates linux network configuration to reflect the settings in the xSFTP configuration (network restart required)
 --restart | -a
    Reboots the system
 --ethinfo | -o
    Returns output from /sbin/ethtool as a semicolon-separated list of 'name':'value' pairs.
 --regencron | -j
    Regenerates /etc/cron.d/xsftp to reflect the xsftp jobs in the database.
 --killjob=<job_id> | -z <job_id>
    Sends a kill signal to the job runner responsible for running the job specified in the argument.
 --runjob=<job_id> | -f <job_id>
    Sends a run signal to the job runner responsible for running the job specified in the argument.
 --start | -y
    Starts the xSFTP Daemon
 --stop | -w
    Stops the xSFTP Daemon
 --settime=<newtime> | -u <newtime>
    Set the system time. <newtime> must be in the format: YYYYMMDDhhmmss
 --radupdate
    Modifies /etc/raddb/server to reflect the RADIUS settings configured in the xSFTP configuration
 --erasepasswd=<username>
    Erases the password entry for <username> in /etc/shadow
 --toggledemomode
    Toggles Demo Mode
 --pamupdate
    Updates Linux PAM configuration to support RADIUS as required by the xSFTP system
 --read_authorized_keys=<username>
    Returns a piclked list of paramiko PKey objects, each represeinging a public key in the specified user's authorized_keys file
 --import_public_keys=<username> <key_file>
    Appends <key_file> onto <username>'s authorized_keys file (WARNING: does no verification of specified <key_file>)
 --del_public_key=<username> <key_fingerprint>
    Deletes public key specified by <key_fingerprint> from <username>'s authorized_keys file
 --set_key_comment=<username> <key_fingerprint> <comment>
    Sets <comment> for the specified user's public key in their authorized_keys file
 --readdir=<dir>
    Returns a python pickled dict() of files and directories in <dir>
 --explorer_copy <source> <dest>
    Copys <source> to <dest>
 --explorer_move <source> <dest>
    Moves <source> to <dest>
 --explorer_delete <path>
    Deletes <path>
 --explorer_temporary_rename <path>
    Renames path to a unique temporary name and returns that name (pickled)
 --explorer_mkdir <path>
    Creates directory specified by <path>
 --explorer_upload <source> <dest>
    Uploads <source> to <dest>
        """ % sys.argv[0]


def is_user(username, check_passwd_file=True):
    '''
    Takes in a string representing an xSFTP user's username. Returns True if the user exists.
    '''
    if xsftp.webui.models.User.objects.filter(username=username):
        if check_passwd_file:
            try:
                pwd.getpwnam(username)
                return True
            except KeyError, e:
                return False
        else:
            return True
    return False


def exitSuccess():
    print "Success!"
    sys.exit(0)


def exitBadArg():
    print "Error: Invalid Argument."
    print "For options, use: %s --help" % sys.argv[0]
    sys.exit(255)


def exitError(message):
    print message
    sys.exit(255)


def parse_authorized_keys_file(username):
    ak_file = "/home/%s/.ssh/authorized_keys" % username
    if not os.path.isfile(ak_file):
        return []
    f = open(ak_file)
    authorized_keys_lines = f.readlines()
    f.close()
    pubkeys = []
    count = 0
    for line in authorized_keys_lines:
        try:
            key = parse_pubkey(line)
        except Exception, e:
            raise Exception(e, count + 1)
        if not key:
            count += 1
            continue
        key.id = count
        count += 1
        pubkeys.append(key)
    return pubkeys


privileges_already_dropped = False
def drop_privileges(username):
    global privileges_already_dropped
    if not privileges_already_dropped:
        uid = pwd.getpwnam(username)[2]
        os.setgroups([g[2] for g in grp.getgrall() if username in g[3]])
        os.setuid(uid)
        privileges_already_dropped = username


def extract_username_from_path(path):
    return path.split("/")[2]


def check_path(dest, username):
    '''
    Checks that 'dest' is within 'username's fcombine home directory
    (i.e. that a destination directory is within a users xsftp directory).
    Eg, the destination is within the fcombine directory of the user's home dir.
    In other words, ensure teh fcombine user's home directory (with xsftp appended) is contains the dest.
    Raises an exception if not the case'''
    if not os.path.abspath(dest).startswith(os.path.abspath("/home/%s/xsftp/" % username)):
        len_prefix = len("/home/%s/xsftp/" % username)
        dest = dest[len_prefix:] # XXX Is it safe to assume that all 'dest's that get passed to check_path start with that prefix?
        raise Exception("Illegal path for user %s: %s" % (username, dest))


def do_copy(source, dest, delete_source=False):
    '''do_copy will NEVER clobber the dest. It will raise an exception if the dest already exists'''
    source = source.strip()
    dest = dest.strip()
    username = extract_username_from_path(source)
    check_path(dest, username)
    drop_privileges(username)

    # Check that source doesn't have a trailing slash, if it does
    if source.endswith("/"): # XXX Maybe we shouldn't be so harsh here
        raise Exception("Invalid source path for copy (trailing slash not allowed): %s" % source)
    # Specify the name of the file or dir that will be created by the copy process
    dest = os.path.join(dest, os.path.basename(source))
    # Check if the dest already exists
    if os.path.exists(dest):
        raise Exception((400, "Cannot copy/move file '%s' - destination '%s' already exists" % (source, dest)))
    if os.path.isfile(source):
        try:
            # First, we need to check if the destination directory exists ...
            # So, get the endpoint directory
            dest_dir = os.path.dirname(dest)
            # If the path doesn't yet exist ...
            if not os.path.exists(dest_dir):
                # create it
                try:
        
                    os.makedirs(dest_dir)
                except Exception, e:
                    raise Exception("Couldn't make dirs ...")
            else:
                # the path exists already
                # if it's not a directory ...
                if not os.path.isdir(dest_dir):
                    # bail out - the target 'directory' is in fact a file - not much we can do about that
                    raise Exception((500, "Destination 'directory' is a file"))
            fsutil.copy(source, dest, copy_mode=True, copy_stat=True, ignore_errors=True) # fails silently on copying mode and stat data
        except IOError, e:
            # Got an IOError
            raise Exception((501, "An I/O error occurred while copying this file: %s" % (e)))
    # else if the source is a directory
    elif os.path.isdir(source):
        fsutil.copytree(source, dest, symlinks=False, copy_mode=True, copy_stat=True, ignore_errors=True)
    # else if the source is neither a file or a directory
    else:
        raise Exception((502, "Error: Abnormal source '%s' is neither a file nor a directory" % source))
    # if the job is set to delete source, so do it (this is a funny english)
    if delete_source:
        do_delete(source)

def do_delete(path):
    username = extract_username_from_path(path)
    check_path(path, username)
    drop_privileges(username)
    if os.path.isfile(path):
        os.remove(path)
    else:
        fsutil.rmtree(path)
    
debug_file = file("/tmp/upload_handler.debug", 'a') #FIXME DELETE ME
def my_debug(msg):
    debug_file.write("PRIVEXEC: %s\n" % msg)
    debug_file.flush()

#### MAIN BLOCK ####

try:
    opts, args = getopt.getopt(sys.argv[1:], "hlc:b:d:g:r:s:e:p:t:k:x:n:z:miaqojfywu:", ["settime=", "start", "stop", "runjob=", "killjob=", "ethinfo", "setlogperm", "restart", "netupdate", "remotelog", "reset=", "password=", "erasescript=", "sync=", "groupdel=", "groupadd=", "deleteuser=", "backup=", "createuser=", "help", "mklogdir", "regencron", "radupdate", "erasepasswd=", "toggledemomode", "pamupdate", "readdir=", "explorer_copy", "explorer_move", "explorer_mkdir", "explorer_delete", "explorer_upload", "explorer_getfile", "explorer_temporary_rename","read_authorized_keys=", "import_public_keys=", "del_public_key=", "set_key_comment=", ])
#    print "opts are:", opts
#    print "args are:", args
except getopt.GetoptError, e:
    print "Error: %s" % e
    print "For options, use: %s --help" % sys.argv[0]
    sys.exit(255)

if not opts:
    print "Usage: %s [OPTION]..." % sys.argv[0]
    print "For options, use: %s --help" % sys.argv[0]
    sys.exit(0)

# iterate through each option (o, eg: -u) and argument (a, eg: <username>)
for o, a in opts:

    if o in ("-h", "--help"):
        usage()
        sys.exit(0)

    elif o in ("-l", "--mklogdir"):
        print "Creating xSFTP log directory at %s" % config.LOGDIR
        returnCode = os.system("/bin/mkdir -p %s" % config.LOGDIR)
        if returnCode:
            exitError("Error: /bin/mkdir returned code %s" % returnCode)
        returnCode = os.system("/bin/chown apache:apache %s" % config.LOGDIR)
        if returnCode:
            exitError("Error: /bin/chown returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-c", "--createuser"):
        if is_user(a):
            exitError("xSFTP user '%s' already exists" % a)
        print "Creating xSFTP user: %s" % a
        createUserCmd = '/usr/sbin/useradd -c "xsftp user" -m -k /etc/xsftp/skel -s /usr/local/bin/fxsh %s' % a
        returnCode = os.system(createUserCmd)
        if returnCode:
            exitError("Error: /usr/sbin/useradd returned code %s" % returnCode)
        # if there exists a dir called TRANSIENT_KEY_PATH/<username>_backup/, then <username> has just been renamed from some other username, and therein lies their ssh pub keys.
        backedupKeysPath = xsftp.webui.constants.TRANSIENT_KEY_PATH + a + "_backup"
        if os.path.isdir(backedupKeysPath):
            restoreKeysCmds = [# set correct ownership on the backed up rsa keys
                        "/bin/mv -f %(backedupKeysPath)s/* /home/%(user)s/.ssh/" % {'user':a, 'backedupKeysPath':backedupKeysPath},
                        "/bin/chown %(user)s:%(user)s /home/%(user)s/.ssh/*" % {'user':a},
                        "/bin/rm -rf %s" % backedupKeysPath,
                        ]
            for cmd in restoreKeysCmds:
                returnCode = os.system(cmd)
                if returnCode:
                    exitError("Error: '%s' returned code %s" % (cmd, returnCode))
        exitSuccess()

    elif o in ("--pamupdate"):
        # update /etc/pam.d/system-auth if required
        pamconf_file = "/etc/pam.d/system-auth"
        f = file(pamconf_file,"r")
        pamconf_lines = f.readlines()
        f.close()
        for line in pamconf_lines:
            # very basic check if conf is already updated
            if "radius" in line or "listfile" in line:
                print "PAM config is already updated."
                sys.exit()
        # update the file.
        new_conf_lines = []
        for line in pamconf_lines:
            new_conf_lines.append(line)
            if ">=" in line:
                new_conf_lines.append("auth        requisite     pam_listfile.so onerr=fail item=user sense=allow file=/opt/fcombine/var/radius_users\n")
                new_conf_lines.append("auth        sufficient    pam_radius_auth.so\n")
        f = file(pamconf_file,"w")
        f.write("".join(new_conf_lines))
        f.close()
        exitSuccess()

    elif o in ("--toggledemomode"):
        # toggle demo mode
        configuration = xsftp.webui.models.Configuration.objects.all()[0]
        demo_mode = configuration.demo_mode
        if demo_mode:
            configuration.demo_mode = False
            configuration.save()
            print "Demo Mode is OFF"
        else:
            configuration.demo_mode = True
            configuration.save()
            print "Demo Mode is ON"
        sys.exit()

    elif o in ("-b", "--backup"):
        args = a.split(",") #this implies a comma is an invalid character in usernames, which it is (our forms validation makes it so)
        if not len(args) == 2:
            exitBadArg()
        oldUsername, newUsername = args
        if not is_user(oldUsername):
            exitError("User '%s' is not a valid xSFTP user" % oldUsername)
        print "Preparing backup of ~/.ssh/ for user '%s' in preparation for their rename to '%s'" % (oldUsername, newUsername)
        backupCmd = "/bin/mv /home/%(oldUsername)s/.ssh %(path)s%(newUsername)s_backup" % {'oldUsername':oldUsername, 'newUsername':newUsername, 'path':xsftp.webui.constants.TRANSIENT_KEY_PATH}
        returnCode = os.system(backupCmd)
        if returnCode:
            exitError("Error: /bin/mv returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-d", "--deleteuser"):
        print "Deleting xSFTP user '%s'" % a
        # first unmount everything in the user's ~/xsftp/ directory
        umountPath = "/home/%s/xsftp/" % a
        if not os.path.isdir(umountPath):
            exitError("Could not find path '%s'" % umountPath)
        mounted = True
        while mounted:
            dirList = glob.glob("%s*" % umountPath)
            for dir in dirList:
                os.system("/bin/umount -l %s" % dir)
            mounted = False
            # now check that everything is actually unmounted.
            f = file("/etc/mtab")
            mounts = f.readlines()
            f.close()
            for mountLine in mounts:
                mountDir = mountLine.split()[1]
                if mountDir.startswith('/home/%s/xsftp/' % a):
                    mounted = True
        # now delete the user
        delUserCmd = '/usr/sbin/userdel -fr %s' % a
        returnCode = os.system(delUserCmd)
        if returnCode:
            exitError("Error: /usr/sbin/userdel returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-g", "--groupadd"):
        try:
            sid = int(a)
        except:
            exitBadArg()
        try:
            server = xsftp.webui.models.Server.objects.get(id=sid)
        except:
            exitError("Error: No server exists with sid = %s" % sid)
        print "Adding linux write group for xSFTP server link '%s' whos id is %s" % (server.server_name, sid)
        addGroupCmd = '/usr/sbin/groupadd x_%s' % sid
        returnCode = os.system(addGroupCmd)
        if returnCode:
            exitError("Error: /usr/sbin/groupadd returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-r", "--groupdel"):
        try:
            sid = int(a)
        except:
            exitBadArg()
        print "Deleting linux write group for xSFTP server link whos id is/was %s" % (sid)
        addGroupCmd = '/usr/sbin/groupdel x_%s' % sid
        returnCode = os.system(addGroupCmd)
        if returnCode:
            exitError("Error: /usr/sbin/groupdel returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-s", "--sync"):
        try:
            djangoWriteUserObj = xsftp.webui.models.User.objects.get(username=a)
        except:
            exitBadArg()
        print "Synching server link write group membership for user %s" % djangoWriteUserObj.username
        syncUsersGroupMembershipCmd = "/usr/sbin/usermod -G %s %s" % (",".join(["x_%s" % server.id for server in djangoWriteUserObj.userprofile.getEffectiveWriteServers()]) or "''", djangoWriteUserObj.username)
        returnCode = os.system(syncUsersGroupMembershipCmd)
        if returnCode:
            exitError("Error: /usr/sbin/usermod returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-e", "--erasescript"):
        print "Erasing xsftp script '%s'" % a
        scriptFile = xsftp.webui.constants.SCRIPT_PATH + a
        if not scriptFile in glob.glob(xsftp.webui.constants.SCRIPT_PATH + "*"):
            exitError("No such script '%s'" % a)
        delScriptCmd = '/bin/rm -f "%s"' % scriptFile
        returnCode = os.system(delScriptCmd)
        if returnCode:
            exitError("Error: /bin/rm returned code %s" % returnCode)
        exitSuccess()

    elif o in ("--erasepasswd"):
        username = a
        if not xsftp.webui.models.User.objects.filter(username=username):
            exitError("No such xSFTP user '%s'" % username)
        print "Erasing Linux password for user '%s'" % username
        pwdRmCmd = "/usr/bin/passwd --delete %s" % username
        returnCode = os.system(pwdRmCmd)
        if returnCode:
            exitError("Error: /usr/bin/passwd returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-p", "--password"):
        args = a.split(",") #this implies a comma is an invalid character in usernames, which it is (our forms validation makes it so)
        if not len(args) == 2:
            exitBadArg()
        username, password = args
        # ensure the user is an xsftp user
        if not xsftp.webui.models.User.objects.filter(username=username):
            exitError("No such xSFTP user '%s'" % username)
        print "Setting password for user '%s'" % username
        pwdChCmd = 'echo "' + username + ':' + password + '" | /usr/sbin/chpasswd -m'
        returnCode = os.system(pwdChCmd)
        if returnCode:
            exitError("Error: /usr/sbin/chpasswd returned code %s" % returnCode)
        exitSuccess()

    elif o in ("-t", "--reset"):
        try:
            server = xsftp.webui.models.Server.objects.get(id=a)
        except:
            exitError("Error: There is no server with id=%s" % a)
        print "Resetting server link '%s' with id '%s'" % (server.server_name, a)
        smpAbsPath = xsftp.common.constants.SERVERDIR + str(a)
        returnCode = None
        while not returnCode:
            unmountCmd = "/bin/umount -l %s" % smpAbsPath
            returnCode = os.system(unmountCmd)
        server.status = 5 #set status to MPSTATE_SM_DISCONNECTED_AND_BM_BROKEN XXX the variable name should be referenced here, not just '5'
        server.save()
        exitSuccess()

    elif o in ("-m", "--remotelog"):
        LOG_PREFIX = xsftp.webui.constants.SYSLOG_FACILITY + "."
        f = file(xsftp.webui.constants.SYSLOG_CONF, "r")
        syslogConfLines = f.readlines()
        f.close()
        f = file(xsftp.webui.constants.SYSLOG_CONF, "w")
        syslogConfLines[0] = "##### THIS FILE IS AUTOMATICALLY GENERATED BY THE FCOMBINE - DO NOT EDIT MANUALLY! #####\n"
        for line in syslogConfLines:
            if not line.startswith(LOG_PREFIX):
                f.write(line)
        f.write(LOG_PREFIX + "*;ftp.*\t%s\n" % xsftp.webui.constants.SYSLOG_LOG_FILE)
        if xsftp.webui.models.Configuration.objects.all()[0].remote_syslog_server:
            f.write(LOG_PREFIX + "*;ftp.*\t@%s\n" % xsftp.webui.models.Configuration.objects.all()[0].remote_syslog_server)
        f.flush()
        f.close()
        os.system("/sbin/service rsyslog reload")
        exitSuccess()

    elif o in ("-i", "--netupdate"):
        ipaddrConfig = xsftp.webui.models.Configuration.objects.all()[0].ip_address
        netmaskConfig = xsftp.webui.models.Configuration.objects.all()[0].subnet_mask
        gatewayConfig = xsftp.webui.models.Configuration.objects.all()[0].default_gateway
        dns1Config = xsftp.webui.models.Configuration.objects.all()[0].primary_dns or ""
        dns2Config = xsftp.webui.models.Configuration.objects.all()[0].secondary_dns or ""
        f = file(xsftp.webui.constants.IP_CONFIG, "w")
        f.write("##### THIS FILE IS AUTOMATICALLY GENERATED BY THE FCOMBINE - DO NOT EDIT MANUALLY! #####\n")
        f.write("DEVICE=eth0\nONBOOT=yes\nBOOTPROTO=none\nTYPE=Ethernet\n")
        f.write("IPADDR=%s\n" % ipaddrConfig)
        f.write("NETMASK=%s\n" % netmaskConfig)
        f.write("GATEWAY=%s\n" % gatewayConfig)
        f.write("DNS1=%s\n" % dns1Config)
        f.write("DNS2=%s\n" % dns2Config)
        f.flush()
        f.close()
        exitSuccess()

    elif o in ("--radupdate"):
        radiusServerConfig = xsftp.webui.models.Configuration.objects.all()[0].radius_server
        radiusSecretConfig = xsftp.webui.models.Configuration.objects.all()[0].radius_secret
        radiusAuthportConfig = xsftp.webui.models.Configuration.objects.all()[0].radius_authport
        radiusTimeout = 3
        f = file(xsftp.webui.constants.PAM_RADIUS_CONFIG, "w")
        f.write("##### THIS FILE IS AUTOMATICALLY GENERATED BY THE FCOMBINE - DO NOT EDIT MANUALLY! #####\n")
        if radiusServerConfig:
            f.write("%s:%s %s %s\n" % (radiusServerConfig, radiusAuthportConfig, radiusSecretConfig, radiusTimeout))
        f.flush()
        f.close()
        exitSuccess()


    elif o in ("-q", "--setlogperm"):
        os.system("chown root:apache %s*" % xsftp.webui.constants.SYSLOG_LOG_FILE)
        os.system("chmod 640 %s" % xsftp.webui.constants.SYSLOG_LOG_FILE)
        exitSuccess()

    elif o in ("-o", "--ethinfo"):
        p = subprocess.Popen(["/sbin/ethtool eth0"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
        (pout, pin) = (p.stdout, p.stdin)
        lines = [line.strip() for line in pout.readlines()[1:]]
        cleanLines = []
        for line in lines:
            if line.find(":") == -1: 
                cleanLines[-1] += " %s" % line
                name, value = cleanLines[-1].split(":")
                value = value.strip()
                value = ",".join(value.split())
                cleanLines[-1] = "%s:%s" % (name, value)
            else:
                cleanLines.append(line)
        tuplelines = []
        for line in cleanLines:
            name, value = line.split(":")
            value = value.strip()
            tuplelines.append((name, value))
        outputString = ""
        for item in tuplelines:
            outputString += item[0] + ":" + item[1] + ";" 
        outputString = outputString[:-1]
        print outputString
        sys.exit(0)

    elif o in ("-j", "--regencron"):
        # get all enabled, sane jobs
        jobs = xsftp.webui.models.Job.objects.filter(enabled=True, errorFlags=0)
        cronlines = list()
        for job in jobs:
            # initialise all cron timing fields to "*"
            min = hour = day = month = dow = "*"
            # If job schedule is 'run once'
            if job.schedule_type == 0:
                # If it's already been run, skip it
                if job.run_count > 0:
                    continue
                (min, hour, day, month) = (job.run_at.minute, job.run_at.hour, job.run_at.day, job.run_at.month)
            else:
                # generate the cron-style timing syntax for this job
                if job.schedule_type in [1, 2, 3, 4, 5]:
                    min = [00, 15, 30, 45][int(job.minute)]
                if job.schedule_type == 6:
                    min = job.minute
                if job.schedule_type in [2, 3, 4, 5, 6]:
                    hour = job.hour
                if job.schedule_type in [4, 5, 6]:
                    day = job.day
                if job.schedule_type in [5, 6]:
                    month = job.month
                if job.schedule_type in [3, 6]:
                    dow = job.dow
            crontiming = "%s %s %s %s %s" % (min, hour, day, month, dow)
            cronline = "%s root DJANGO_SETTINGS_MODULE=xsftp.settings %s/bin/jobrunner.py %s" % (crontiming, xsftp.common.constants.APPDIR, job.id)
            # add it to the list of cronlines
            cronlines.append(cronline)
        # write out the cronlines to /etc/cron.d/xsftp
        f = file("/etc/cron.d/xsftp", 'w')
        f.write("\n".join(cronlines))
        f.write("\n")
        f.close()
        exitSuccess()
        
    elif o in ("-z", "--killjob"):
        jid = a
        if not xsftp.webui.models.Job.objects.filter(id=jid):
            exitError("Error: job with id=%s does not exist" % jid)
        print "Killing job with id '%s'" % a
        pid = xsftp.webui.models.Job.objects.get(id=jid).pid
        if pid:
            # kill the process with pid = pid
            os.kill(pid, signal.SIGTERM)
        else:
            exitError("Error: No pid for job %s" % jid)
        exitSuccess()

    elif o in ("-f", "--runjob"):
        jid = a
        if not xsftp.webui.models.Job.objects.filter(id=jid):
            exitError("Error: job with id=%s does not exist" % jid)
        print "Starting job with id '%s'" % a
        p = subprocess.Popen(["%sbin/jobrunner.py" % xsftp.common.constants.APPDIR, "--runnow", jid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        exitSuccess()

    elif o in ("-y", "--start"):
        os.system("/sbin/service xsftpd restart")
        exitSuccess()

    elif o in ("-w", "--stop"):
        os.system("/sbin/service xsftpd stop")
        exitSuccess()

    elif o in ("-u", "--settime"):
        newtime = a
        try:
            int(newtime)
            if not len(str(newtime)) == 14:
                raise Exception
        except:
            exitError("Error: please use the format: YYYYMMDDhhmmss")
        year = newtime[:4]
        month = newtime[4:6]
        day = newtime[6:8]
        hour = newtime[8:10]
        minute = newtime[10:12]
        second = newtime[12:14]
        time_arg = "%s%s%s%s%s.%s" % (month, day, hour, minute, year, second)
        os.system("/bin/date %s" % time_arg)
        exitSuccess()

    elif o in ("--read_authorized_keys",):
        if not is_user(a):
            exitError("User '%s' is not a valid xSFTP user" % a)
        try:
            pubkeys = parse_authorized_keys_file(a)
        except Exception, e:
            pubkeys = e
        print pickle.dumps(pubkeys)

    elif o in ("--import_public_keys", ):
        if not is_user(a):
            exitError("User '%s' is not a valid xSFTP user" % a)
        if len(args) != 1:
            exitBadArg()
        src_file = args[0]
        if not os.path.isfile(src_file):
            exitError("Specified source file '%s' not found." % src_file)
        src_file = open(src_file, "r")
        src_file_data = src_file.read()
        src_file.close()
        drop_privileges(a)
        authorized_keys_dir = "/home/%s/.ssh" % a
        authorized_keys_file = "%s/authorized_keys" % authorized_keys_dir
        # ensure authorized_keys_file exists and has the correct perms
        authorized_keys_file_size = 0
        if not os.path.isfile(authorized_keys_file):
            if not os.path.isdir(authorized_keys_dir):
                os.mkdir(authorized_keys_dir, 0700)
            open(authorized_keys_file, 'w')
        else:
            authorized_keys_file_stat = os.stat(authorized_keys_file)
            if not stat.S_IMODE(authorized_keys_file_stat[stat.ST_MODE]) == 0600:
                os.chmod(authorized_keys_file, 0600)
            if not stat.S_IMODE(authorized_keys_file_stat[stat.ST_MODE]) == 0700:
                os.chmod(authorized_keys_dir, 0700)
            authorized_keys_file_size = authorized_keys_file_stat.st_size
        # append the specified file to the authorized_keys_file
        # XXX consider implementing a check here as we blindly append
        # the specified file. Since it is us doing it, we know we have
        # already checked it in the form validation code, but still...
        if authorized_keys_file_size:
            src_file_data = "\n" + src_file_data
        dst_file = open(authorized_keys_file, "a")
        dst_file.write(src_file_data)
        dst_file.close()

    elif o in ("--del_public_key",):
        if not is_user(a): exitError("User '%s' is not a valid xSFTP user" % a)
        if len(args) != 1: exitBadArg()
        drop_privileges(a)
        fingerprint = args[0]
        try:
            pubkeys = parse_authorized_keys_file(a)
        except Exception, e:
            exitError('Error reading authorized_keys at line %s: %s' % (e[1], e[0]))
        new_pubkeys = [key for key in pubkeys if key.fingerprint != fingerprint]
        if new_pubkeys == pubkeys:
            exitError('No such key')
        authorized_keys_file = "/home/%s/.ssh/authorized_keys" % a
        new_ak_data = []
        for key in new_pubkeys:
            line = "%(type)s %(b64key)s %(comment)s" % {'type':key.type, 'b64key':key.get_base64(), 'comment':key.comment}
            new_ak_data.append(line)
        new_ak_data = "\n".join(new_ak_data)
        f = open(authorized_keys_file, 'w')
        f.write(new_ak_data)
        f.close()

    elif o in ("--set_key_comment",):
        if not is_user(a): exitError("User '%s' is not a valid xSFTP user" % a)
        if len(args) != 2: exitBadArg()
        drop_privileges(a)
        fingerprint = args[0]
        comment = args[1]
        try:
            pubkeys = parse_authorized_keys_file(a)
        except Exception, e:
            exitError('Error reading authorized_keys at line %s: %s' % (e[1], e[0]))
        fingerprint_found = False
        for key in pubkeys:
            if key.fingerprint == fingerprint:
                fingerprint_found = True
                key.comment = comment
        if not fingerprint_found:
            exitError('No such key')
        authorized_keys_file = "/home/%s/.ssh/authorized_keys" % a
        new_ak_data = []
        for key in pubkeys:
            line = "%(type)s %(b64key)s %(comment)s" % {'type':key.type, 'b64key':key.get_base64(), 'comment':key.comment}
            new_ak_data.append(line)
        new_ak_data = "\n".join(new_ak_data)
        f = open(authorized_keys_file, 'w')
        f.write(new_ak_data)
        f.close()

    elif o in ("--readdir",):
        nodes = dict()
        try:
            entries = os.listdir(a)
        except Exception, e:
            print pickle.dumps(e)
            sys.exit(-1)
        for entry in entries:
            try:
                stat_data = os.lstat(os.path.join(a, entry))
            except Exception, e:
                stat_data = e
            nodes[entry] = stat_data
        print pickle.dumps(nodes)

    elif o in ("-a", "--restart"):
        # first give the restart_in_progress.html page a chance to render
        time.sleep(5)
        os.system("/sbin/shutdown -r now")
        exitSuccess()

    elif o in ("--explorer_copy",):
        if len(args) != 2:
            exitBadArg()
        # OK, now copy the source to the dest
        try:
            do_copy(args[0], args[1])
        except Exception, e:
            print pickle.dumps(e)

    elif o in ("--explorer_temporary_rename"):
        if len(args) != 1:
            print pickle.dumps(Exception((503, "Invalid arguments for temporary rename")))
        source = args[0]
        source_dir = os.path.dirname(source)
        try:
            temp_filename = tempfile.mktemp(dir=source_dir, prefix='fcombine_explorer_temp_file_')
            fsutil.move(source, temp_filename, ignore_errors=True)
            print pickle.dumps((200, temp_filename))
        except Exception, e:
            print pickle.dumps(e)
            sys.exit(-1)
        
    elif o in ("--explorer_move",):
        if len(args) != 2:
            exitBadArg()
        # OK, now copy the source to the dest
        user = extract_username_from_path(args[0])
        drop_privileges(user)
        try:
            check_path(args[1], user) 
            fsutil.move(args[0], args[1], ignore_errors=True)
        except Exception, e:
            print pickle.dumps(e)

    elif o in ("--explorer_delete",):
        if len(args) != 1:
            exitBadArg()
        try:
            do_delete(args[0])
        except Exception, e:
            print pickle.dumps(e)

    elif o in ("--explorer_mkdir",):
        # Get the directory name
        dir_name = args[0]
        # Get the real_dir name
        real_dir = args[1]
        full_path_to_new_dir = os.path.join(real_dir, dir_name)
        # Try to create the dir, catch any errors and pass them back to the caller
        try:
            username = extract_username_from_path(full_path_to_new_dir)
            check_path(full_path_to_new_dir, username)
            drop_privileges(username)
            os.mkdir(full_path_to_new_dir)
        except Exception, e:    
            print pickle.dumps(e)

    elif o in ("--explorer_upload",):
        dest = args[0]
        filename = args[1]
        my_debug("Writing file '%s' to '%s'" % (filename, dest))
        username = extract_username_from_path(dest)
        drop_privileges(username)
        dest = os.path.join(dest, os.path.basename(filename)) # XXX do we need this?
        try:
            # First, we need to check if the destination directory exists ...
            # So, get the endpoint directory
            dest_dir = dest[:dest.rfind("/")]
            # If the path doesn't yet exist ...
            if not os.path.exists(dest_dir):
                # create it
                os.makedirs(dest_dir)
            else:
                # the path exists already
                # if it's not a directory ...
                if not os.path.isdir(dest_dir):
                    # bail out - the target 'directory' is in fact a file - not much we can do about that
                    raise Exception((500, "Destination 'directory' is a file"))
            if os.path.exists(dest):
                raise Exception((501, "Destination file already exists"))
        except Exception, e:
            try:
                err_no = e.message[0]
                err_msg = e.message[1]
                message = "%s %s\n" % (err_no, err_msg)
            except:
                message = '500 %s' % str(e).replace("\n"," ")
            sys.stdout.write(message)
            sys.exit(-1)
        sys.stdout.write("200\n")
        sys.stdout.flush()
        try:
            # If the below operation fails, we probably don't have permission to create the file.
            # Depending on FUSE implementation, the error should be IOError 13 Perm Denied, however
            # the FTP FUSE module returns IOError 2 No such file or directory. Capture both and
            # return Permission Denied.
            try:
                f = file(dest, 'w')
            except:
                raise IOError('Permission denied')
            data = True
            length = 0
            while data:
                my_debug("reading data from stdin ...")
                data = sys.stdin.read(4096)
                my_debug("done reading data")
                length += len(data)
                my_debug("data length is %s" % length)
                if data:
                    my_debug("about to write data to file ...")
                    f.write(data)
                    my_debug("finished writing to file")
            f.close()
            sys.stdout.write(pickle.dumps(length))
        except Exception, e:
            sys.stdout.write(pickle.dumps(e))

    elif o in ("--explorer_getfile",):
        # FIXME check that the file is in a legit directory (eg /home/<user>/xsftp/something/something2
        # FIXME Check that the user is an xsftp user
        full_path_to_file = args[0]
        file_size = os.stat(full_path_to_file)[stat.ST_SIZE]
        f = open(full_path_to_file)
        print "200 %s" % file_size
        data = True
        while data:
            data = f.read(4096)
            if data:
                sys.stdout.write(data)
        f.close()

    else:
        usage()
        sys.exit(255)


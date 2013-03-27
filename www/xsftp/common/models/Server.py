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

import datetime
from django.db import models

from xGroup import xGroup
from django.contrib.auth.models import User
from xsftp.common.constants import COMMENT_LENGTH
from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity



class Server(models.Model):
    '''
    Server link object class
    '''

    class Meta:
        app_label = "webui"

    # Generic attributes
    server_name = models.CharField(max_length=30)
    type = models.CharField(max_length=30)
    enabled = models.BooleanField(default=True)
    address = models.CharField(max_length=256, blank=True, null=True)
    remote_user = models.CharField(max_length=60)
    remote_path = models.CharField(max_length=512)
    comment = models.CharField(max_length=COMMENT_LENGTH, blank=True)
    created = models.DateTimeField()
    status = models.IntegerField(blank=True, null=True)
    timeFirstSeenInCurrentState = models.DateTimeField(blank=True, null=True)
    timeLastSeenHealthy = models.DateTimeField(blank=True, null=True)
    time_last_checked = models.DateTimeField(blank=True, \
            null=True, default=None)
    read_users = models.ManyToManyField(User, related_name="read_servers")
    write_users = models.ManyToManyField(User, related_name="write_servers")
    read_groups =  models.ManyToManyField(xGroup, related_name="read_servers")
    write_groups = models.ManyToManyField(xGroup, related_name="write_servers")
    # SFTP-specific attributes
    port = models.IntegerField(blank=True, null=True)
    key_file = models.CharField(max_length=256, blank=True)
    key_fingerprint = models.CharField(max_length=64, blank=True, null=True)
    # CIFS-specific attributes
    cifs_share = models.CharField(max_length=512, blank=True, null=True)
    cifs_password = models.CharField(max_length=512, blank=True, null=True)
    cifs_port = models.IntegerField(blank=True, null=True)
    # FTP-specific attributes
    ftp_port = models.IntegerField(blank=True, null=True)
    ftp_password = models.CharField(max_length=512, blank=True, null=True)
    ftp_passive = models.BooleanField(default=True)
    ftp_ssl = models.BooleanField(default=True)
    ftp_ssl_implicit = models.BooleanField(default=False)

    def __init__(self, *args, **kwargs):
        super(Server, self).__init__(*args, **kwargs)
        self.mount_point = None

    def save(self, synchronise=True):
        '''synchronise option specifies whether we need to do a dbCommit and
           checkJobSanity()'''
        if type(self.time_last_checked) == type(datetime.datetime.now()):
            self.time_last_checked = \
                    self.time_last_checked.replace(microsecond=0)
        # if this server has no associated BMP's
        try:
            if not self.read_users.all() and not self.write_users.all() and \
                    not self.read_groups.all() and not self.write_groups.all():
                # then mark status as -10 ("this server link is unused")
                self.status = -10
        except ValueError:
            # we get here if 'self' is a new server that hasn't been saved yet,
            # in which case it will be unused
            self.status = -10
        f = open('/tmp/out','a')
        f.close()
        super(Server, self).save()
        if synchronise:
            dbCommit()
            checkJobSanity()

    def delete(self):
        # Find all jobs that have this object as a foreign key,
        # and set that foreign key to None
        for job in self.jobs_source.all():
            job.source_server = None
            job.save()
        for job in self.jobs_dest.all():
            job.dest_server = None
            job.save()
        super(Server, self).delete()
        #log("deleted Server Link '%s'" % self.server_name)
        dbCommit()
        checkJobSanity()

    def getAllReadUsers(self):
        '''
        Returns a list containing all user objects who can read from this server
        by any association incuding those with write access.
        '''
        return self.getEffectiveReadUsers() + self.getEffectiveWriteUsers()

    def getEffectiveReadUsers(self):
        '''
        Returns a list containing user objects who can *ONLY* read from (and not
        write to) this server. Read access by virtue of group membership will be
        included.
        '''
        # First, get the "direct" users
        readUsers = list(self.read_users.get_query_set()[:])
        # figure out the effective read users by looking at groups
        # for each user in read groups
        for readGroup in self.read_groups.get_query_set():
            for user in readGroup.users.get_query_set():
                # and if user is not already identified as a read user
                if user not in readUsers:
                    # add the user as a read user
                    readUsers.append(user)
        # now remove users identified as having read access who also have write
        # access by virtue of group membership.
        # for each user in write users
        for writeUser in self.write_users.get_query_set():
            if writeUser in readUsers:
                readUsers.remove(writeUser)
        # for each user in all write groups, including user only ones
        for writeGroup in self.write_groups.get_query_set():
            for writeUser in writeGroup.users.get_query_set():
                # if the user happens to be in the list of identified read users
                if writeUser in readUsers:
                    # remove the user as a read user
                    readUsers.remove(writeUser)
        return readUsers

    def getEffectiveWriteUsers(self):
        '''
        Returns a list containing user objects which have read-and-write
        permissions on this server. Users who have this permission by virtue of
        group membership will be included.
        '''
        writeUsers = []
        for user in self.write_users.all():
            writeUsers.append(user)
        for writeGroup in self.write_groups.all():
            for user in writeGroup.users.all():
                # and if user is not already identified as a write user
                if user not in writeUsers:
                    # add the user as a write user
                    writeUsers.append(user)
        return writeUsers

    def __unicode__(self):
        return self.server_name

    def __str__(self):
        return self.__unicode__()

    class Admin:
        pass

    def getAssociatedUsers(self):
        '''
        Returns a list containing 4-tuples for each user with any perms on this
        server (ordered alphabetically on username). The first item is the user
        object, and the remaining 3 identify the user's permissions and group
        associations on this server in the form:
        (userObj, user_perm, effective_perm, ( [readGroupObj, ...], [writeGroupObj, ...] ) )
        Where:
            user_perm = bitmask, 0 if user is not a direct read or write user,
                        +1 for read perm,
                        +2 for write perm.
            effective_perm = 1 for read perm, 2 for write perm
        '''
        associated_users = {}
        for user in self.read_users.all():
            associated_users[user] = [1, 1, [list(), list()]]
        for user in self.write_users.all():
            if user in associated_users:
                associated_users[user][0] = 2
                associated_users[user][1] = 2
            else:
                associated_users[user] = [2, 2, [list(), list()]]
        for read_group in self.read_groups.all():
            for user in read_group.users.all():
                if user in associated_users:
                    associated_users[user][2][0].append(read_group)
                else:
                    associated_users[user] = [0, 1, [[read_group], list()]]
        for write_group in self.write_groups.all():
            for user in write_group.users.all():
                if user in associated_users:
                    associated_users[user][2][1].append(write_group)
                    associated_users[user][1] = 2
                else:
                    associated_users[user] = [0, 2, [list(), [write_group]]]
        result = []
        for item in associated_users.items():
            result.append((item[0], item[1][0], item[1][1],\
                        [item[1][2][0], item[1][2][1]]))
        result = sorted(result, key=lambda x: x[0].username.lower())
        return result

    def healthStrings(self):
        '''
        Returns a list of meningful strings in HTML describing the health (or
        lack thereof) of a server, including cause and remediation
        '''
        if self.status == 0:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_OK</td></tr>
                                    <tr><td>Description:</td><td>Server is healthy.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 1:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_BM_BROKEN</td></tr>
                                    <tr><td>Description:</td>
                                        <td>A required internal association to this Server Link doesn't exist yet, and is in the process of being automatically created.<br></br>
                                            This problem may not affect all users of this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td><td>This state can occur during application of new permissions on this Server Link,<br></br>
                                                           or when the Server Link is mid-way through being repaired from a previous unhealthy state.</td></tr>
                                    <tr><td>Remediation:</td><td>This problem will be automatically repaired.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 2:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_SM_BROKEN</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link is down, and its internal associations may also be down.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>Either:
                                            <ul>
                                                <li>This Server Link is mid-way through being initialised</li>
                                                <li>This Server Link is mid-way through being repaired from a previous unhealthy state</li>
                                                <li>An an unexpected shutdown of the associated Server Link process may have occured</li>
                                            </ul>
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 3:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_BM_AND_SM_BROKEN</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link is down, and at least one internal association is also down.<br></br>
                                            This problem may not affect all users of this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            A shutdown of the associated Server Link process has occured, and at least one internal association remains to be initialised.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 4:
            if self.type == 'sftp':
                type = 'SSH'
                type_cause = '<li>A shutdown of the SFTP session as well as the SSH service on the endpoint server</li>'
            else:
                type = self.type.upper()
                type_cause = '<li>Shutdown of the %s service on the endpoint server</li>' % type
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_SM_DISCONNECTED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link was healthy but has been disconnected.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This error state can be caused by the following:
                                            <ul>
                                                <li>Network issues (cabling problems, routing problems, network outages, etc)</li>
                                                <li>A shutdown or reboot of the endpoint server is in progress</li>
                                                %(type_cause)s
                                            </ul>
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>
                                            This problem will self-heal when the endpoint server and its %(type)s service come back online.<br></br>
                                            To attempt a forceful reconnect of this Server Link, you may reset it on the <a href="/serverlinks/">Server Links</a> page.
                                        </td>
                                    </tr>
                                </table>''' % {'type_cause':type_cause, 'type':type, "state":self.status}
        elif self.status == 5:
            if self.type == 'sftp':
                type_cause = '<li>A shutdown of the SFTP session as well as the SSH service on the endpoint server</li>'
            else:
                type_cause = '<li>Shutdown of the %s service on the endpoint server</li>' % self.type.upper()
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_SM_DISCONNECTED_AND_BM_BROKEN</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link was healthy but has been disconnected, and at least one internal association is also down.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This error state can be caused by the following:
                                            <ul>
                                                <li>This server link has been reset, and is in the process of being re-establsihed</li>
                                                <li>Network issues (cabling problems, routing problems, network outages, etc)</li>
                                                <li>A shutdown or reboot of the endpoint server is in progress</li>
                                                %(type_cause)s
                                            </ul>
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.</td></tr>
                                </table>''' % {'type_cause':type_cause, "state":self.status}
        elif self.status == 6:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_BM_UNREATTACHED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link's internal associations were attached to a Server Link process which has since died. There may or may not be a new Server Link process.<br></br>
                                            This problem may not affect all users of this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This issue can occur when a Server Link is mid-way through being repaired from a previous unhealthy state, or when an unexpected shutdown of a Server Link process occurs.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 7:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_BMP_DOESNT_EXIST</td></tr>
                                    <tr><td>Description:</td>
                                        <td>At least one of this Server Link's internal associations remain to be initialised.<br></br>
                                            This problem may not affect all users of this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This state generally occurs after a full system restart. It indicates that Server Links are mid-way through being initialised.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 8:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_SMP_DOESNT_EXIST</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link remains to be initialised.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This state generally occurs during system start-up. It indicates that this Server Link is mid-way through being initialised.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.</td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 9:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_CANT_RESOLVE_HOSTNAME</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Can't resolve the specified endpoint address '%(address)s' of this Server link.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            There may be an error in the provided endpoint server address, or there may be DNS resolution issues.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please check the server address setting for this Server Link, and/or the system-wide DNS settings in the <a href="/configuration/">Configuration</a> section.</td></tr>
                                </table>'''  % {"state":self.status, "address":self.address}
        elif self.status == 10:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_NO_ROUTE_TO_HOST</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Can't connect to the specified server address '%(address)s' of this Server link.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            There may be an error in the provided server address, the port, the system wide network settings, or with the endpoint server itself.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please check the server address and port settings for this Server Link, and/or the system-wide network settings in the <a href="/configuration/">Configuration</a> section.</td></tr>
                                </table>''' % {"state":self.status, "address":self.address}
        elif self.status == 11:
            type = self.type.upper()
            if self.type == 'sftp':
                port = self.port
                type = "SSH/SFTP"
            elif self.type == 'cifs':
                port = self.cifs_port
            elif self.type == 'ftp':
                port = self.ftp_port
            else:
                port = '<UNKNOWN>'
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_CONNECTION_REFUSED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Could not connect to the endpoint server's %(type)s service on port %(port)s at address '%(address)s'.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The host at the specified server address %(address)s is actively refusing connections on the specified port number %(port)s.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>Please check:
                                            <ul>
                                                <li>that the server address and port settings for this Server Link are correct</li>
                                                <li>that the specified server is listening for connections on the specified port</li>
                                                <li>that there are no host-based (or other) firewalls preventing the connection</li>
                                            </ul>
                                        </td>
                                    </tr>
                                </table>''' % {"address":self.address, "port":port, "type":type, "state":self.status}
        elif self.status == 12:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_CONNECTION_TIMEOUT</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Can't connect to the specified server address '%(address)s' of this Server link.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            There may be an error in the provided server address, port, system wide network settings, or with the endpoint server itself.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please check the server address and port settings for this Server Link, and/or the system-wide network settings in the <a href="/configuration/">Configuration</a> section.
                                        </td></tr>
                                </table>''' % {"state":self.status, "address":self.address}
        elif self.status == 13:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_KEY_MISMATCH</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The RSA key fingerprint of this server has changed!<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The SSH service on the specified endpoint server may have been reinstalled or reinitialised, or a rogue server is acting as an imposter and is attempting a man in the middle attack!
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>If the SSH service on the specified endpoint server has been re-initialised, reset the Server Link's <a href="/serverlinks/">local key fingerprint record.</a>
                                        </td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 14:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_KEYFILE_MISSING</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Can not locate the local DSS private key file<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The local automatically generated DSS private key file is missing.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please reboot the Fcombine to re-generate a new key pair.<br></br>
                                                                 Note that all endpoint servers will need to be reconfigured with the Global Server Link Public Key.
                                        </td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 15:
            type = self.type.upper()
            if self.type == 'sftp':
                port = self.port
                type = "SSH"
            elif self.type == 'cifs':
                port = self.cifs_port
            elif self.type == 'ftp':
                port = self.ftp_port
            else:
                port = '<UNKNOWN>'
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_WRONG_SERVICE</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Wrong service detected at port %(port)s on specified endpoint server '%(address)s'<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The host at the specified server address %(address)s is accepting connections on the specified port number %(port)s, however it is not serving the %(type)s service on this port.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please ensure the correct port is specified for this Server Link.<br></br>
                                                                 Please ensure also that the %(type)s service is running on the specified port on the endpoint server.
                                        </td></tr>
                                </table>''' % {"address":self.address, "port":port, 'type':type, "state":self.status}
        elif self.status == 16:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_PUBLIC_KEY_NOT_ALLOWED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The endpoint's SSH service does not allow public key authentication, thus preventing this system from establishing the Server Link.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The endpoint's SSH service is specifically configured to disallow public key authentication as an authentication mechanism.<br></br>
                                            The Fcombine relys on public key authentication to authenticate itself to endpoint servers and establish SFTP sessions to them.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please configure public key authentication as an allowed authentication mechanism on the endpoint server at %(address)s.
                                        </td></tr>
                                </table>''' % {"address":self.address, "state":self.status}
        elif self.status == 17:

            if self.type == 'sftp':
                type_cause = "<li>This system's public key may not be correctly imported into the endpoint's SSH service.</li>"
                type_remedy = "Please ensure that this system's Global Server Link Public Key is correctly imported into the endpoint server's SSH service."
            else:
                type_cause = "<li>The specified password is incorrect.</li>"
                type_remedy = "Please check that the Password for this Server Link is correct"
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_AUTH_FAILED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The endpoint server has rejected this system's authentication attempt.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>Either:
                                            <ul>
                                                <li>The specified remote username '%(remote_user)s' is incorrect; or</li>
                                                %(type_cause)s
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please check that the remote user name '%(remote_user)s' for this Server Link is correct<br></br>
                                                                 %(type_remedy)s
                                        </td></tr>
                                </table>''' % {"remote_user":self.remote_user, "type_cause":type_cause, "type_remedy":type_remedy, "state":self.status}
        elif self.status == 18:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_KEY_REQUIRES_PASSPHRASE</td></tr>
                                    <tr><td>Description:</td>
                                        <td>
                                            The local private key has requested a passphrase. This is not supported in this Fcombine release.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This system's private key has been manually created with a passphrase.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please delete the manually created key pair, then reboot the Fcombine to re-generate a new key pair.<br></br>
                                                                Note that all endpoint servers will need to be reconfigured with the newly generated Global Server Link Public Key.
                                        </td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 19:
            healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_BAD_REMOTE_PATH</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The specified remote path '%(remote_path)s' for this Server Link does not exist.<br></br>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The remote path that was entered for this Server Link does not exist on the remote server.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please check that the remote path '%(remote_path)s' for this Server Link exists on the endpoint server (%(address)s).
                                        </td></tr>
                                </table>''' % {"remote_path":self.remote_path, "address":self.address, "state":self.status}
        elif self.status == 20:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_SOCKET_ERROR</td></tr>
                                    <tr><td>Description:</td>
                                        <td>An unexpected socket related error has occured.
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            A tcp socket error occured while a Server Link or one of its internal associations was being profiled for its health status.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.
                                        </td></tr>
                                </table>''' % {"state":self.status}
        elif self.status == 21:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_CIFS_BAD_SHARE_NAME</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Either:<br></br>
                                            <ul>
                                                <li> The specified CIFS Share Name could not be found or connected to; or</li>
                                                <li> The specified user account may not have permissions to use the share..</li>
                                            </ul>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The specified CIFS Share Name could not be found or connected to on the endpoint server.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Check that the specified Share Name '%(cifs_share)s' is correct<br></br>
                                                                 Check that the endpoint server permissions allow the user '%(cifs_user)s' to access the share.<br></br>
                                        </td></tr>
                                </table>''' % {'cifs_user': self.remote_user, 'cifs_share':self.cifs_share, "state":self.status}
        elif self.status == 22:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_CIFS_ERROR</td></tr>
                                    <tr><td>Description:</td>
                                        <td>An unspecified CIFS-related error has occured.<br/>
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            An error has been detected whilst profiling this CIFS Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Please check the settings for this Server Link.<br/>
                                                                 Automatic repair of this problem will be attempted.
                                        </td>
                                    </tr>
                                </table>''' % {"state":self.status}
        elif self.status == 23:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_FTP_DATA_CHANNEL_ERROR</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The DATA channel of the FTP connection could not be established.
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This error is typically caused by a firewall preventing the establishment of the TCP connection for the FTP DATA channel.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>
                                            If a firewall exists between the Fcombine and the specified endpoint server, ensure that it is configured to allow this FTP connection.%(passive_mode)s
                                        </td>
                                    </tr>
                                </table>''' % {"state":self.status, "passive_mode": ["<br/>Try specifying Passive Mode for this Server Link, as it is more firewall friendly.", "<br/>Ensure that the Fcombine can establish TCP connections to the endpoint server on the negotiated passive port (typically any port between 1025 and 65535, inclusive). "][self.ftp_passive] }
        elif self.status == 24:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_FTP_FTPS_NOT_SUPPORTED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The endpoint server does not support FTPS (Implicit mode) on the specified port.
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The attempt to establish an implicit SSL/TLS session over the TCP connection to the endpoint server failed.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>
                                            <ul>
                                                <li>Check that the specified FTP port is correct.
                                                <li>Ensure the endpoint server's FTP service supports FTPS (Implicit) on the specified FTP port.
                                                <li>Consider trying FTP/SSL Explicit mode.
                                            </ul>
                                        </td>
                                    </tr>
                                </table>''' % {"state":self.status}
        elif self.status == 25:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_FTP_FTPES_NOT_SUPPORTED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The endpoint server does not support FTPES (Explicit mode) on the specified port.
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The attempt to negotiate an SSL/TLS session for the FTP CONTROL connection failed.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>
                                            Ensure the endpoint server's FTP service supports FTPES (Explicit) on the specified FTP port.  
                                        </td>
                                    </tr>
                                </table>''' % {"state":self.status}

        elif self.status == 26:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_FTP_FTPES_REQUIRED</td></tr>
                                    <tr><td>Description:</td>
                                        <td>The endpoint server may require FTPES (Explicit mode).
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            The attempt to login without negotiating an SSL/TLS session for the FTP CONTROL connection was rejected by the remote FTP server.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>
                                            Try specifying FTPES (Explicit) for this Server Link.
                                        </td>
                                    </tr>
                                </table>''' % {"state":self.status}
        elif self.status == 27:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_FTP_ERROR</td></tr>
                                    <tr><td>Description:</td>
                                        <td>An error occured preventing this FTP Server link from being established.
                                            This problem will affect <i>ALL</i> users of this Server Link until repaired.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            A protocol error occured whilst trying to establish this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td>
                                        <td>
                                            Ensure that all of the specified settings of this Server Link are correct.<br/>
                                            Search the the System Log (keyword: MPSTATE_FTP_ERROR) for error details including any messages that were received by the remote FTP server.
                                        </td>
                                    </tr>
                                </table>''' % {"state":self.status}
        elif self.status == -10:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_NOT_IN_USE</td></tr>
                                    <tr><td>Description:</td>
                                        <td>This Server Link is not in use.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            There are no read or read/write users or groups associated to this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Edit this Server Link and add permit access to one or more users and/or groups.
                                        </td></tr>
                                </table>''' % {"state":self.status}
        elif -4 <= self.status <= -1:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_ERROR%(state)s</td></tr>
                                    <tr><td>Description:</td>
                                        <td>An error occured while this Server Link or one of its internal associations was being profiled for its health status.
                                            This problem may not affect all users of this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This error can occur during a Server Link's initialisation phase.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.
                                        </td></tr>
                                </table>''' % {"state":self.status}
        else:
                healthString = '''    <table>
                                    <tr><td>State:</td><td>(%(state)s) MPSTATE_ERROR_%(state)s</td></tr>
                                    <tr><td>Description:</td>
                                        <td>Server Link health profiling in progress.
                                            This problem may not affect all users of this Server Link.
                                        </td>
                                    </tr>
                                    <tr><td>Cause:</td>
                                        <td>
                                            This Server Link is being profiled for its health status.
                                        </td>
                                    </tr>
                                    <tr><td>Remediation:</td><td>Automatic repair of this problem will be attempted.
                                        </td></tr>
                                </table>''' % {"state":self.status}
        return healthString



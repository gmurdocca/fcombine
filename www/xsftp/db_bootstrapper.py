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
import sys
sys.path.append("/opt/fcombine/www")
os.environ["DJANGO_SETTINGS_MODULE"]="xsftp.settings"
import getopt
import pwd
import stat
from xsftp.webui.constants import DB_FILE
from django.core import management
from django.contrib.auth.models import User
from xsftp.common.models.UserProfile import UserProfile
from xsftp.common.models.LDAPServer import LDAPServer
from xsftp.common.models.DirectoryServer import LocalDirectoryServer
from xsftp.common.models.DirectoryServer import LDAPDirectoryServer
from xsftp.common.models.AuthServer import LocalAuthServer
from xsftp.common.models.AuthServer import LDAPAuthServer
from xsftp.common.models.AuthServer import RADIUSAuthServer
from xsftp.common.models.Configuration import Configuration

delete_dbfile = False
create_test_db = False

def usage():
    print """== db_bootstrapper==
Initialises the Fcombine database.
Usage:
%s [--full]
    --full      Delete the database file '%s' if it already exists
    --test      Populate the database with test objects
""" % (sys.argv[0], DB_FILE)

try:
    opts, args = getopt.getopt(sys.argv[1:], "", ["full", "test"])

    for opt, arg in opts:
        if opt == "--full":
            delete_dbfile = True
        if opt == "--test":
            create_test_db = True
except getopt.GetoptError, e:
        print "ERROR: %s" % e
        usage()
        sys.exit()
except ValueError, e:
    if not len(sys.argv) == 1:
        print "ERROR: Invalid option."
        usage()
        sys.exit()
if args:
    print "ERROR: Invalid argument."
    usage()
    sys.exit()

if os.path.isfile(DB_FILE):
    if delete_dbfile:
        os.unlink(DB_FILE)
    else:
        print ("DB File already exists! Use --full to purge it,"
               "and optionally --test to insert test data.")
        sys.exit()

# create new empty db
management.call_command('syncdb', interactive=False)

# set correct perms for the app
os.chown(DB_FILE, 0, pwd.getpwnam('apache').pw_uid)
os.chmod(DB_FILE, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

# create admin User
admin_user = User()
admin_user.username = "admin"
admin_user.email = "admin@example.com"
admin_user.is_staff = True
admin_user.is_superuser = True
admin_user.set_password("fcombine")
admin_user.save()

# create an AuthServer object for the admin user
local_dir_server = LocalDirectoryServer()
local_dir_server.save()
local_auth_server = LocalAuthServer()
local_auth_server.directory_server = local_dir_server
local_auth_server.save()

# create admin's UserProfile
admin_userprofile = UserProfile()
admin_userprofile.auth_server = local_auth_server
admin_userprofile.user = admin_user
admin_userprofile.save()

# create stock configuration
configuration = Configuration()
configuration.device_name = "fcombine"
configuration.ip_address = "192.168.0.1"
configuration.subnet_mask = "255.255.255.0"
configuration.save()

if create_test_db:
    print "** Adding test objects to Fcombine database **"

    print "Creating local user: localuser"
    # create local User
    local_user = User()
    local_user.username = "localuser"
    local_user.email = "localuser@example.com"
    local_user.is_staff = False
    local_user.set_password("localuser")
    local_user.save()
    # create local's UserProfile
    local_userprofile = UserProfile()
    local_userprofile.auth_server = local_auth_server
    local_userprofile.user = local_user
    local_userprofile.save()

    print "Creating LDAP user: ldapuser"
    # create ldap User
    ldap_user = User()
    ldap_user.username = "ldapuser"
    ldap_user.email = "ldapuser@example.com"
    ldap_user.is_staff = False
    ldap_user.save()

    # Create an LDAP Server
    ldap_server = LDAPServer()
    ldap_server.hostname = "172.16.1.11"
    ldap_server.port = 636
    ldap_server.use_ssl = True
    ldap_server.bind_dn = "cn=LDAP Bind 1,ou=Fcombine Users,dc=example,dc=com"
    ldap_server.bind_password = "bindpassword"
    ldap_server.base_dn = "dc=example,dc=com"
    ldap_server.username_attribute = "sAMAccountName"
    #FIXME Continue here.

    # Create an LDAP Directory Server

    


    # create an LDAP AuthServer (AD) for this user
    ldap_auth_server1 = LDAPAuthServer()
    # can also be done this way:
    # ldap_auth_server1.bind_dn = "ldapbind1@example.com"
    ldap_auth_server1.bind_password = "bindpassword"
    ldap_auth_server1.base_dn = "dc=example,dc=com"
    ldap_auth_server1.username_attribute = "sAMAccountName"
    ldap_auth_server1.filter = "(&(objectClass=user)(sAMAccountName=$username))"
    ldap_auth_server1.verify_cert = False
    ldap_auth_server1.sync_idle_period = 10
    ldap_auth_server1.save()

    # create a standalone LDAP AuthServer (openldap)
    ldap_auth_server1 = LDAPAuthServer()
    ldap_auth_server1.hostname = "172.16.1.2"
    ldap_auth_server1.port = 636
    ldap_auth_server1.use_ssl = True
    ldap_auth_server1.bind_dn = "uid=ldapauth,ou=People,dc=pdev,dc=com"
    # can also be done this way:
    # ldap_auth_server1.bind_dn = "ldapbind1@example.com"
    ldap_auth_server1.bind_password = "boggle"
    ldap_auth_server1.base_dn = "ou=People,dc=pdev,dc=com"
    #ldap_auth_server1.username_attribute = ""
    ldap_auth_server1.filter = "(&(objectClass=posixAccount)(uid=$username))"
    ldap_auth_server1.verify_cert = False
    ldap_auth_server1.sync_idle_period = 10
    ldap_auth_server1.save()

    # create ldap's UserProfile
    ldap_userprofile = UserProfile()
    ldap_userprofile.auth_server = ldap_auth_server1
    ldap_userprofile.user = ldap_user
    ldap_userprofile.save()

    print "Creating RADIUS user: radiususer"
    # create RADUS user
    radius_user = User()
    radius_user.username = "radiususer"
    radius_user.email = "radiususer@example.com"
    radius_user.is_staff = False
    radius_user.save()

    # create a RADIUS AuthServer for this user
    radius_auth_server1 = RADIUSAuthServer()
    radius_auth_server1.radius_server = "172.16.1.11"
    radius_auth_server1.radius_authport = 1812
    radius_auth_server1.radius_secret = "secret"
    radius_auth_server1.save()

    # create radius's UserProfile
    radius_userprofile = UserProfile()
    radius_userprofile.auth_server = radius_auth_server1
    radius_userprofile.user = radius_user
    radius_userprofile.save() 

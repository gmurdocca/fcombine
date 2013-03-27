#!/usr/bin/python
############################################################################
# Fcombine FX Django xForms.py
# ###########################
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

# ******************************
#          Imports
# ******************************

from django import forms
from django.contrib.auth.models import User
from django.contrib import auth
from datetime import datetime
import xsftp.webui.constants
import xsftp, time, os, re, IPy, pwd, cracklib, paramiko, binascii, base64, zipfile, subprocess, pickle, tempfile
from cStringIO import StringIO
import xsftp.common.constants
from xsftp.common.Licenses import Licenses


# ******************************
#          Constants
# ******************************


VALID_FILENAME_PATTERN = re.compile(xsftp.common.constants.FILENAME_PATTERN)
VALID_PATH_PATTERN = re.compile(xsftp.common.constants.PATH_PATTERN)
VALID_CRON_PATTERN = re.compile(xsftp.common.constants.CRON_PATTERN)
VALID_USERNAME_PATTERN = re.compile(xsftp.common.constants.USERNAME_PATTERN)
VALID_GROUPNAME_PATTERN = re.compile(xsftp.common.constants.GROUPNAME_PATTERN)
VALID_SERVERLINKNAME_PATTERN = re.compile(xsftp.common.constants.SERVERLINKNAME_PATTERN)
VALID_SCRIPTNAME_PATTERN = re.compile(xsftp.common.constants.SCRIPTNAME_PATTERN)
VALID_JOBNAME_PATTERN = re.compile(xsftp.common.constants.VALID_JOBNAME_PATTERN)
VALID_IP_ADDRESS_PATTERN = re.compile(xsftp.common.constants.IP_ADDRESS_PATTERN)
VALID_FQDN_PATTERN = re.compile(xsftp.common.constants.FQDN_PATTERN)
VALID_DEVICENAME_PATTERN = re.compile(xsftp.common.constants.DEVICENAME_PATTERN)
VALID_EMAIL_ADDRESS_PATTERN = re.compile(xsftp.common.constants.EMAIL_ADDRESS_PATTERN)
VALID_CIFS_SHARE_PATTERN = re.compile(xsftp.common.constants.CIFS_SHARE_PATTERN)

# max visible number of choices in a selectmultiple widget before scrollbars are rendered
SELECT_MULTIPLE_SIZE = 7
# max comment length for pubkeys imported via My SSH Keys
MAX_PUBKEY_COMMENT_LENGTH = 70
# Default device name
DEFAULT_DEVICE_NAME = "fcombine"


#############################################################################
#                            WIDGET Classes
#############################################################################

class TextLabelWidget(forms.widgets.Widget):

    def __init__(self, attrs=None):
        default_attrs = {'style':'fontsize:10px;'}
        if attrs:
            default_attrs.update(attrs)
        super(TextLabelWidget, self).__init__(default_attrs)

    def render(self, name, value, attrs=None):
        final_attrs = self.build_attrs(attrs)
        attrs_string = " ".join(["%s='%s'" % (a, v) for a, v in final_attrs.items()])
        return u"<span %s>%s</span>" % (attrs_string, value)


#############################################################################
#                            FIELD Classes
#############################################################################


class PasswordField(forms.CharField):
    widget = forms.PasswordInput()

class MyDateField(forms.DateField):
    widget = forms.TextInput(attrs={'class':'vDateField'})

class MyDateTimeField(forms.DateTimeField):
    widget = forms.DateTimeInput(attrs={'class':'vDateTimeField'})

class MyBasicDateTimeField(forms.DateTimeField):
    widget = forms.DateTimeInput(attrs={'class':'vBasicDateTimeField'})

class MyTextLabelField(forms.CharField):
    widget = TextLabelWidget()


#############################################################################
#                            FORM Classes
#############################################################################


# ******************************
#          User Forms
# ******************************


class NewUserForm(forms.Form):
    username = forms.CharField(label="Username")
    internal_auth = forms.BooleanField(label="Local Account", initial=True, required=False, widget=forms.CheckboxInput(attrs={'onclick':'showPasswordFields();'}))
    password_1 = PasswordField(label="Password", required=False)
    password_2 = PasswordField(label="Verify Password", required=False)


    def clean_username(self):
        submittedUsername = self.data.get('username')
        if User.objects.filter(username=submittedUsername):
            raise forms.ValidationError('The username already exists')
        if not VALID_USERNAME_PATTERN.search(submittedUsername):
            raise forms.ValidationError('The username contains illegal characters')
        try:
            pwd.getpwnam(submittedUsername)
        except KeyError:
            return submittedUsername
        raise forms.ValidationError('This username is reserved and is not available for use.')

    def clean_password_1(self):
        if self.data.get('internal_auth'):
            if not self.data.get('password_1'):
                raise forms.ValidationError('This field is required.')
            if self.data.get('password_1') and self.data.get('password_2') and self.data['password_1'] != self.data['password_2']:
                raise forms.ValidationError('The passwords were not the same.')
            if xsftp.webui.models.Configuration.objects.all()[0].password_complexity:
                try:
                    cracklib.FascistCheck(self.data['password_1'])
                except ValueError, e:
                    raise forms.ValidationError("Bad password: %s" % e)
            return self.data['password_1']
        else:
            return ''

    def clean_password_2(self):
        if self.data.get('internal_auth'):
            if not self.data.get('password_2'):
                raise forms.ValidationError('This field is required.')
            return self.data['password_2']
        else:
            return ''

    def save(self):
        newuser = auth.models.User()
        newuser.username = self.cleaned_data.get('username')
        newuser.date_joined = time.strftime("%Y-%m-%d %H:%M:%S")
        newuser.is_active = True
        if self.data.get('internal_auth'):
            newuser.set_password(self.cleaned_data.get('password_1'))
        newuser.save()
        newuserprofile = xsftp.webui.models.UserProfile()
        newuserprofile.user = newuser
        newuserprofile.internal_auth = self.cleaned_data.get('internal_auth')
        newuserprofile.save()


class EditUserForm(forms.Form):
    user_id = forms.CharField(widget=forms.HiddenInput)
    username = forms.CharField(label="Username")
    internal_auth = forms.BooleanField(label="Local Account", help_text="<span style='color:orange'>Unchecking this will cause this user's locally-stored password, if one exists, to be erased.</span>", widget=forms.CheckboxInput(attrs={'onclick':'showPasswordFields();'}), required=False)
    first_name = forms.CharField(label="First Name", required=False)
    last_name = forms.CharField(label="Last Name", required=False)
    email = forms.EmailField(label="Email Address", required=False)
    is_staff = forms.BooleanField(label="Administrator", required = False)
    is_active = forms.BooleanField(label="Enabled", required=False, initial=True)
    expiry = MyDateField(label="Account Expiry", required=False)
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
#    change_password = forms.BooleanField(label="Change Password Next Login", required=False) #TODO implement in future release

    def __init__(self, is_administrator, requesting_user, *args, **kwargs):
        super(EditUserForm, self).__init__(*args, **kwargs)
        # if the user chose to edit the built-in admin account, then hide is_staff, is_active and expiry fields
        self.is_administrator = is_administrator
        self.requesting_user = requesting_user
        if is_administrator:
            self.fields['is_staff'].widget = self.fields['is_active'].widget = self.fields['expiry'].widget = self.fields['internal_auth'].widget = forms.widgets.HiddenInput()
        # if requesting_user is the builtin admin, the targeted user for editing is NOt the built in admin and demo mode is on:
        if requesting_user.id == 1 and not is_administrator and xsftp.webui.models.Configuration.objects.all()[0].demo_mode:
            # display the is_demo_user toggle
            self.fields['is_demo_user'] = forms.BooleanField(label="Demo User", required = False)

    def clean_username(self):
        submittedUsername = self.data.get('username')
        original_username = User.objects.get(id=self.data.get('user_id')).username
        if submittedUsername == original_username:
            return submittedUsername
        if User.objects.filter(username=submittedUsername):
            raise forms.ValidationError('The username already exists')
        if not VALID_USERNAME_PATTERN.search(submittedUsername):
            raise forms.ValidationError('The username contains illegal characters')
        try:
            pwd.getpwnam(submittedUsername)
        except KeyError:
            return submittedUsername
        raise forms.ValidationError('This username is reserved and is not available for use.')

    def clean_email(self):
        submittedEmail = self.data.get('email').strip()
        if submittedEmail and not VALID_EMAIL_ADDRESS_PATTERN.search(submittedEmail):
            raise forms.ValidationError('Please enter a valid email address')
        return submittedEmail

    def save(self):
        # get existing User object
        existinguser = User.objects.get(id=self.data.get('user_id'))
        # get existint UserProfile object
        existinguserprofile = existinguser.userprofile
        # if the username is about to be changed, then their home directory name will change as a result. Copy the old user's ~/.ssh directory to TRANSIENT_KEY_PATH/newUsername/
        # models.dbCommit will see that directory and restore the old pubkeys it in the new user's ~/.ssh/
        newUsername = self.cleaned_data.get('username')
        oldUsername = existinguser.username
        if newUsername != oldUsername:
            backupCommand = "sudo %swww/xsftp/webui/privexec.py --backup=%s,%s > /dev/null 2>&1 " % (xsftp.common.constants.APPDIR, oldUsername, newUsername)
            os.system(backupCommand)
        # populate its fields
        existinguser.username = newUsername
        existinguser.first_name = self.cleaned_data.get('first_name')
        existinguser.last_name = self.cleaned_data.get('last_name')
        existinguser.email = self.cleaned_data.get('email')
        # only save the below if the user being edited is not the built-in administrator account.
        if not self.is_administrator:
            existinguser.is_staff = self.cleaned_data.get('is_staff')
            existinguser.is_active = self.cleaned_data.get('is_active')
            existinguserprofile.expiry = self.cleaned_data.get('expiry')
            existinguserprofile.internal_auth = self.cleaned_data.get('internal_auth')
            # remove the linux and Django password if internal auth is False:
            if not self.cleaned_data.get('internal_auth'):
                rmPasswdCommand = "sudo %swww/xsftp/webui/privexec.py --erasepasswd=%s > /dev/null 2>&1 " % (xsftp.common.constants.APPDIR, newUsername)
                os.system(rmPasswdCommand)
                existinguser.set_password(None)
            if xsftp.webui.models.Configuration.objects.all()[0].demo_mode:
                existinguserprofile.is_demo_user = self.cleaned_data.get('is_demo_user')
        # save modified User object
        existinguser.save()
        # populate its fields
        existinguserprofile.comment = self.cleaned_data.get('comment')
#        existinguserprofile.change_password = self.cleaned_data.get('change_password') #TODO implement in future release
        # save modified USerProfile object
        existinguserprofile.save()


class EditProfileForm(forms.Form):
    user_id = forms.CharField(widget=forms.HiddenInput)
    first_name = forms.CharField(label="First Name", required=False)
    last_name = forms.CharField(label="Last Name", required=False)
    email = forms.EmailField(label="Email Address", required=False)
    
    def save(self):
        existingUser = User.objects.get(id=self.data.get('user_id'))
        existingUser.first_name = self.data.get('first_name')
        existingUser.last_name = self.data.get('last_name')
        existingUser.email = self.data.get('email')
        existingUser.save()

class ChangeUserPasswordForm(forms.Form):
    new_password_1 = PasswordField(label="New Password")
    new_password_2 = PasswordField(label="Verify New Password")

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangeUserPasswordForm, self).__init__(*args, **kwargs)

    def clean_new_password_1(self):
        if self.data.get('new_password_1') and self.data.get('new_password_2') and self.data['new_password_1'] != self.data['new_password_2']:
            raise forms.ValidationError('The new passwords were not the same.')
        if xsftp.webui.models.Configuration.objects.all()[0].password_complexity:
            try:
                cracklib.FascistCheck(self.data['new_password_1'])
            except ValueError, e:
                raise forms.ValidationError("Bad password: %s" % e)
        return self.data['new_password_1']

# ******************************
#          Group Forms
# ******************************


class NewGroupForm(forms.Form):
    group_name = forms.CharField(label="Group Name")
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    alertable = forms.BooleanField(label="Alertable", initial=False, required=False)

    def clean_group_name(self):
        submittedGroupname = self.data.get('group_name')
        if xsftp.webui.models.xGroup.objects.filter(group_name=submittedGroupname):
            raise forms.ValidationError('The group name already exists')
        if not VALID_GROUPNAME_PATTERN.search(submittedGroupname):
            raise forms.ValidationError('The group name contains illegal characters')
        return self.data.get('group_name')

    def save(self):
        newgroup = xsftp.webui.models.xGroup()
        newgroup.group_name = self.cleaned_data.get('group_name')
        newgroup.created = time.strftime("%Y-%m-%d %H:%M:%S")
        newgroup.comment = self.cleaned_data.get('comment')
        newgroup.alertable = self.cleaned_data.get('alertable')
        newgroup.save()


class EditGroupForm(forms.Form):
    id = forms.CharField(widget=forms.HiddenInput)
    group_name = forms.CharField(label="Group Name")
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    alertable = forms.BooleanField(label="Alertable", required=False)
    users = forms.MultipleChoiceField(required=False, label="Members", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    

    def __init__(self, *args, **kwargs):
        newargs = list(args[:])
        if newargs:
            data = newargs[0]
        elif "data" in kwargs.keys():
            data = kwargs["data"]
        else:
            data = None
        # If "data" is a Group object
        if isinstance(data, xsftp.webui.models.xGroup):
            newdata = data.__dict__.copy()
            newdata["users"] = [user.id for user in data.users.get_query_set()]
            if newargs:
                newargs[0] = newdata
            else:
                kwargs["data"] = newdata
        super(EditGroupForm, self).__init__(*newargs, **kwargs)
        # update the multiselect forms choices with the current user list in the 2-tuple choices format (value, label) where value is the value attribure of the <option> html tag, and label is the actual text to display
        self.fields['users'].choices = [(user.id, user.username) for user in auth.models.User.objects.all()]

    def clean_group_name(self):
        submittedGroupname = self.data.get('group_name')
        original_group_name = xsftp.webui.models.xGroup.objects.get(id=self.data.get('id')).group_name
        if original_group_name != submittedGroupname and xsftp.webui.models.xGroup.objects.filter(group_name=submittedGroupname):
            # error: they tried to change group name to something that already exists.
            raise forms.ValidationError('The group name already exists')
        if not VALID_GROUPNAME_PATTERN.search(submittedGroupname):
            raise forms.ValidationError('The group name contains illegal characters')
        return self.data.get('group_name')

    def save(self):
        # get existing group object
        existinggroup = xsftp.webui.models.xGroup.objects.get(id=self.data.get('id'))
        # populate its fields
        existinggroup.group_name = self.cleaned_data.get('group_name')
        existinggroup.comment = self.cleaned_data.get('comment')
        existinggroup.alertable = self.cleaned_data.get('alertable')
        # generate list of user id's from the submitted new members list which is in the form of [User.username, ...]
        #new_member_ids = [User.objects.get(id=uid).id for uid in self.cleaned_data.get('users')]
        # save new member list to the user manytomany field attribute
        existinggroup.users = self.cleaned_data.get('users')
        existinggroup.save()



# ******************************
#       ServerLink Forms
# ******************************

server_types =     [('sftp', 'SFTP (SSH File Transfer Protocol)'),
                    ('ftp', 'FTP (File Transfer Protocol)'),
                    ('cifs', 'CIFS (Windows Share)'),
                   ]

class NewServerForm(forms.Form):
    server_name = forms.CharField(label="Server Link Name")
    type = forms.ChoiceField(server_types, label='Server Link Type', widget=forms.Select(attrs={'onclick':'showType();'}))
    enabled = forms.BooleanField(label="Enabled", initial=True, required=False)
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    address = forms.CharField(label="Address", required=False)
    port = forms.IntegerField(label="Port", initial="22", required=False, help_text="Standard port for SFTP is 22")
    cifs_port = forms.IntegerField(label="Port", initial="445", required=False, help_text="Standard port for CIFS is 445 or 139")
    ftp_port = forms.IntegerField(label="Port", initial="21", required=False, help_text="Standard port for FTP is 21 (FTP and FTPES), or 990 (FTPS)")
    remote_user = forms.CharField(label="Remote User", required=True)
    cifs_password = PasswordField(label="Password", required=False)
    cifs_share = forms.CharField(label="Share Name", required=False)
    ftp_password = PasswordField(label="Password", required=False)
    ftp_passive = forms.BooleanField(label="FTP Passive Mode", initial=True, required=False)
    ftp_encryption = forms.ChoiceField([('0', 'None (Standard FTP)'), ('1', 'Explicit SSL/TLS (FTPES)'), ('2', 'Implicit SSL/TLS (FTPS)')], label='FTP Encryption')
    remote_path = forms.CharField(label="Remote Path", required=False)
    
    def __init__(self, *args, **kwargs):
        super(NewServerForm, self).__init__(*args, **kwargs)
        self.type = self.data.get('type')

    def clean_type(self):
        submittedType = self.data.get('type')
        if submittedType not in [type[0] for type in server_types]:
            raise forms.ValidationError('Please select a valid Server Link type')
        return submittedType

    def clean_ftp_encryption(self):
        if self.data.get('ftp_encryption') not in [str(i) for i in range(3)]:
            raise forms.ValidationError('Please select a valid FTP Encryption type')
        return self.data.get('ftp_encryption')

    def clean_server_name(self):
        submittedServerName = self.data.get('server_name')
        if xsftp.webui.models.Server.objects.filter(server_name=submittedServerName):
            raise forms.ValidationError('The Server Link name already exists')
        if not VALID_SERVERLINKNAME_PATTERN.search(submittedServerName):
            raise forms.ValidationError('The Server Link name contains illegal characters')
        return self.data.get('server_name')

    def clean_address(self):
        submittedAddress = self.data.get('address')
        if not VALID_IP_ADDRESS_PATTERN.search(submittedAddress) and not VALID_FQDN_PATTERN.search(submittedAddress):
            raise forms.ValidationError('Please enter a valid IP Address or Fully Qualified Domain Name')
        return submittedAddress

    def clean_port(self):
        submittedPort = self.data.get('port')
        if self.type == 'sftp':
            try:
                port = int(submittedPort)
            except ValueError:
                raise forms.ValidationError('Please enter a valid port number')
            if not 0 < port < 65535:
                raise forms.ValidationError('Please enter a valid port number')
        return submittedPort

    def clean_cifs_port(self):
        submittedPort = self.data.get('cifs_port')
        if self.type == 'cifs':
            try:
                port = int(submittedPort)
            except ValueError:
                raise forms.ValidationError('Please enter a valid port number')
            if not 0 < port < 65535:
                raise forms.ValidationError('Please enter a valid port number')
        return submittedPort

    def clean_ftp_port(self):
        submittedPort = self.data.get('ftp_port')
        if self.type == 'ftp':
            try:
                port = int(submittedPort)
            except ValueError:
                raise forms.ValidationError('Please enter a valid port number')
            if not 0 < port < 65535:
                raise forms.ValidationError('Please enter a valid port number')
        return submittedPort

    def clean_ftp_password(self):
        submittedFTPPassword = self.data.get('ftp_password')
        if self.type == 'ftp' and not submittedFTPPassword:
            raise forms.ValidationError('Please enter a valid password')
        return submittedFTPPassword

    def clean_remote_path(self):
        submittedRemotePath = self.data.get('remote_path')
        if submittedRemotePath and not VALID_PATH_PATTERN.search(submittedRemotePath):
            raise forms.ValidationError('Please enter a valid path name')
        return submittedRemotePath

    def clean_remote_user(self):
        submittedRemoteUser = self.data.get('remote_user')
        if not submittedRemoteUser:
            raise forms.ValidationError('Please enter a Remote User')
        return submittedRemoteUser

    def clean_cifs_share(self):
        submittedShareName = self.data.get('cifs_share')
        if self.type == 'cifs' and not submittedShareName or not VALID_CIFS_SHARE_PATTERN.search(submittedShareName):
            raise forms.ValidationError('Please enter a valid share name')
        return submittedShareName.strip()

    def save(self):
        newserver = xsftp.webui.models.Server()
        newserver.server_name = self.cleaned_data.get('server_name')
        newserver.type = self.cleaned_data.get('type')
        newserver.created = time.strftime("%Y-%m-%d %H:%M:%S")
        newserver.comment = self.cleaned_data.get('comment')
        newserver.address = self.cleaned_data.get('address')
        newserver.cifs_port = self.cleaned_data.get('cifs_port')
        newserver.cifs_password = self.cleaned_data.get('cifs_password')
        newserver.cifs_share = self.cleaned_data.get('cifs_share')
        newserver.ftp_port = self.cleaned_data.get('ftp_port')
        newserver.ftp_password = self.cleaned_data.get('ftp_password')
        newserver.ftp_passive = self.cleaned_data.get('ftp_passive')
        # derive ftp_ssl and ftp_ssl_implicit values
        ftp_encryption = self.cleaned_data.get('ftp_encryption')
        if ftp_encryption == "0":
            newserver.ftp_ssl = False
        elif ftp_encryption == "1":
            newserver.ftp_ssl = True
        elif ftp_encryption == "2":
            newserver.ftp_ssl = True
            newserver.ftp_ssl_implicit = True
        newserver.port = self.cleaned_data.get('port')
        newserver.remote_user = self.cleaned_data.get('remote_user')
        newserver.remote_path = self.cleaned_data.get('remote_path')
        newserver.save()
    

class EditServerForm(forms.Form):
    id = forms.CharField(widget=forms.HiddenInput)
    server_name = forms.CharField(label="Server Link Name")
    type = forms.ChoiceField(server_types, label='Server Link Type', widget=forms.Select(attrs={'onclick':'showType();'}))
    enabled = forms.BooleanField(label="Enabled", required=False)
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    address = forms.CharField(label="Address", required=False)
    port = forms.IntegerField(label="Port", required=False, help_text="Standard port for SFTP is 22")
    cifs_port = forms.IntegerField(label="Port", initial="139", required=False, help_text="Standard ports for CIFS are 139 and 445")
    ftp_port = forms.IntegerField(label="Port", initial="21", required=False, help_text="Standard ports for FTP are 21 (FTP and FTPES), and 990 (FTPS)")
    remote_user = forms.CharField(label="Remote User", required=True)
    cifs_password = PasswordField(label="Password", required=False, help_text="Leave blank to leave password unchanged")
    cifs_share = forms.CharField(label="Share Name", required=False)
    ftp_password = PasswordField(label="Password", required=False, help_text="Leave blank to leave password unchanged")
    ftp_passive = forms.BooleanField(label="FTP Passive Mode", initial=True, required=False)
    ftp_encryption = forms.ChoiceField([('0', 'None (Standard FTP)'), ('1', 'Explicit SSL/TLS (FTPES)'), ('2', 'Implicit SSL/TLS (FTPS)')], label='FTP Encryption')
    remote_path = forms.CharField(label="Remote Path", required=False)
    read_users = forms.MultipleChoiceField(required=False, label="Read Users", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    write_users = forms.MultipleChoiceField(required=False, label="Write Users", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    read_groups = forms.MultipleChoiceField(required=False, label="Read Groups", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    write_groups = forms.MultipleChoiceField(required=False, label="Write Groups", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    
    def __init__(self, *args, **kwargs):
        # args is immutable, but we want to modify it, so make a copy as a list
        newargs = list(args[:])
        if newargs:
            data = newargs[0]
        elif "data" in kwargs.keys():
            data = kwargs["data"]
        else:
            data = None
        # If data is a Server object
        if isinstance(data, xsftp.webui.models.Server):
            newdata = data.__dict__.copy()
            # Assign lists of users/groups to the appropriate keys in newdata
            newdata["read_users"] = [user.id for user in data.read_users.get_query_set()]
            newdata["read_groups"] = [group.id for group in data.read_groups.get_query_set()]
            # Now do the same for write groups
            newdata["write_users"] = [user.id for user in data.write_users.get_query_set()]
            newdata["write_groups"] = [group.id for group in data.write_groups.get_query_set()]
            # derive and insert the correct value into the ftp_encryption field
            if not newdata.get('ftp_ssl'):
                newdata['ftp_encryption'] = '0'
            else:
                if not newdata.get('ftp_ssl_implicit'):
                    newdata['ftp_encryption'] = '1'
                else:
                    newdata['ftp_encryption'] = '2'
            # Finally, replace the appropriate arguments
            if newargs:
                newargs[0] = newdata
            else:
                kwargs["data"] = newdata
        super(EditServerForm, self).__init__(*newargs, **kwargs)
        self.fields['read_users'].choices = [(user.id, user.username) for user in User.objects.all()]
        self.fields['write_users'].choices = [(user.id, user.username) for user in User.objects.all()]
        self.fields['read_groups'].choices = [(group.id, group.group_name) for group in xsftp.webui.models.xGroup.objects.all()]
        self.fields['write_groups'].choices = [(group.id, group.group_name) for group in xsftp.webui.models.xGroup.objects.all()]
        self.type = self.data.get('type')

    def clean_type(self):
        submittedType = self.data.get('type')
        if submittedType not in [type[0] for type in server_types]:
            raise forms.ValidationError('Please select a valid Server Link type')
        return submittedType

    def clean_ftp_encryption(self):
        if self.data.get('ftp_encryption') not in [str(i) for i in range(3)]:
            raise forms.ValidationError('Please select a valid FTP Encryption type')
        return self.data.get('ftp_encryption')

    def clean_server_name(self):
        original_server_name = xsftp.webui.models.Server.objects.get(id=self.data.get('id')).server_name
        submittedServerName = self.data.get('server_name')
        if original_server_name != submittedServerName and xsftp.webui.models.Server.objects.filter(server_name=submittedServerName):
            # error: they tried to change server name to something that already exists.
            raise forms.ValidationError('The Server Link name already exists')
        if not VALID_SERVERLINKNAME_PATTERN.search(submittedServerName):
            raise forms.ValidationError('The Server Link name contains illegal characters')
        return self.data.get('server_name')

    def clean_address(self):
        submittedAddress = self.data.get('address')
        if not VALID_IP_ADDRESS_PATTERN.search(submittedAddress) and not VALID_FQDN_PATTERN.search(submittedAddress):
            raise forms.ValidationError('Please enter a valid IP Address or Fully Qualified Domain Name')
        return submittedAddress

    def clean_port(self):
        submittedPort = self.data.get('port')
        if self.type == 'sftp':
            try:
                port = int(submittedPort)
            except ValueError:
                raise forms.ValidationError('Please enter a valid port number')
            if not 0 < port < 65535:
                raise forms.ValidationError('Please enter a valid port number')
        return submittedPort

    def clean_cifs_port(self):
        submittedPort = self.data.get('cifs_port')
        if self.type == 'cifs':
            try:
                port = int(submittedPort)
            except ValueError:
                raise forms.ValidationError('Please enter a valid port number')
            if not 0 < port < 65535:
                raise forms.ValidationError('Please enter a valid port number')
        return submittedPort

    def clean_ftp_port(self):
        submittedPort = self.data.get('ftp_port')
        if self.type == 'ftp':
            try:
                port = int(submittedPort)
            except ValueError:
                raise forms.ValidationError('Please enter a valid port number')
            if not 0 < port < 65535:
                raise forms.ValidationError('Please enter a valid port number')
        return submittedPort

    def clean_ftp_password(self):
        submittedFTPPassword = self.data.get('ftp_password')
        if self.type == 'ftp' and not submittedFTPPassword:
            submittedFTPPassword = xsftp.webui.models.Server.objects.get(id=self.data.get('id')).ftp_password
        return submittedFTPPassword

    def clean_remote_path(self):
        submittedRemotePath = self.data.get('remote_path')
        if submittedRemotePath and not VALID_PATH_PATTERN.search(submittedRemotePath):
            raise forms.ValidationError('Please enter a valid path name')
        return submittedRemotePath

    def clean_remote_user(self):
        submittedRemoteUser = self.data.get('remote_user')
        if not submittedRemoteUser:
            raise forms.ValidationError('Please enter a Remote User')
        return submittedRemoteUser

    def clean_cifs_share(self):
        submittedShareName = self.data.get('cifs_share')
        if self.type == 'cifs' and not submittedShareName or not VALID_CIFS_SHARE_PATTERN.search(submittedShareName):
            raise forms.ValidationError('Please enter a valid share name')
        return submittedShareName.strip()

    def clean_cifs_password(self):
        submitted_cifs_password = self.data.get('cifs_password')
        if self.type == 'cifs' and not submitted_cifs_password:                                             
            submitted_cifs_password = xsftp.webui.models.Server.objects.get(id=self.data.get('id')).cifs_password
        return submitted_cifs_password

    def save(self):
        server_reset = False
        server = xsftp.webui.models.Server.objects.get(id=self.cleaned_data.get('id'))
        # populate its fields
        server.server_name = self.cleaned_data.get('server_name')
        # if server was disabled and is now enabled, set its status to 2 (MPSTATE_SM_BROKEN)
        if not server.enabled and self.cleaned_data.get('enabled'):
            server.status = 2 
        # else if server was enabled and still is enabled and was unused
        elif server.enabled and self.cleaned_data.get('enabled') and server.status == -10:
            # set status to 2 - if it stil is not being used, the server.save() method in models will flick it back to -10 unused.
            server.status = 2
        server.enabled = self.cleaned_data.get('enabled')
        server.comment = self.cleaned_data.get('comment')
        # reset server link if the type has changed
        old_type = server.type
        new_type = self.cleaned_data.get('type')
        if new_type != old_type:
            server.type = new_type
            server_reset = True
        # reset server link if the ftp_password has changed
        old_ftp_password = server.ftp_password
        new_ftp_password = self.cleaned_data.get('ftp_password')
        if new_ftp_password != old_ftp_password:
            server.ftp_password = new_ftp_password
            server_reset = True
        # reset server link if the ftp_port has changed
        old_ftp_port = server.ftp_port
        new_ftp_port = self.cleaned_data.get('ftp_port')
        if new_ftp_port != old_ftp_port:
            server.ftp_port = new_ftp_port
            server_reset = True
        # reset server link if the ftp_encryption value has changed
        old_ftp_ssl = server.ftp_ssl
        # derive the values for ftp_ssl and ftp_ssl_implicit
        ftp_encryption = self.cleaned_data.get('ftp_encryption')
        if ftp_encryption == '0':
            new_ftp_ssl = False
            new_ftp_ssl_implicit = False
        elif ftp_encryption == '1':
            new_ftp_ssl = True
            new_ftp_ssl_implicit = False
        elif ftp_encryption == '2':
            new_ftp_ssl = True
            new_ftp_ssl_implicit = True
        else: #should never happen (above validation ensures that only 0, 1 or 2 come through), but just assign values for FTPES as a failsafe
            new_ftp_ssl = True
            new_ftp_ssl_implicit = False
        if     new_ftp_ssl != old_ftp_ssl or\
            new_ftp_ssl == old_ftp_ssl == True and new_ftp_ssl_implicit != old_ftp_ssl:
            server_reset = True
        server.ftp_ssl = new_ftp_ssl
        server.ftp_ssl_implicit = new_ftp_ssl_implicit
        # reset server link if the ftp_passive value has changed
        old_ftp_passive = server.ftp_passive
        new_ftp_passive = self.cleaned_data.get('ftp_passive')
        if new_ftp_passive != old_ftp_passive:
            server.ftp_passive = new_ftp_passive
            server_reset = True
        # reset server link if the cifs_password has changed
        old_cifs_password = server.cifs_password
        new_cifs_password = self.cleaned_data.get('cifs_password')
        if new_cifs_password != old_cifs_password:
            server.cifs_password = new_cifs_password
            server_reset = True
        # reset server if cifs_share has changed
        old_cifs_share = server.cifs_share
        new_cifs_share = self.cleaned_data.get('cifs_share')
        if new_cifs_share != old_cifs_share:
            server.cifs_share = new_cifs_share
            server_reset = True
        # reset server if cifs_port has changed
        old_cifs_port = server.cifs_port
        new_cifs_port = self.cleaned_data.get('cifs_port')
        if new_cifs_port != old_cifs_port:
            server.cifs_port = new_cifs_port
            server_reset = True
        # reset server link if the server's sftp address has changed
        old_address = server.address
        new_address = self.cleaned_data.get('address')
        if new_address != old_address:
            server.address = new_address
            server_reset = True
        # reset server link if the server's sftp port has changed
        old_port = server.port
        new_port = self.cleaned_data.get('port')
        if new_port != old_port:
            server.port = new_port
            server_reset = True
        # reset server link if remote_user has changed
        old_remote_user = server.remote_user
        new_remote_user = self.cleaned_data.get('remote_user')
        if new_remote_user != old_remote_user:
            server.remote_user = new_remote_user
            server_reset = True
        # reset server link if remote_path has changed
        old_remote_path = server.remote_path
        new_remote_path = self.cleaned_data.get('remote_path')
        if new_remote_path != old_remote_path:
            server.remote_path = new_remote_path
            server_reset = True
        # save the rest of the server link's atributes (these ones don't require a server link reset)
        server.read_users = self.cleaned_data.get('read_users')
        server.write_users = self.cleaned_data.get('write_users')
        server.read_groups = self.cleaned_data.get('read_groups')
        server.write_groups = self.cleaned_data.get('write_groups')
        # reset the server link if necessary
        if server_reset:
            resetCommand = 'sudo %swww/xsftp/webui/privexec.py --reset=%s > /dev/null 2>&1' % (xsftp.common.constants.APPDIR, server.id)
            os.system(resetCommand)
        # save the new server object
        server.save()


# ******************************
#         Script Forms
# ******************************


class NewScriptForm(forms.Form):
    script_name = forms.CharField(label="Script Name")
    file = forms.FileField(help_text="Note: Please ensure that the script file name does not contain any whitespace.")
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    
    def clean_script_name(self):
        submittedScriptName = self.data.get('script_name')
        if xsftp.webui.models.Script.objects.filter(script_name=submittedScriptName):
            raise forms.ValidationError('A script with this name already exists')
        if not VALID_SCRIPTNAME_PATTERN.search(submittedScriptName):
            raise forms.ValidationError('The Script name contains illegal characters')
        return self.data.get('script_name')

    def clean_file(self):
        submittedFilename = self.cleaned_data.get('file').name
        if not VALID_FILENAME_PATTERN.search(submittedFilename):
            raise forms.ValidationError('The file name contained illegal characters')
        return self.cleaned_data.get('file')

    def save(self):
        newscript = xsftp.webui.models.Script()
        newscript.script_name = self.cleaned_data.get('script_name')
        newscript.comment = self.cleaned_data.get('comment')
        fileObj = self.cleaned_data.get('file')
        newscript.file = fileObj
        newscript.save()
        # set execute perms on the script
        absScriptFileName =  xsftp.webui.constants.SCRIPT_PATH + fileObj.name
        setExecCmd = "/bin/chmod +x %s" % absScriptFileName
        os.system(setExecCmd)


class EditScriptForm(forms.Form):
    id = forms.CharField(widget=forms.HiddenInput)
    script_name = forms.CharField(label="Script Name")
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    file = forms.FileField(label="Change File", required=False)
    execUsers = forms.MultipleChoiceField(required=False, label="Exec Users", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    execGroups = forms.MultipleChoiceField(required=False, label="Exec Groups", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))

    # __init__ will either get a querydict or an object, and we detect and use either to populate fields and their arguments
    def __init__(self, *args, **kwargs):
        '''
        this __init__ can accept either a HTTP_POST dictionary, OR a Script object, for the "data" argument
        '''
        # If __init__ is passed a "Script" object, then a fake "HTTP_POST"-like dictionary must be created in order to pass up to the parent __init__ in forms.Form
        # args is immutable, but we want to modify it, so make a copy as a list 
        newargs = list(args[:])
        # If newargs (ie, *args), is not empty, then it's first element MUST correspond to the "data" argument (as per definitiion of __init__ in forms.Form)
        if newargs:
            data = newargs[0]
        # Else, maybe the "data" argument was passed as a keyword?
        elif "data" in kwargs.keys():
            data = kwargs["data"]
        else:
            data = None
        # If data is a Script object
        if isinstance(data, xsftp.webui.models.Script):
            newdata = data.__dict__.copy()
            # Assign lists of users/groups to the appropriate keys in newdata
            newdata["execUsers"] = [user.id for user in data.execUsers.get_query_set()]
            newdata["execGroups"] = [group.id for group in data.execGroups.get_query_set()]
            # Finally, replace the appropriate arguments
            if newargs:
                newargs[0] = newdata
            else:
                kwargs["data"] = newdata
        super(EditScriptForm, self).__init__(*newargs, **kwargs)
        self.fields['execUsers'].choices = [(user.id, user.username) for user in User.objects.all()]
        self.fields['execGroups'].choices = [(group.id, group.group_name) for group in xsftp.webui.models.xGroup.objects.all()]
        # if data is not None, populate the help_text on the file field, otherwise dont.
        if data:
            if isinstance(data, xsftp.webui.models.Script):
                # data is the script object
                script = data
            else:
                # data is a query_dict, grab the associated secript object.
                script = xsftp.webui.models.Script.objects.get(id=data["id"])
            self.fields['file'].help_text = "Currently: <a href='/scripts/get/%s/'>%s</a>" % (script.id, script.get_basename())

    def clean_file(self):
        # make sure the filename doesnt contain any nasty or illegal characters
        if self.cleaned_data['file']:
            submittedFilename = self.cleaned_data.get('file').name
            if not VALID_FILENAME_PATTERN.search(submittedFilename):
                # illegal characters detected in file, reject it
                raise forms.ValidationError('The file name contained illegal characters')
        return self.cleaned_data.get('file')

    def clean_script_name(self):
        original_script_name = xsftp.webui.models.Script.objects.get(id=self.data.get('id')).script_name
        submittedScriptName = self.data.get('script_name')
        if original_script_name != submittedScriptName and xsftp.webui.models.Script.objects.filter(script_name=submittedScriptName):
            # error: they tried to change script name to something that already exists.
            raise forms.ValidationError('The script name already exists')
        if not VALID_SCRIPTNAME_PATTERN.search(submittedScriptName):
            raise forms.ValidationError('The Script name contains illegal characters')
        return self.data.get('script_name')

    def save(self):
        # messages is a list of strings to render in putmessage back in the view
        messages = []
        script = xsftp.webui.models.Script.objects.get(id=self.cleaned_data.get('id'))
        # populate its fields
        script.script_name = self.cleaned_data.get('script_name')
        script.comment = self.cleaned_data.get('comment')
        script.execUsers = self.cleaned_data.get('execUsers')
        script.execGroups = self.cleaned_data.get('execGroups')
        # if they submitted a new script file
        new_script = False
        if self.cleaned_data["file"]:
            # if the newly submitted script file was modified, save it, otherwise skip it.
            existingScriptFile = open(script.file.path, "r")
            existingScriptFileContent = existingScriptFile.read()
            existingScriptFile.close()
            submittedScriptFileContent = self.cleaned_data.get('file').read()
            # if the submitted script file differes in content to the existing script file
            if existingScriptFileContent != submittedScriptFileContent:
                new_script = True
                # delete the old script file as django's filestorage tacks a _1 on the end if the filename overlaps
                os.unlink(script.file.path)
                # attach the new file to the script
                script.file = self.cleaned_data.get('file')
            else:
                messages.append("The script file you submitted is the same as the existing one and has been left unchanged.")
        
        # save the modified script to the db
        script.save()
        if new_script:
            # set execute perms on the script file
            setExecCmd = '/bin/chmod +x "%s"' % script.file.path
            os.system(setExecCmd)
        return messages


# ******************************
#         Job Forms
# ******************************


class GlobForm(forms.Form):
    '''
    A form class for creating new Globs.
    '''
    glob = forms.CharField(label="Source Files")

    def save(self):
        globObject = xsftp.webui.models.Glob()
        globObject.glob = self.cleaned_data.get('glob')
        return globObject

    def clean_glob(self):
        # XXX - do we need to do any cleaning here?
        return self.data.get('%s-glob' % self.prefix)
        

class EditGlobForm(forms.Form):

    glob = forms.CharField(label="Source Files")

    def save(self):
        globObject = xsftp.webui.models.Glob()
        globObject.glob = self.cleaned_data.get('glob')
        return globObject

    def clean_glob(self):
        # XXX - do we need to do any cleaning here?
        return self.data.get('%s-glob' % self.prefix)


monthChoices = [
    ('1', "January"),
    ('2', "February"),
    ('3', "March"),
    ('4', "April"),
    ('5', "May"),
    ('6', "June"),
    ('7', "July"),
    ('8', "August"),
    ('9', "September"),
    ('10', "October"),
    ('11', "November"),
    ('12', "December"),
    ]

dowChoices = [
    ('1', "Monday"),
    ('2', "Tuesday"),
    ('3', "Wednesday"),
    ('4', "Thursday"),
    ('5', "Friday"),
    ('6', "Saturday"),
    ('7', "Sunday"),
    ]

minuteChoices = [
    ('0','first minute'),
    ('1','15th minute'),
    ('2','30th minute'),
    ('3','45th minute'),
    ]

class NewJobForm(forms.Form):
    #GENERAL
    job_name = forms.CharField(label="Job Name")
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    enabled = forms.BooleanField(label="Enabled", initial=True, required=False)
    #SCHEDULE DETAILS
    schedule_type = forms.ChoiceField([('0',"Run Once"), ('1',"Hourly"),('2',"Daily"),('3',"Weekly"),('4',"Monthly"),('5',"Yearly"),('6',"Advanced")], widget=forms.Select(attrs={'onclick':'showSchedule();'}))
    run_at =  MyBasicDateTimeField(label="Run At", required=False ) # activated only if run once is checked
    minute = forms.ChoiceField([('0',"On The Hour"),('1',"15th Minute"),('2',"30th Minute"),('3',"45th Minute")], label="Minute", required=False)
    hour = forms.ChoiceField(label="Hour", required=False, choices=[(str(x),str(x)) for x in range(24)])
    day = forms.ChoiceField(label="Day of Month", required=False, choices=[(str(x+1),str(x+1)) for x in range(31)])
    month = forms.ChoiceField(label="Month", required=False, choices=monthChoices)
    dow = forms.ChoiceField(label="Day of Week", required=False, choices=dowChoices)
    advanced = forms.CharField(label="Advanced", required=False)
    expiry = MyDateTimeField(label="Expiry", required=False)
    # TASK DETAILS
    source_server = forms.ChoiceField([], label="Source Server Link")
    #source_glob = forms.CharField(label="Source Files", required=False)
    dest_server = forms.ChoiceField([], label="Destination Server Link")
    dest_path = forms.CharField(label="Destination Path", required=False)
    delete_source = forms.BooleanField(label="Delete Source Files", initial=False, required=False)
    exist_action = forms.ChoiceField([('0',"Raise error"),('1',"Skip the file"),('2',"Overwrite destination"),('3',"Auto-increment filename")], label="If Destination Exists:")
    continue_on_error = forms.BooleanField(label="Continue on Error", initial=True, required=False)
    use_pre_script = forms.BooleanField(label="Use Pre-script", initial=False, required=False, widget=forms.CheckboxInput(attrs={'onclick':'showScripts();'}))
    pre_script = forms.ChoiceField([], required=False)
    use_post_script = forms.BooleanField(label="Use Post-script", initial=False, required=False, widget=forms.CheckboxInput(attrs={'onclick':'showScripts();'}))
    post_script =  forms.ChoiceField([], required=False)
    # ALERTING DETAILS
    alert_owner_on_success = forms.BooleanField(label="Alert me on Success", initial=False, required=False)
    alert_owner_on_fail = forms.BooleanField(label="Alert me on Failure", initial=True, required=False)
    suppress_group_alerts = forms.BooleanField(label="Suppress Group Alerts", initial=True, required=False, widget=forms.CheckboxInput(attrs={'onclick':'showSuppressGroupAlerts();'}))
    alert_groups_on_success = forms.MultipleChoiceField(required=False, label="Alert Groups on Success", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    alert_groups_on_fail = forms.MultipleChoiceField(required=False, label="Alert Groups on Failure", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))

    def __init__(self, user, *args, **kwargs):
        # call the parent's init
        super(NewJobForm, self).__init__(*args, **kwargs)
        # capture the user in the instance
        self.user = user
        # assign the user-specific field choices
        self.fields['source_server'].choices = [("", "Select one...")] + [(str(server.id), server.server_name) for server in  user.userprofile.getAllReadServers()]
        self.fields['dest_server'].choices = [("", "Select one...")] + [(str(server.id), server.server_name) for server in  user.userprofile.getEffectiveWriteServers()]
        self.fields['pre_script'].choices = self.fields['post_script'].choices = [("", "Select one...")] + [(str(script.id), script.script_name) for script in user.userprofile.getEffectiveScripts()]
        self.fields['alert_groups_on_success'].choices = self.fields['alert_groups_on_fail'].choices = [(str(group.id), group.group_name) for group in xsftp.webui.models.xGroup.objects.get_query_set().filter(alertable=True)]

    def clean_job_name(self):
        submittedJobName = self.data.get('job_name')
        if xsftp.webui.models.Job.objects.filter(job_name=submittedJobName):
            raise forms.ValidationError('The job name already exists')
        if not 1 < len(submittedJobName) < 65:
            raise forms.ValidationError('The job name must be between 1 and 64 characters')
        if not VALID_JOBNAME_PATTERN.search(submittedJobName):
            raise forms.ValidationError('The Job name contains illegal characters')
        return self.data.get('job_name')

    def clean_schedule_type(self):
        # ensure submitted value is between 0 and 6 incl.
        if self.data.get('schedule_type') not in [str(i) for i in range(7)]:
            raise forms.ValidationError('Please select a valid schedule type')
        return self.data.get('schedule_type')

    def clean_run_at(self):
        if self.data.get('schedule_type') == "0" and not self.data.get('run_at'):
            raise forms.ValidationError('This field is required.')
        # ensure it is properly formatted, and it is not set in the past
        try:
            #if self.data.get('schedule_type') == "0" and datetime(*strptime(self.data.get('run_at'), "%Y-%m-%d %H:%M")[0:6]) < datetime.now():
            if self.data.get('schedule_type') == "0" and self.cleaned_data.get('run_at') < datetime.now():
                raise forms.ValidationError("The specified date/time occurs in the past")
        except ValueError:
            raise forms.ValidationError("Enter a valid date/time in the form: YYYY-MM-DD hh:mm")
        return self.data.get('run_at')

    def clean_minute(self):
        # if schedule type isnt "runOnce" or "advanced", and they have tried to enter something other than whats available in the minute pull-down menu
        if self.data.get('schedule_type') not in ["0","6"] and self.data.get('minute') not in ["0","1","2","3"]:
            raise forms.ValidationError("Please choose a valid minute of the hour")
        return self.data.get('minute')

    def clean_hour(self):
        if self.data.get('schedule_type') not in ["0","1","6"] and self.data.get('hour') not in [str(x) for x in range(24)]: 
            raise forms.ValidationError("Please choose a valid hour of the day")
        return self.data.get('hour')

    def clean_day(self):
        # this is day of month
        if self.data.get('schedule_type') in ["4","5"] and self.data.get('day') not in [str(x) for x in range(1,32)]:
            raise forms.ValidationError("Please choose a valid day of the month")
        #if they specified a yearly schedule
        if self.data.get('schedule_type') == "5":
            # check that the specified day occurs at least once per leap year (using year 2000 as the leap year)
            try: datetime(2000, int(self.data.get('month')), int(self.data.get('day')))
            except: raise forms.ValidationError("The day you chose never occurs in the specified month")
        return self.data.get('day')

    def clean_month(self):
        if self.data.get('schedule_type') == "5" and self.data.get('month') not in [str(x) for x in range(1,13)]:
            raise forms.ValidationError("Please choose a valid day of the month")
        return self.data.get('month')

    def clean_dow(self):
        if self.data.get('schedule_type') == "3" and self.data.get('month') not in [str(x) for x in range(1,8)]:
            raise forms.ValidationError("Please choose a valid day of the week")
        return self.data.get('dow')

    def clean_advanced(self):
        if self.data.get('schedule_type') == "6":
            # ensure advanced field contains valid crontab formated string
            if not VALID_CRON_PATTERN.search(self.data.get('advanced')):
                raise forms.ValidationError("Please enter a valid cron-style schedule")
        return self.data.get('advanced')

    def clean_expiry(self):
        try:
            if self.data.get('schedule_type') != "0" and self.data.get('expiry') != "":
                if self.cleaned_data.get('expiry') < datetime.now():
                    raise forms.ValidationError("The specified date/time occurs in the past")
        except ValueError:
            raise forms.ValidationError("Enter a valid date/time in the form: YYYY-MM-DD hh:mm")
        return self.data.get('expiry')

    def clean_source_server(self):
        if self.data.get('source_server') not in [str(server.id) for server in self.user.userprofile.getAllReadServers()]:
            raise forms.ValidationError("Please choose a valid source server")
        return self.data.get('source_server')

    def clean_dest_server(self):
        if self.data.get('dest_server') not in [str(server.id) for server in  self.user.userprofile.getEffectiveWriteServers()]:
            raise forms.ValidationError("Please choose a valid destination server")
        return self.data.get('dest_server')

    def clean_exist_action(self):
        if self.data.get('exist_action') not in [str(x) for x in range(4)]:
            raise forms.ValidationError("Please choose a valid action")
        return self.data.get('exist_action')

    def clean_pre_script(self):
        if self.data.get('use_pre_script'):
            if self.data.get('pre_script') not in [str(script.id) for script in self.user.userprofile.getEffectiveScripts()]:
                raise forms.ValidationError("Please choose a valid pre-script")
        return self.data.get('pre_script')

    def clean_post_script(self):
        if self.data.get('use_post_script'):
            if self.data.get('post_script') not in [str(script.id) for script in self.user.userprofile.getEffectiveScripts()]:
                raise forms.ValidationError("Please choose a valid post-script")
        return self.data.get('post_script')

    def clean_alert_groups_on_success(self):
        if not self.data.get('suppress_group_alerts') and not self.data.get('alert_groups_on_success') and not self.data.get('alert_groups_on_fail'):
            raise forms.ValidationError("Please choose at least one valid group")
        return self.cleaned_data.get('alert_groups_on_success')

    def clean_alert_groups_on_fail(self):
        if not self.data.get('suppress_group_alerts') and not self.data.get('alert_groups_on_fail') and not self.data.get('alert_groups_on_success'):
            raise forms.ValidationError("Please choose at least one valid group")
        return self.cleaned_data.get('alert_groups_on_fail')


    def save(self):
        newjob = xsftp.webui.models.Job()
        newjob.run_count = 0
        newjob.owner = self.user
        newjob.errorFlags = -1
        newjob.job_name = self.cleaned_data.get('job_name')
        newjob.comment = self.cleaned_data.get('comment')
        newjob.enabled = self.cleaned_data.get('enabled')
        newjob.schedule_type = self.cleaned_data.get('schedule_type')
        newjob.run_at = self.cleaned_data.get('run_at') or None
        if newjob.schedule_type == '6': # advanced (cron-style schedule)
            newjob.minute, newjob.hour, newjob.day, newjob.month, newjob.dow = self.cleaned_data.get('advanced').split()
        else:
            newjob.minute = self.cleaned_data.get('minute')
            newjob.hour = self.cleaned_data.get('hour')
            newjob.day = self.cleaned_data.get('day')
            newjob.month = self.cleaned_data.get('month')
            newjob.dow = self.cleaned_data.get('dow')
        newjob.expiry = self.cleaned_data.get('expiry') or None
        newjob.source_server = xsftp.webui.models.Server.objects.get(id = int(self.cleaned_data.get('source_server')))
        newjob.dest_server = xsftp.webui.models.Server.objects.get(id = int(self.cleaned_data.get('dest_server')))
        newjob.dest_path = self.cleaned_data.get('dest_path')
        newjob.delete_source = self.cleaned_data.get('delete_source')
        newjob.exist_action = self.cleaned_data.get('exist_action')
        newjob.continue_on_error = self.cleaned_data.get('continue_on_error')
        newjob.use_pre_script = self.cleaned_data.get('use_pre_script')
        if self.cleaned_data.get('pre_script'): newjob.pre_script = xsftp.webui.models.Script.objects.get(id=int(self.cleaned_data.get('pre_script')))
        newjob.use_post_script = self.cleaned_data.get('use_post_script')
        if self.cleaned_data.get('post_script'): newjob.post_script = xsftp.webui.models.Script.objects.get(id=int(self.cleaned_data.get('post_script')))
        newjob.alert_owner_on_success = self.cleaned_data.get('alert_owner_on_success')
        newjob.alert_owner_on_fail = self.cleaned_data.get('alert_owner_on_fail')
        newjob.suppress_group_alerts = self.cleaned_data.get('suppress_group_alerts')
        # save the job before assigning the m2m field
        newjob.save()
        newjob.alert_groups_on_success = self.cleaned_data.get('alert_groups_on_success')
        newjob.alert_groups_on_fail = self.cleaned_data.get('alert_groups_on_fail')
        newjob.save()
        return newjob



class EditJobForm(forms.Form):
    job_name = forms.CharField(label="Job Name")
    job_owner = forms.ChoiceField([], required=False, label="Job Owner")
    comment = forms.CharField(label="Comment", required=False, widget=forms.widgets.Textarea)
    enabled = forms.BooleanField(label="Enabled", required=False)
    #SCHEDULE DETAILS
    schedule_type = forms.ChoiceField([("0","Run Once"), ("1","Hourly"),("2","Daily"),("3","Weekly"),("4","Monthly"),("5","Yearly"),("6","Advanced")], widget=forms.Select(attrs={'onclick':'showSchedule();'}))
    run_at =  MyBasicDateTimeField(label="Run At", required=False ) # activated only if run once is checked
    minute = forms.ChoiceField([("0","On The Hour"),("1","15th Minute"),("2","30th Minute"),("3","45th Minute")], label="Minute", required=False)
    hour = forms.ChoiceField(label="Hour", required=False, choices=[(str(x),str(x)) for x in range(24)])
    day = forms.ChoiceField(label="Day of Month", required=False, choices=[(str(x+1),str(x+1)) for x in range(31)])
    month = forms.ChoiceField(label="Month", required=False, choices=monthChoices)
    dow = forms.ChoiceField(label="Day of Week", required=False, choices=dowChoices)
    advanced = forms.CharField(label="Advanced", required=False)
    expiry = MyDateTimeField(label="Expiry", required=False)
    # TASK DETAILS
    source_server = forms.ChoiceField([], label="Source Server Link", required=False)
    dest_server = forms.ChoiceField([], label="Destination Server Link", required=False)
    dest_path = forms.CharField(label="Destination Path", required=False)
    delete_source = forms.BooleanField(label="Delete Source Files", required=False)
    exist_action = forms.ChoiceField([('0',"Raise error"),('1',"Skip the file"),('2',"Overwrite destination"),('3',"Auto-increment filename")], label="If Destination Exists:")
    continue_on_error = forms.BooleanField(label="Continue on Error", required=False)
    use_pre_script = forms.BooleanField(label="Use Pre-script", required=False, widget=forms.CheckboxInput(attrs={'onclick':'showScripts();'}))
    pre_script = forms.ChoiceField([], required=False)
    use_post_script = forms.BooleanField(label="Use Post-script", required=False, widget=forms.CheckboxInput(attrs={'onclick':'showScripts();'}))
    post_script =  forms.ChoiceField([], required=False)
    # ALERTING DETAILS
    alert_owner_on_success = forms.BooleanField(label="Alert me on Success", required=False)
    alert_owner_on_fail = forms.BooleanField(label="Alert me on Failure", required=False)
    suppress_group_alerts = forms.BooleanField(label="Suppress Group Alerts", required=False, widget=forms.CheckboxInput(attrs={'onclick':'showSuppressGroupAlerts();'}))
    alert_groups_on_success = forms.MultipleChoiceField(required=False, label="Alert Groups on Success", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    alert_groups_on_fail = forms.MultipleChoiceField(required=False, label="Alert Groups on Failure", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))

    def __init__(self, user, *args, **kwargs):
        # note: user above is the requesting user's user object.
        super(EditJobForm, self).__init__(*args, **kwargs)
        # capture the job we are editing
        # capture owner and current user (who will be an administrator) performing the job edit
        owner = xsftp.webui.models.User.objects.get(id=args[0]['owner_id'])
        self.owner = owner
        self.user = user
        # user the user is an administrator
        if user.is_staff:
            # shot the owner select field
            self.fields['job_owner'].choices = [(str(u.id), u.username) for u in xsftp.webui.models.User.objects.all()]
        else:
            # otehrwise hide it
            self.fields.pop('job_owner')
        # assign other user-specific field choices
        self.fields['source_server'].choices = [("", "Select one...")] + [(str(server.id), server.server_name) for server in  owner.userprofile.getAllReadServers()]
        self.fields['dest_server'].choices = [("", "Select one...")] + [(str(server.id), server.server_name) for server in  owner.userprofile.getEffectiveWriteServers()]
        # populate pre and post script choices
        self.fields['pre_script'].choices = self.fields['post_script'].choices = [("", "Select one...")] + [(str(script.id), script.script_name) for script in owner.userprofile.getEffectiveScripts()]
        self.fields['alert_groups_on_success'].choices = self.fields['alert_groups_on_fail'].choices = [(str(group.id), group.group_name) for group in xsftp.webui.models.xGroup.objects.get_query_set().filter(alertable=True)]
        # Preselect the servers and scripts as specified in the job

    def clean_job_name(self):
        submittedJobName = self.data.get('job_name')
        if not VALID_JOBNAME_PATTERN.search(submittedJobName):
            raise forms.ValidationError('The Job name contains illegal characters')
        return self.data.get('job_name')

    def clean_schedule_type(self):
        # ensure submitted value is between 0 and 6 incl.
        if self.data.get('schedule_type') not in [str(i) for i in range(7)]:
            raise forms.ValidationError('Please select a valid selection type')
        return self.data.get('schedule_type')

    def clean_run_at(self):
        if self.data.get('schedule_type') == "0" and not self.data.get('run_at'):
            raise forms.ValidationError('This field is required.')
        # ensure it is properly formatted, and it is not set in the past
        try:
            #if self.data.get('schedule_type') == "0" and datetime(*strptime(self.data.get('run_at'), "%Y-%m-%d %H:%M")[0:6]) < datetime.now():
            if self.data.get('schedule_type') == "0" and self.cleaned_data.get('run_at') < datetime.now():
                raise forms.ValidationError("The specified date/time occurs in the past")
        except ValueError:
            raise forms.ValidationError("Enter a valid date/time in the form: YYYY-MM-DD hh:mm")
        return self.data.get('run_at')

    def clean_minute(self):
        # if schedule type isnt "runOnce" or "advanced", and they have tried to enter something other than whats available in the minute pull-down menu
        if self.data.get('schedule_type') not in ["0","6"] and self.data.get('minute') not in ["0","1","2","3"]:
            raise forms.ValidationError("Please choose a valid minute of the hour")
        return self.data.get('minute')

    def clean_hour(self):
        if self.data.get('schedule_type') not in ["0","1","6"] and self.data.get('hour') not in [str(x) for x in range(24)]: 
            raise forms.ValidationError("Please choose a valid hour of the day")
        return self.data.get('hour')

    def clean_day(self):
        # this is day of month
        if self.data.get('schedule_type') in ["4","5"] and self.data.get('day') not in [str(x) for x in range(1,32)]:
            raise forms.ValidationError("Please choose a valid day of the month")
        #if they specified a yearly schedule
        if self.data.get('schedule_type') == "5":
            # check that the specified day occurs at least once per leap year (using year 2000 as the leap year)
            try: datetime(2000, int(self.data.get('month')), int(self.data.get('day')))
            except: raise forms.ValidationError("The day you chose never occurs in the specified month")
        return self.data.get('day')

    def clean_month(self):
        if self.data.get('schedule_type') == "5" and self.data.get('month') not in [str(x) for x in range(1,13)]:
            raise forms.ValidationError("Please choose a valid month")
        return self.data.get('month')

    def clean_dow(self):
        if self.data.get('schedule_type') == "3" and self.data.get('month') not in [str(x) for x in range(1,8)]:
            raise forms.ValidationError("Please choose a valid day of the week")
        return self.data.get('dow')

    def clean_advanced(self):
        if self.data.get('schedule_type') == "6":
            # ensure advanced field contains valid crontab formated string
            if not VALID_CRON_PATTERN.search(self.data.get('advanced')):
                raise forms.ValidationError("Please enter a valid cron-style schedule")
        return self.cleaned_data.get('advanced')

    def clean_expiry(self):
        try:
            if self.data.get('schedule_type') != "0" and self.data.get('expiry') != "":
                if self.cleaned_data.get('expiry') < datetime.now():
                    raise forms.ValidationError("The specified date/time occurs in the past")
        except ValueError:
            raise forms.ValidationError("Enter a valid date/time in the form: YYYY-MM-DD hh:mm")
        return self.data.get('expiry')

    def clean_source_server(self):
        if not self.user.is_staff and self.data.get('source_server') not in [str(server.id) for server in self.owner.userprofile.getAllReadServers()]:
             raise forms.ValidationError("Please choose a valid source server")
        return self.data.get('source_server')

    def clean_dest_server(self):
        if not self.user.is_staff and self.data.get('dest_server') not in [str(server.id) for server in  self.owner.userprofile.getEffectiveWriteServers()]:
             raise forms.ValidationError("Please choose a valid destination server")
        return self.data.get('dest_server')

    def clean_exist_action(self):
        if self.data.get('exist_action') not in [str(x) for x in range(4)]:
            raise forms.ValidationError("Please choose a valid action")
        return self.data.get('exist_action')

    def clean_pre_script(self):
        if self.data.get('use_pre_script'):
            if self.data.get('pre_script') not in [str(script.id) for script in self.user.userprofile.getEffectiveScripts()]:
                raise forms.ValidationError("Please choose a valid pre-script")
        return self.data.get('pre_script')

    def clean_post_script(self):
        if self.data.get('use_post_script'):
            if self.data.get('post_script') not in [str(script.id) for script in self.user.userprofile.getEffectiveScripts()]:
                raise forms.ValidationError("Please choose a valid post-script")
        return self.data.get('post_script')

    def clean_alert_groups_on_success(self):
        if not self.data.get('suppress_group_alerts') and not self.data.get('alert_groups_on_success') and not self.data.get('alert_groups_on_fail'):
            raise forms.ValidationError("Please choose at least one valid group from either section")
        return self.cleaned_data.get('alert_groups_on_success')

    def clean_alert_groups_on_fail(self):
        if not self.data.get('suppress_group_alerts') and not self.data.get('alert_groups_on_fail') and not self.data.get('alert_groups_on_success'):
            raise forms.ValidationError("Please choose at least one valid group from either section")
        return self.cleaned_data.get('alert_groups_on_fail')

    def save(self, jid, commit=True):
        job = xsftp.webui.models.Job.objects.get(id = jid)
        job.run_count = 0
        job.job_name = self.cleaned_data.get('job_name')
        if self.user.is_staff:
            job.owner = xsftp.webui.models.User.objects.get(id=int(self.cleaned_data.get('job_owner')))
        job.comment = self.cleaned_data.get('comment')
        job.enabled = self.cleaned_data.get('enabled')
        job.schedule_type = self.cleaned_data.get('schedule_type')
        job.run_at = self.cleaned_data.get('run_at') or None
        if job.schedule_type == '6': # advanced (cron-style schedule)
            job.minute, job.hour, job.day, job.month, job.dow = self.cleaned_data.get('advanced').split()
        else:
            job.minute = self.cleaned_data.get('minute')
            job.hour = self.cleaned_data.get('hour')
            job.day = self.cleaned_data.get('day')
            job.month = self.cleaned_data.get('month')
            job.dow = self.cleaned_data.get('dow')
        job.expiry = self.cleaned_data.get('expiry') or None
        if self.cleaned_data.get('source_server'):
            job.source_server = xsftp.webui.models.Server.objects.get(id = int(self.cleaned_data.get('source_server')))
        if self.cleaned_data.get('dest_server'):
            job.dest_server = xsftp.webui.models.Server.objects.get(id = int(self.cleaned_data.get('dest_server')))
        job.dest_path = self.cleaned_data.get('dest_path')
        job.delete_source = self.cleaned_data.get('delete_source')
        job.exist_action = self.cleaned_data.get('exist_action')
        job.continue_on_error = self.cleaned_data.get('continue_on_error')
        job.use_pre_script = self.cleaned_data.get('use_pre_script')
        if self.cleaned_data.get('pre_script'): job.pre_script = xsftp.webui.models.Script.objects.get(id=int(self.cleaned_data.get('pre_script')))
        job.use_post_script = self.cleaned_data.get('use_post_script')
        if self.cleaned_data.get('post_script'): job.post_script = xsftp.webui.models.Script.objects.get(id=int(self.cleaned_data.get('post_script')))
        job.alert_owner_on_success = self.cleaned_data.get('alert_owner_on_success')
        job.alert_owner_on_fail = self.cleaned_data.get('alert_owner_on_fail')
        job.suppress_group_alerts = self.cleaned_data.get('suppress_group_alerts')
        job.alert_groups_on_success = self.cleaned_data.get('alert_groups_on_success')
        job.alert_groups_on_fail = self.cleaned_data.get('alert_groups_on_fail')
        if commit:
            job.save()
        return job


# ******************************
#     Import SSH Key Forms
# ******************************


def parse_pubkey(key_data):
    '''
    Parses the specified SSH Public key data and returns a paramiko key object.
    SSH Public key data can be in either OpenSSH SSH-2 or PuTTY (RFC 4716) format.
    '''
    comment = ""
    key_data = key_data.strip().replace('\r','')
    if not key_data or key_data.startswith("#"):
        return None
    if key_data.startswith("---- BEGIN SSH2 PUBLIC KEY ----"):
        # this is a PuTTY formatted public key
        # XXX this implementation only supports the "Comment:" header. Other headers will trip it up.
        b64key = ""
        lines = key_data.split('\n')
        current_header = False
        for line in lines:
            if line == ("---- BEGIN SSH2 PUBLIC KEY ----") or line == ("---- END SSH2 PUBLIC KEY ----"):
                continue
            elif current_header == "Comment":
                comment += line.replace('"','').replace('\r', '').replace("'","")
                if comment.endswith("\\"):
                    comment = comment[:-1]
                else:
                    current_header = False
            elif line.startswith("Comment: "):
                comment = line.strip().split(" ", 1)[1].replace('"','').replace('\r', '').replace("'","")
                if comment.endswith("\\"):
                    comment = comment[:-1]
                    current_header = "Comment"
            else:
                if line.find(": ") == -1:
                    b64key += line.strip()
            keytype_string = None
    else:
        # this is an SSH-2 formatted public key
        (keytype_string, b64key, comment) = (key_data.split(" ", 2) + [''] * 3)[:3]
        comment = comment.replace("'","")
        if not keytype_string or not b64key:
            raise paramiko.SSHException("unknown key file format")
    try:
        keytype = base64.decodestring(b64key)[4:11]
    except Exception, e: raise paramiko.SSHException(e)
    if keytype_string and keytype_string != keytype:
        raise paramiko.SSHException("malformed key data")
    if keytype == 'ssh-rsa':
        try:
            key = paramiko.RSAKey(data=base64.decodestring(b64key))
        except binascii.Error, e: raise paramiko.SSHException(e)
    elif keytype == 'ssh-dss':
        try:
            key = paramiko.DSSKey(data=base64.decodestring(b64key))
        except binascii.Error, e: raise paramiko.SSHException(e)
    else:
        raise paramiko.SSHException("unknown encoded key type: %s" % keytype)
    key.comment = comment.strip()[:MAX_PUBKEY_COMMENT_LENGTH] or "(none specified)" #(none specified) is a special reserved string
    key.fingerprint = binascii.hexlify(key.get_fingerprint())
    key.type = keytype
    key.str_type = ["RSA", "DSA"]["ssh-dss" == key.type]
    key.bit_length = key.get_bits()
    return key


def read_authorized_keys(username):
    '''
    Returns a list of paramiko key objects for each key in specified user's authorized-keys file
    '''
    privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--read_authorized_keys=%s" % username]
    p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()
    output = pickle.loads(stdout)
    if isinstance(output, Exception):
        raise output
    return output


class importSshKeyForm(forms.Form):
    ssh_key_file = forms.FileField(label="SSH Public Key File", help_text="Select an SSH-2 or PuTTY (RFC 4716) formatted Public Key file, or a ZIP archive of multiple key files to import.")

    def clean_ssh_key_file(self):
        submittedFileObj = self.cleaned_data.get('ssh_key_file')
        self.submittedFileObj = submittedFileObj
        submittedFileData = submittedFileObj.read()
        pubkeys = []
        try:
            key = parse_pubkey(submittedFileData)
            pubkeys.append(key)
        except paramiko.SSHException:
            # submitted file might be a ZIP, check it.
            f = StringIO(submittedFileData)
            try:
                zip_file = zipfile.ZipFile(f)
            except:
                raise forms.ValidationError('The specified file was not a valid Public Key file or a valid ZIP archive of SSH Public Key files')
            for key_name in  zip_file.namelist():
                try:
                    key_data = zip_file.read(key_name)
                except:
                    raise forms.ValidationError("Could not read file '%s' within uploaded ZIP file. Ensure that the ZIP file is not password protected" %  key_name)
                try:
                    key = parse_pubkey(key_data)
                except Exception, e:
                    raise forms.ValidationError("The file '%s' within uploaded ZIP file was not a valid Public Key file. Error: %s" % (key_name, e))
                pubkeys.append(key)
        self.pubkeys_to_import = pubkeys

    def save(self, username):
        duplicates = []
        # process the submitted keys, checking for duplicates in the list of submitted keys
        unique_pubkeys_to_import = []
        for key in self.pubkeys_to_import:
            if key.fingerprint in [ukey.fingerprint for ukey in unique_pubkeys_to_import]:
                duplicates.append(key)
            else:
                unique_pubkeys_to_import.append(key)
        # process the submitted keys, checking for duplicates in authorized_keys file
        existing_key_fingerprints = [key.fingerprint for key in read_authorized_keys(username)]
        import_key_data = []
        for key in unique_pubkeys_to_import:
            if key.fingerprint in existing_key_fingerprints:
                duplicates.append(key)
            else:
                # generate import_key_data
                line = "%(type)s %(b64key)s %(comment)s" % {'type':key.type, 'b64key':key.get_base64(), 'comment':key.comment}
                import_key_data.append(line)
        import_key_data = "\n".join(import_key_data)
        # append import_key_data into the user's authorized_keys file
        key_fd, key_file_name = tempfile.mkstemp(dir="/tmp", prefix="fcombine_temp_file_pubkey_")
        key_file_handle = os.fdopen(key_fd, "w")
        key_file_handle.write(import_key_data)
        key_file_handle.close()
        append_key_command = "sudo %swww/xsftp/webui/privexec.py --import_public_keys=%s %s > /dev/null 2>&1" % (xsftp.common.constants.APPDIR, username, key_file_name)
        os.system(append_key_command)
        os.unlink(key_file_name)
        return (self.submittedFileObj.name, duplicates)


class EditSshKeyForm(forms.Form):
    fingerprint = forms.CharField(widget=forms.HiddenInput)
    key_name = forms.CharField(required=False, label="SSH Key Name (Comment)", help_text="Enter a new name/comment for this Public Key")

    def clean_key_name(self):
        submittedComment = self.data.get('key_name')
        if len(submittedComment) > MAX_PUBKEY_COMMENT_LENGTH:
            raise forms.ValidationError('The name/comment is too long (Max length is %s)' % MAX_PUBKEY_COMMENT_LENGTH)
        if submittedComment == '(none specified)':
            raise forms.ValidationError('The name/comment is a reserved phrase, please choose something different')
        if submittedComment.find("'") != -1:
            raise forms.ValidationError('The name/comment can not contain single quote characters')
        return submittedComment

    def save(self, username):
        fingerprint = self.cleaned_data.get('fingerprint')
        key_name = self.cleaned_data.get('key_name')
        chKeyNameCmd = "sudo %swww/xsftp/webui/privexec.py --set_key_comment=%s %s '%s' > /dev/null 2>&1" % (xsftp.common.constants.APPDIR, username, fingerprint, key_name)
        os.system(chKeyNameCmd)



# ******************************
#      Login & Toolbar Forms
# ******************************


class LoginForm(forms.Form):
    username = forms.CharField()
    password = PasswordField()


class ChangeMyPasswordForm(forms.Form):
    old_password = PasswordField(label="Old Password")
    new_password_1 = PasswordField(label="New Password")
    new_password_2 = PasswordField(label="Verify New Password")

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangeMyPasswordForm, self).__init__(*args, **kwargs)

    def clean_old_password(self):
        if self.data.get('old_password') and not self.user.check_password(self.data['old_password']):
            raise forms.ValidationError('The password was incorrect.')
        return self.data['old_password']

    def clean_new_password_1(self):
        if self.data.get('new_password_1') and self.data.get('new_password_2') and self.data['new_password_1'] != self.data['new_password_2']:
            raise forms.ValidationError('The new passwords were not the same.')
        if xsftp.webui.models.Configuration.objects.all()[0].password_complexity:
            try:
                cracklib.FascistCheck(self.data['new_password_1'])
            except ValueError, e:
                raise forms.ValidationError("Bad password: %s" % e)
        return self.data['new_password_1']


# ******************************
#      Configuration Forms
# ******************************



class EditConfigForm(forms.Form):
    device_name = forms.CharField(label="Device Name", required=False)
    ip_address = forms.CharField(label="IP Address", help_text="<span style='color:#FF6600'>Modifying this field will require a system restart</span>")
    subnet_mask = forms.CharField(label="Subnet Mask", help_text="<span style='color:#FF6600'>Modifying this field will require a system restart</span>")
    default_gateway = forms.CharField(label="Default Gateway", required=False, help_text="<span style='color:#FF6600'>Modifying this field will require a system restart</span><br/>Leave blank for none.")
    primary_dns = forms.CharField(label="Primary DNS Server", required=False)
    secondary_dns = forms.CharField(label="Secondary DNS Server", required=False)
    system_time = MyBasicDateTimeField(label="System Time", required=False)
    password_complexity = forms.BooleanField(label="Enforce Password Complexity", required=False)
    radius_server = forms.CharField(label="RADIUS Server Address", help_text="Leave this field blank to disable RADIUS Authentication", required=False)
    radius_authport = forms.IntegerField(label="RADIUS Server Auth Port", required=False)
    radius_secret = PasswordField(label="RADIUS Server Secret", required=False)
    remote_syslog_server = forms.CharField(label="Remote Syslog Server", required=False, help_text="Leave this field blank if you want logs to be written only to this system's internal Syslog service")
    smtp_server = forms.CharField(label="SMTP Gateway Server", required=False)
    smtp_port = forms.IntegerField(label="SMTP Port", required=True, help_text="Default SMTP port is 25")
    smtp_from_address = forms.CharField(label="SMTP From Address", required=False)
    serverlink_alert_groups = forms.MultipleChoiceField(required=False, label="Server Link Health Global Alert Groups", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    job_success_alert_groups = forms.MultipleChoiceField(required=False, label="Job Success Global Alert Groups", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))
    job_failure_alert_groups = forms.MultipleChoiceField(required=False, label="Job Failure Global Alert Groups", help_text="Hold down 'Ctrl' (or 'Command' on a Mac) to unselect, or to select more than one.", widget=forms.SelectMultiple(attrs={'size':str(SELECT_MULTIPLE_SIZE)}))

    def __init__(self, *args, **kwargs):
        # args is immutable, but we want to modify it, so make a copy as a list
        newargs = list(args[:])
        if newargs:
            data = newargs[0]
        elif "data" in kwargs.keys():
            data = kwargs["data"]
        else:
            data = None
        # If data is a config object
        if isinstance(data, xsftp.webui.models.Configuration):
            # then we got here via a GET (no POST data yet)
            newdata = data.__dict__.copy()
            # Assign lists of users/groups to the appropriate keys in newdata
            newdata["serverlink_alert_groups"] = [group.id for group in data.serverlink_alert_groups.get_query_set()]
            newdata["job_success_alert_groups"] = [group.id for group in data.job_success_alert_groups.get_query_set()]
            newdata["job_failure_alert_groups"] = [group.id for group in data.job_failure_alert_groups.get_query_set()]
            # assign correct devicename
            newdata["device_name"] = data.get_device_name()
            # Finally, replace the appropriate arguments
            if newargs:
                newargs[0] = newdata
            else:
                kwargs["data"] = newdata
        super(EditConfigForm, self).__init__(*newargs, **kwargs)
        if Licenses().is_subscribed():
            self.fields['device_name'] = MyTextLabelField(label="Device Name", help_text="This value is set in your subscription file.", widget=TextLabelWidget(attrs={'style':'font-size:16px;'}), required=False)
        self.fields['serverlink_alert_groups'].choices = [(group.id, group.group_name) for group in xsftp.webui.models.xGroup.objects.all() if group.alertable]
        self.fields['job_success_alert_groups'].choices = [(group.id, group.group_name) for group in xsftp.webui.models.xGroup.objects.all() if group.alertable]
        self.fields['job_failure_alert_groups'].choices = [(group.id, group.group_name) for group in xsftp.webui.models.xGroup.objects.all() if group.alertable]
        self.fields['smtp_from_address'].help_text = "Enter the email address to use as the from-address for email alerts sent by this system.<br/>Defaults to <i>admin@%s</i> if left blank." % xsftp.webui.models.Configuration.objects.all()[0].ip_address
        self.fields['system_time'].help_text = "Current time on this system is %s" % datetime.now().strftime("%Y-%m-%d %H:%M")

    def is_valid_port(self, port):
        try:
            port = int(port)
        except ValueError:
            return False
        if 0 <= port <= 65535:
            return True
        return False

    def clean_radius_secret(self):
        sumbittedRadiusServer = self.data.get('radius_server')
        sumbittedRadiusSecret = self.data.get('radius_secret')
        if sumbittedRadiusServer and not sumbittedRadiusSecret:
            raise forms.ValidationError('Please enter your RADIUS Server Secret')
        return self.data.get('radius_secret')

    def clean_radius_authport(self):
        sumbittedRadiusAuthport = str(self.data.get('radius_authport'))
        if not sumbittedRadiusAuthport:
            return '1812'
        if not self.is_valid_port(sumbittedRadiusAuthport):
            raise forms.ValidationError('Please enter a valid Port number')
        return self.data.get('radius_authport')

    def clean_smtp_port(self):
        sumbittedRadiusAuthport = str(self.data.get('smtp_port'))
        if not self.is_valid_port(sumbittedRadiusAuthport):
            raise forms.ValidationError('Please enter a valid Port number')
        return self.data.get('smtp_port')

    def clean_radius_server(self):
        sumbittedRadiusServer = self.data.get('radius_server')
        if sumbittedRadiusServer and not VALID_IP_ADDRESS_PATTERN.search(sumbittedRadiusServer) and not VALID_FQDN_PATTERN.search(sumbittedRadiusServer):
            raise forms.ValidationError('Please enter a valid IP Address or Fully Qualified Domain Name')
        return self.data.get('radius_server')

    def clean_device_name(self):
        submittedDeviceName = self.data.get('device_name')
        if Licenses().is_subscribed():
            return DEFAULT_DEVICE_NAME
        else:
            if not submittedDeviceName:
                raise forms.ValidationError('This field is required')
            elif not VALID_DEVICENAME_PATTERN.search(submittedDeviceName):
                raise forms.ValidationError('The Device Name contains illegal characters')
            else:
                return self.data.get('device_name')

    def clean_ip_address(self):
        submittedIpAddress = self.data.get('ip_address')
        if not VALID_IP_ADDRESS_PATTERN.search(submittedIpAddress):
            raise forms.ValidationError('Please enter a valid IP address')
        return self.data.get('ip_address')

    def clean_subnet_mask(self):
        submittedSubnetMask = self.data.get('subnet_mask')
        if not VALID_IP_ADDRESS_PATTERN.search(submittedSubnetMask):
            raise forms.ValidationError('Please enter a valid subnet mask in dotted decimal form (eg. 255.255.255.0)')
        submittedIpAddress = self.data.get('ip_address')
        if VALID_IP_ADDRESS_PATTERN.search(submittedIpAddress):
            try:
                IPy.IP("%s/%s" % (submittedIpAddress, submittedSubnetMask), make_net=True)
            except:
                raise forms.ValidationError('Please enter a valid subnet mask in dotted decimal form (eg. 255.255.255.0)')
        return self.data.get('subnet_mask')

    def clean_default_gateway(self):
        submittedDefaultGW = self.data.get('default_gateway')
        if submittedDefaultGW and not VALID_IP_ADDRESS_PATTERN.search(submittedDefaultGW):
            raise forms.ValidationError('Please enter a valid IP Address')
        return self.data.get('default_gateway')

    def clean_primary_dns(self):
        submittedPrimaryDNS = self.data.get('primary_dns')
        if submittedPrimaryDNS and not VALID_IP_ADDRESS_PATTERN.search(submittedPrimaryDNS):
            raise forms.ValidationError('Please enter a valid IP Address')
        return self.data.get('primary_dns')

    def clean_secondary_dns(self):
        submittedPrimaryDNS = self.data.get('primary_dns')
        submittedSecondaryDNS = self.data.get('secondary_dns')
        if submittedPrimaryDNS == submittedSecondaryDNS and submittedPrimaryDNS:
            raise forms.ValidationError('Primary and Secondary DNS servers must be different')
        if submittedSecondaryDNS and not VALID_IP_ADDRESS_PATTERN.search(submittedSecondaryDNS):
            raise forms.ValidationError('Please enter a valid IP Address')
        if submittedSecondaryDNS and not self.data.get('primary_dns'):
            raise forms.ValidationError('Primary DNS server must not be empty if you specify a Secondary DNS Server')
        return self.data.get('secondary_dns')

    def clean_smtp_server(self):
        sumbittedSMTPServer = self.data.get('smtp_server')
        if sumbittedSMTPServer and not VALID_IP_ADDRESS_PATTERN.search(sumbittedSMTPServer) and not VALID_FQDN_PATTERN.search(sumbittedSMTPServer):
            raise forms.ValidationError('Please enter a valid IP Address or Fully Qualified Domain Name')
        return self.data.get('smtp_server')

    def clean_smtp_from_address(self):
        submittedFromAddress = self.data.get('smtp_from_address')
        if submittedFromAddress and not VALID_EMAIL_ADDRESS_PATTERN.search(submittedFromAddress):
            raise forms.ValidationError('Please enter a valid email address')
        return self.data.get('smtp_from_address')

    def clean_remote_syslog_server(self):
        submittedSyslogServer = self.data.get('remote_syslog_server')
        if submittedSyslogServer and not VALID_IP_ADDRESS_PATTERN.search(submittedSyslogServer) and not VALID_FQDN_PATTERN.search(submittedSyslogServer):
            raise forms.ValidationError('Please enter a valid IP Address or Fully Qualified Domain Name')
        return self.data.get('remote_syslog_server')

    def save(self):
        # mofify system time if specified
        system_time = self.cleaned_data.get('system_time')
        if system_time:
            time_arg = "%04d%02d%02d%02d%02d%02d" % (system_time.year, system_time.month, system_time.day, system_time.hour, system_time.minute, system_time.second)
            setTimeCommand = "sudo %swww/xsftp/webui/privexec.py --settime=%s > /dev/null 2>&1 " % (xsftp.common.constants.APPDIR, time_arg)
            os.system(setTimeCommand)
        # instantiate a config object
        config = xsftp.webui.models.Configuration.objects.all()[0]
        # populate its fields
        config.device_name = self.cleaned_data.get('device_name')
        config.ip_address = self.cleaned_data.get('ip_address')
        config.subnet_mask = self.cleaned_data.get('subnet_mask')
        config.default_gateway = self.cleaned_data.get('default_gateway')
        config.primary_dns = self.cleaned_data.get('primary_dns') or None
        config.secondary_dns = self.cleaned_data.get('secondary_dns') or None
        config.password_complexity = self.cleaned_data.get('password_complexity')
        config.radius_server = self.cleaned_data.get('radius_server')
        config.radius_authport = self.cleaned_data.get('radius_authport')
        config.radius_secret = self.cleaned_data.get('radius_secret')
        config.smtp_server = self.cleaned_data.get('smtp_server')
        config.smtp_port = self.cleaned_data.get('smtp_port')
        config.smtp_from_address = self.cleaned_data.get('smtp_from_address')
        config.remote_syslog_server = self.cleaned_data.get('remote_syslog_server')
        config.serverlink_alert_groups = self.cleaned_data.get('serverlink_alert_groups')
        config.job_success_alert_groups = self.cleaned_data.get('job_success_alert_groups')
        config.job_failure_alert_groups = self.cleaned_data.get('job_failure_alert_groups')
        config.save()


#############################
# LeetTable Classes

class LeetHeading:
    def __init__(self, text="", sortable=True, render_as="text"):
        self.text = text
        self.sortable = sortable
        self.render_as = render_as


class LeetButton:
    SPACE = "&nbsp;&nbsp;&nbsp;&nbsp;"
    CR = "<br/>"

    def __init__(self, value, name="button", delimiter=None):
        self.value = value
        self.name = name
        self.delimiter = delimiter


class LeetTable:
    '''
    Creates a leet table with optional filter and optionally-sortable columns.
    Due to the nature of the form, you must provide the action to the form
    Because this form is some kind of weird mutant that is halfway between a form and a display table, we can't rely on a lot of the shortcut goodies that Django provides
    '''
    def __init__(self, action="", headings=[], objects=[], sortable=False, buttons=[], filter="", filterable=True, sortCol=0, sortOrder="asc", objectDescription="Object", totalObjects=0):
        self.action = action
        self.headings = headings
        self.objects = objects
        self.sortable = sortable
        self.buttons = buttons
        self.filter = filter
        self.filterable = filterable
        self.sortCol = sortCol
        self.sortOrder = sortOrder
        self.objectDescription = objectDescription
        self.totalObjects = totalObjects

# END of LeetTable
#####################################

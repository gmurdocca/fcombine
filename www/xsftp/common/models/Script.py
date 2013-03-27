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

from django.db import models
from django.contrib.auth.models import User
from django.core.files.storage import FileSystemStorage

from xGroup import xGroup
import xsftp.common.constants
from xsftp.webui import constants
from xsftp.common.constants import COMMENT_LENGTH
from xsftp.common.models.dbfunctions import dbCommit
from xsftp.common.models.dbfunctions import checkJobSanity


class Script(models.Model):
    '''
    Script object class
    '''

    class Meta:
        app_label = "webui"

    script_store = FileSystemStorage(location=xsftp.webui.constants.SCRIPT_PATH)
    script_name = models.CharField(max_length=60)
    comment = models.CharField(max_length=COMMENT_LENGTH, blank=True)
    file = models.FileField(upload_to=lambda :"", storage=script_store)
    execUsers = models.ManyToManyField(User, blank=True)
    execGroups =  models.ManyToManyField(xGroup, blank=True)

    def getEffectiveUsers(self):
        '''
        Returns a list of users who can execute this script (ie. use this script in their jobs), including execute permissions granted by virtue of group membership.
        '''
        users = list(self.execUsers.all())
        for group in self.execGroups.all():
            for user in group.users.all():
                if user not in users:
                    users.append(user)
        return users

    def save(self):
#        if not self.pk:
#            #log("created new script '%s'" % self.script_name)
#        else:
#            #log("modified script '%s'" % self.script_name)
        super(Script, self).save()
        dbCommit()
        checkJobSanity()

    def delete(self):
        # disconnect script from any jobs that refer to it
        for job in self.jobs_pre.all():
            job.pre_script = None
            job.save()
        for job in self.jobs_post.all():
            job.post_script = None
            job.save()
        super(Script, self).delete()
        #log("deleted script '%s'" % self.script_name)
        dbCommit()
        checkJobSanity()

    def getAssociatedUsers(self):
        '''
        Returns an ordered list containing 3-tuples for each user who have execute perms on this script (ordered alphabetically on username).
        The first item is the user object
        The second item identifies whether the user is an execUser member or not (bool)
        The third item lists execGroups that the user is a member of
        ( userObj, perm, [ groupObj, ... ] )
        '''
        associated_users = {}
        for user in self.execUsers.all():
            associated_users[user] = [True, []]
        for group in self.execGroups.all():
            for user in group.users.all():
                if user in associated_users:
                    associated_users[user][1].append(group)
                else:
                    associated_users[user] = [False, [group]]
        result = []
        for item in associated_users.items():
            result.append((item[0], item[1][0], item[1][1]))
        result = sorted(result, key=lambda x: x[0].username.lower())
        return result

    def __unicode__(self):
        return self.script_name

    def __str__(self):
        return self.__unicode__()

    def get_basename(self):
        return os.path.basename(self.file.path)

    class Admin:
        pass


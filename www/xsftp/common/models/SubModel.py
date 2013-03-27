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
from django.contrib.contenttypes.models import ContentType

class SubModel(models.Model):
    """This is a properly subclassable django model"""

    content_type = models.ForeignKey(ContentType, editable=False, null=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.content_type = ContentType.objects.get_for_model( \
                    self.__class__)

        super(SubModel, self).save(*args, **kwargs)

    def cast(self):
        return self.content_type.get_object_for_this_type(pk=self.pk)

    class Meta:
        abstract = True


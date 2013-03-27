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

from xsftp.common import popenutil

class Mounter(object):
    """Mounter is an abstract class used to make concrete classes
       that mount a particular type.  For example, concrete classes
       might include a CIFS mounter, a SSHFS mounter etc"""

    def mount(self, server, uid=0, gid=0):
        raise NotImplementedError()

    def unmount(self, server):
        """The default unmounter suits most server types"""
        cmd = ["umount", "-l", "-f", server.mount_point]

        popenutil.quick_popen(cmd)

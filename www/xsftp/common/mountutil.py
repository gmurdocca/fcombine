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
import popenutil

def is_mounted(mount_point):
    # TODO: we should cache this once we start
    # looking for mount errors

    try:
        fh = open("/proc/mounts", "r")
        for line in fh:
            test_mount_point = line.split()[1]

            try:
                if os.path.samefile(mount_point, test_mount_point) == True:
                    return True
            except OSError, ex:
                # Permission denied.  Happens if we compare the file
                # with a mountpoint we don't have permission to.
                # The only instance I know where this is possible
                # is with fuse mountpoints where allow_root is not
                # enabled

                # 13 = Permission denied
                if ex.errno != 13:
                    # reraise the error
                    raise
    finally:
        fh.close()

    return False

def unmount(mount_point, lazy=True, force=True):
    cmd = ["umount"]
    if lazy == True:
        cmd.append("-l")

    if force == True:
        cmd.append("-f")

    cmd.append(mount_point)

    popenutil.quick_popen(cmd)


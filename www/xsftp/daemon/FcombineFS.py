#!/usr/bin/python
############################################################################
# The xSFTP FcombineFS
# #####################
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
import fuse
import time
import fcntl
import subprocess
from fuse import Fuse

sys.path.append("/opt/fcombine/www")

import xsftp.common.constants
from DemandMounter import DemandMounter
from xsftp.common.Logger import log, logger

# set fuse module options
fuse.fuse_python_api = (0, 2)
fuse.feature_assert('stateful_files', 'has_init')

# we import this last so we catch as many errors as possible

class FcombineFSFile(object):

    def __init__(self, path, flags, *mode):
        self.file = os.fdopen(os.open("." + path, flags, *mode),
                              self.flag2mode(flags))
        self.fd = self.file.fileno()

    def read(self, length, offset):
        self.file.seek(offset)
        return self.file.read(length)

    def write(self, buf, offset):
        self.file.seek(offset)
        self.file.write(buf)
        return len(buf)

    def release(self, flags):
        self.file.close()

    def _fflush(self):
        if 'w' in self.file.mode or 'a' in self.file.mode:
            self.file.flush()

    def fsync(self, isfsyncfile):
        self._fflush()
        if isfsyncfile and hasattr(os, 'fdatasync'):
            os.fdatasync(self.fd)
        else:
            os.fsync(self.fd)

    def flush(self):
        self._fflush()
        # cf. xmp_flush() in fusexmp_fh.c
        os.close(os.dup(self.fd))

    def fgetattr(self):
        return os.fstat(self.fd)

    def ftruncate(self, len):
        self.file.truncate(len)

    def lock(self, cmd, owner, **kw):
        # The code here is much rather just a demonstration of the locking
        # API than something which actually was seen to be useful.

        # Advisory file locking is pretty messy in Unix, and the Python
        # interface to this doesn't make it better.
        # We can't do fcntl(2)/F_GETLK from Python in a platfrom independent
        # way. The following implementation *might* work under Linux. 
        #
        # if cmd == fcntl.F_GETLK:
        #     import struct
        # 
        #     lockdata = struct.pack('hhQQi', kw['l_type'], os.SEEK_SET,
        #                            kw['l_start'], kw['l_len'], kw['l_pid'])
        #     ld2 = fcntl.fcntl(self.fd, fcntl.F_GETLK, lockdata)
        #     flockfields = ('l_type', 'l_whence', 'l_start', 'l_len', 'l_pid')
        #     uld2 = struct.unpack('hhQQi', ld2)
        #     res = {}
        #     for i in xrange(len(uld2)):
        #          res[flockfields[i]] = uld2[i]
        #  
        #     return fuse.Flock(**res)

        # Convert fcntl-ish lock parameters to Python's weird
        # lockf(3)/flock(2) medley locking API...
        op = { fcntl.F_UNLCK : fcntl.LOCK_UN,
               fcntl.F_RDLCK : fcntl.LOCK_SH,
               fcntl.F_WRLCK : fcntl.LOCK_EX }[kw['l_type']]
        if cmd == fcntl.F_GETLK:
            return -EOPNOTSUPP
        elif cmd == fcntl.F_SETLK:
            if op != fcntl.LOCK_UN:
                op |= fcntl.LOCK_NB
        elif cmd == fcntl.F_SETLKW:
            pass
        else:
            return -EINVAL

        fcntl.lockf(self.fd, op, kw['l_start'], kw['l_len'])

    def flag2mode(self, flags):
        md = {os.O_RDONLY: 'r', os.O_WRONLY: 'w', os.O_RDWR: 'w+'}
        m = md[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]

        if flags | os.O_APPEND:
            m = m.replace('w', 'a', 1)

        return m



class FcombineFS(Fuse):

    ################################
    ########### BIG FAT TODO:
    ################################
    # Do we need to update the activity counter for file reads/writes?
    # Perhaps we should just check to see if there's any open
    # files on the filesystem when the unmount is ready to occur?
    ###############################

    def __init__(self, home_source, home_dest):
        Fuse.__init__(self, dash_s_do="setsingle")
        self.home_source = home_source
        self.home_dest = os.path.normpath(home_dest)

        if os.path.exists(self.home_source) == False:
            raise OSError("No such file or directory %s" % self.home_source)

        if os.path.exists(self.home_dest) == False:
            raise OSError("No such file or directory %s" % self.home_dest)

        self.demand_mounter = DemandMounter()


    def update_activity(self, path):
        pass

    def getattr(self, path):
        log(7, "getattr")
        self.update_activity(path)
        return os.lstat("." + path)

    def readlink(self, path):
        log(7, "readlink")
        self.update_activity(path)
        return os.readlink("." + path)

    def readdir(self, path, offset):
        log(7, "readdir")
        self.demand_mounter.check_path(path)

        for e in os.listdir("." + path):
            yield fuse.Direntry(e)

    def unlink(self, path):
        log(7, "unlink")
        self.update_activity(path)
        os.unlink("." + path)

    def rmdir(self, path):
        log(7, "rmdir")
        self.update_activity(path)
        os.rmdir("." + path)

    def symlink(self, path, path1):
        log(7, "symlink")
        self.update_activity(path)
        os.symlink(path, "." + path1)

    def rename(self, path, path1):
        log(7, "rename")
        self.update_activity(path)
        os.rename("." + path, "." + path1)

    def link(self, path, path1):
        log(7, "link")
        self.update_activity(path)
        os.link("." + path, "." + path1)

    def chmod(self, path, mode):
        log(7, "chmod")
        self.update_activity(path)
        os.chmod("." + path, mode)

    def chown(self, path, user, group):
        log(7, "chown")
        self.update_activity(path)
        os.chown("." + path, user, group)

    def truncate(self, path, len):
        log(7, "truncate")
        self.update_activity(path)
        f = open("." + path, "a")
        f.truncate(len)
        f.close()

    def mknod(self, path, mode, dev):
        log(7, "mknod")
        self.update_activity(path)
        os.mknod("." + path, mode, dev)

    def mkdir(self, path, mode):
        log(7, "mkdir")
        self.update_activity(path)
        os.mkdir("." + path, mode)

    def utime(self, path, times):
        log(7, "utime")
        self.update_activity(path)
        os.utime("." + path, times)

    def access(self, path, mode):
        log(7, "access")
        if not os.access("." + path, mode):
            return -EACCES

    def statfs(self):
        log(7, "statfs")
        """
        Should return an object with statvfs attributes (f_bsize, f_frsize...).
        Eg., the return value of os.statvfs() is such a thing (since py 2.2).
        If you are not reusing an existing statvfs object, start with
        fuse.StatVFS(), and define the attributes.

        To provide usable information (ie., you want sensible df(1)
        output, you are suggested to specify the following attributes:

            - f_bsize - preferred size of file blocks, in bytes
            - f_frsize - fundamental size of file blcoks, in bytes
                [if you have no idea, use the same as blocksize]
            - f_blocks - total number of blocks in the filesystem
            - f_bfree - number of free blocks
            - f_files - total number of file inodes
            - f_ffree - nunber of free file inodes
        """

        return os.statvfs(".")

    def fsinit(self):
        log(7, "fsinit")
        os.chdir(self.home_source)

    def fsdestroy(self):
        log(7, "fsdestroy")
        self.demand_mounter.fsdestroy()

    def main(self):
        self.file_class = FcombineFSFile
        return Fuse.main(self, args=[sys.argv[0], '-ononempty', self.home_dest])

if __name__ == "__main__":
    # initialize the automounter
    auto_mounter = FcombineFS(xsftp.common.constants.HOMEDIR_SOURCE, 
            xsftp.common.constants.HOMEDIR)

    # redirect standard in/out
    logger.redirect_output()
    auto_mounter.main()


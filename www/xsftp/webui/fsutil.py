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
import stat
from os.path import abspath

__all__ = ["copyfile","copymode","copystat","copy","copytree","move","rmtree"]

COPY_BUFFER = 16*1024 #16kB

def _samefile(src, dst):
    # Macintosh, Unix.
    if hasattr(os.path,'samefile'):
        try:
            return os.path.samefile(src, dst)
        except OSError:
            return False

    # All other platforms: check for same pathname.
    return (os.path.normcase(os.path.abspath(src)) ==
            os.path.normcase(os.path.abspath(dst)))

def copyfile(src, dst):
    """Copy data from src to dst"""
    if _samefile(src, dst):
        raise Exception, "`%s` and `%s` are the same file" % (src, dst)

    fsrc = None
    fdst = None
    try:
        fsrc = open(src, 'rb')
        fdst = open(dst, 'wb')
        while True:
            buf = fsrc.read(COPY_BUFFER)
            if not buf:
                break
            fdst.write(buf)
    finally:
        if fdst:
            fdst.close()
        if fsrc:
            fsrc.close()

def copymode(src, dst):
    """Copy mode bits from src to dst"""
    if hasattr(os, 'chmod'):
        st = os.stat(src)
        mode = stat.S_IMODE(st.st_mode)
        os.chmod(dst, mode)

def copystat(src, dst):
    """Copy all stat info (atime and mtime) from src to dst"""
    st = os.stat(src)
    if hasattr(os, 'utime'):
        os.utime(dst, (st.st_atime, st.st_mtime))

def copy(src, dst, copy_mode=True, copy_stat=True, ignore_errors=False):
    """
    Copy file data and optionally mode bits and stat info.
    NOTE: Can oply operate on a source file, not a directory.
    The destination may be a directory.
    """
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))
    copyfile(src, dst)
    try:
        if copy_mode: copymode(src, dst)
    except Exception, e:
        if not ignore_errors:
            raise e
    try:
        if copy_stat: copystat(src, dst)
    except Exception, e:
        if not ignore_errors:
            raise e

def copytree(src, dst, symlinks=False, copy_mode=True, copy_stat=True, ignore_errors=False):
    """Recursively copy a directory tree using copy().

    The destination directory must not already exist.
    If exception(s) occur, an Error is raised with a list of reasons.

    If the optional symlinks flag is true, symbolic links in the
    source tree result in symbolic links in the destination tree; if
    it is false, the contents of the files pointed to by symbolic
    links are copied.
    """
    # XXX what probs could the below calls cause?
    # os.listdir bails with OSError if src isnt a dir
    try:
        names = os.listdir(src)
    except Exception, e:
        raise Exception("Couldn't read the source directory: %s" % (e.strerror))
    try:
        os.makedirs(dst)
    except Exception, e:
        raise Exception("Couldn't create the destination directory: %s" % (e.strerror))
    errors = []
    for name in names:
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                copytree(srcname, dstname, symlinks, copy_mode=copy_mode, copy_stat=copy_stat, ignore_errors=ignore_errors)
            else:
                copy(srcname, dstname, copy_mode=copy_mode, copy_stat=copy_stat, ignore_errors=ignore_errors)
            # XXX What about devices, sockets etc.?
        except (IOError, os.error), e:
            errors.append((srcname, dstname, str(e)))
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Exception, e:
            errors.extend(e.args[0])
    try:
        if copy_mode:
            copymode(src, dst)
        if copy_stat:
            copystat(src, dst)
    except OSError, e:
        if not ignore_errors:
            errors.extend((src, dst, str(e)))
    if errors:
        raise Exception, errors

def rmtree(path, ignore_errors=False, onerror=None):
    """Recursively delete a directory tree.

    If ignore_errors is set, errors are ignored; otherwise, if onerror
    is set, it is called to handle the error with arguments (func,
    path, exc_info) where func is os.listdir, os.remove, or os.rmdir;
    path is the argument to that function that caused it to fail; and
    exc_info is a tuple returned by sys.exc_info().  If ignore_errors
    is false and onerror is None, an exception is raised.

    """
    if ignore_errors:
        def onerror(*args):
            pass
    elif onerror is None:
        def onerror(*args):
            raise
    names = []
    try:
        names = os.listdir(path)
    except os.error, err:
        onerror(os.listdir, path, sys.exc_info())
    for name in names:
        fullname = os.path.join(path, name)
        try:
            mode = os.lstat(fullname).st_mode
        except os.error:
            mode = 0
        if stat.S_ISDIR(mode):
            rmtree(fullname, ignore_errors, onerror)
        else:
            try:
                os.unlink(fullname)
            except os.error, err:
                onerror(os.remove, fullname, sys.exc_info())
    try:
        os.rmdir(path)
    except os.error:
        onerror(os.rmdir, path, sys.exc_info())

def move(src, dst, copy_mode=True, copy_stat=True, ignore_errors=False):
    """Recursively move a file or directory to another location.

    If the destination is on our current filesystem, then simply use
    rename.  Otherwise, copy src to the dst and then remove src.
    A lot more could be done here...  A look at a mv.c shows a lot of
    the issues this implementation glosses over.

    """
    try:
        #raise Exception("My mother is a poofEnanny") # digital age
        os.rename(src, dst)
    except OSError:
        if os.path.isdir(src):
            if destinsrc(src, dst):
                raise Exception, "Cannot move a directory '%s' into itself '%s'." % (src, dst)
            copytree(src, dst, symlinks=True, copy_mode=copy_mode, copy_stat=copy_stat, ignore_errors=ignore_errors)
            rmtree(src)
        else:
            copy(src,dst, copy_mode=copy_mode, copy_stat=copy_stat, ignore_errors=ignore_errors)
            os.unlink(src)

def destinsrc(src, dst):
    return abspath(dst).startswith(abspath(src))


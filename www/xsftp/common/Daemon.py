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
import getopt
import signal

from xsftp.common.LoggerFile import LoggerFile

class Watcher:
    """this class solves two problems with multithreaded
    programs in Python, (1) a signal might be delivered
    to any thread (which is just a malfeature) and (2) if
    the thread that gets the signal is waiting, the signal
    is ignored (which is a bug).

    The watcher is a concurrent process (not thread) that
    waits for a signal and the process that contains the
    threads.  See Appendix A of The Little Book of Semaphores.
    http://greenteapress.com/semaphores/
    """
    
    def __init__(self):
        """ Creates a child thread, which returns.  The parent
            thread waits for a KeyboardInterrupt and then kills
            the child thread.
        """
        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()

    def watch(self):
        try:
            os.wait()
        except KeyboardInterrupt:
            print '\nKeyboard Interrupt caught, exiting...'
            self.kill()
        sys.exit()

    def kill(self):
        try:
            os.kill(self.child, signal.SIGKILL)
        except OSError: pass

###########################
########### INITIALIZE FORK
###########################

class Daemon:
    """This class sets up the global modules such as common and
       instantiates the helper classes within.  This needs to
       be done prior to any other classes being instantiated
       as they will import common.  This also double-forks
       to daemonize the program"""

    def __init__(self, pid_file, daemonise=True, syslog_name=None):
        self.pid_file = pid_file
        self.daemonise = daemonise

        if syslog_name == None:
            raise AttributeError("""Please specify syslog_name in order to
                    redirect output to syslog""")

    def handle_sigchld(self, signal_number, stack_frame):
        """Create a handler for SIGCHLD so that we clean up our
           zombie children whos exit codes we don't read (eg.
           curlftpfs processes in the doSLAMMount() function)"""

        try:
            os.waitpid(-1, os.WNOHANG)
        except OSError:
            # there were no children to reap, pass
            pass


    def pre_fork(self):
        """Implementations can override this if they want.  This is useful
           for printing error messages and exiting before we've redirected
           all the output"""
        pass


    def main(self):
        raise NotImplementedError("Please override the main function")


    def run(self):
        self.pre_fork()

        """Daemonises us into the background"""
        if self.daemonise:
            # redirect all output to a logfile
            sys.stdout = sys.stderr = LoggerFile()


            # UNIX double-fork trick follows:
            try:
                pid = os.fork()
                if pid > 0:
                    # exit first parent
                    sys.exit(0)

            except OSError, e:
                sys.stderr.write("fork #1 failed: %d (%s)\n""" %
                        (e.errno, e.strerror))
                sys.exit(1)

            # decouple from parent environment
            # don't prevent unmounting or deleting the dir that the daemon was
            # started in...
            os.chdir("/")

            # create a new session, become the group leader of the new process
            # group in the session with no controlling tty.
            # See http://www.win.tue.nl/~aeb/linux/lk/lk-10.html
            os.setsid()
            os.umask(0)

            # do the second fork
            try:
                pid = os.fork()
                if pid > 0:
                    # exit from second parent, print eventual PID before
                    #print "Daemon PID %d" % pid
                    open(self.pid_file, 'w').write("%d"%pid)
                    sys.exit(0)

            except OSError, e:
                sys.stderr.write("fork #2 failed: %d (%s)\n" %
                        (e.errno, e.strerror))
                sys.exit(1)

            # WE ARE NOW DAEMONISED! Start the daemon's main loop
            self.main()
        else:
            Watcher()
            self.main()

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

from xsftp.common.Daemon import Daemon

class FcombineWatchdog(Daemon):
    """Start/Stop Daemon (implement a watchdog to do this and to keep an eye on
       the health of the daemon in case it dies unexpectedly)"""

    def main(self):
        # Basically we sit here and restart the daemon
        # if it dies.  Simple.

        # TODO: if we need to 
        pass

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

import sys

import ConfigParser
from Singleton import Singleton
import xsftp.common.constants

class Config(Singleton):
    """This class basically abstracts access to configuration
       items as read from the config file.  This allows us
       to change the underlying config mechanism and also
       share the config between elements such as the web
       frontend etc without cutting and pasting code.

       The various config items are retrieved by just
       using config.item where item is the config item you want
       The __getattr__ function will pull out the correct
       config item."""

    def __init__(self):
        self.conf = None
        self.types = {}
        self.defaults = {}

        conf_file = xsftp.common.constants.DEFAULT_CONF_FILE
        self.read_config(conf_file)

    def set_type(self, attr, type_):
        """This tells this class to return certain
           config items as a a particular class.  This is
           to save us from constantly having to recast
           strings to the various types like ints.
           
           For example, if you wanted LOGLEVEL always as an
           int, just call set_type("LOGLEVEL", int)"""
        self.types[attr] = type_

    def set_default(self, attr, value):
        self.defaults[attr] = value

    def read_config(self, config_path):
        """Get conf file parameters
           Ensure Conf file is sane"""
        try:
            self.conf = ConfigParser.ConfigParser()
            self.conf.read(config_path)
        except ConfigParser.Error, e:
            sys.stderr.write("\nError: Error reading configuration file '%s':\n" % config_path)
            sys.stderr.write("%s\n" % e)
            sys.exit(1)

        # TODO: this belongs elsewhere
        # tell the config object to cast to the correct types
        self.set_type("LOGLEVEL", int)
        self.set_type("DEBUG", int)
        self.set_type("REPAIR_DELAY", int)
        self.set_type("ALERT_DELAY", int)
        self.set_type("SESSION_COOKIE_AGE", int)

        # TODO: this also belongs elsewhere
        self.set_default("SESSION_COOKIE_AGE", 3600)

    def __getattr__(self, attr):
        # TODO: hack to set LOGLEVEL to the correct config name
        # we should fix the config file

        if attr == "LOGLEVEL":
            attr = "LOGVERB"

        try:
            value = self.conf.get("xsftpd", attr)
        except ConfigParser.Error:
            if self.defaults.has_key(attr):
                value = self.defaults[attr]
            else:
                raise AttributeError(attr)


        if attr in self.types:
            return self.types[attr](value)
        else:
            return value

config = Config()

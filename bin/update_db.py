#!/usr/bin/python
############################################################################
# update_db.py - Fcombine DB updater
# ############################################
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

import sqlite3
import os
import sys
import shutil
import time
from pwd import getpwnam
# Update the python path so we can import our django project
sys.path.append("/opt/fcombine/www")
os.environ["DJANGO_SETTINGS_MODULE"]="xsftp.settings"
import xsftp.webui.constants as c

class FC_Database(object):
    db_file = None
    connection = None
    cursor = None

    def __init__(self, db_file):
        self.db_file = db_file
        if not self.connection:
            connection = sqlite3.connect(self.db_file)
            self.connection = connection
            self.cursor = self.connection.cursor()

    def do_query(self, q_string, commit=False):
        if not self.cursor: raise "Not connected to DB"
        self.cursor.execute(q_string)
        if commit: self.connection.commit()
        return self.cursor.fetchall()

    def get_version(self):
        try:
            version = self.do_query('SELECT * FROM webui_database')
            version = version[0][0]
        except sqlite3.OperationalError:
            try:
                self.do_query('SELECT key_generation_time from webui_userprofile')
                version = 1
            except sqlite3.OperationalError:
                version = 2
        return version

    def close(self):
        self.cursor.close()
        self.connection.close()
        self.cursor = self.connection = None


def update_db(db):
    '''
    Updates Fcombine DB schema version to current.
    Creates backup of original DB and returns full path to backup.
    '''
    backup_filename = "%s/%s_%s" % (os.path.dirname(db.db_file), os.path.basename(db.db_file), time.strftime('%Y_%m_%d'))
    shutil.copy2(db.db_file, backup_filename)
    os.chown(backup_filename, getpwnam('apache')[2], 0)
    batch_queries = [   'CREATE TEMPORARY TABLE webui_userprofile_backup ("user_id" integer NOT NULL UNIQUE PRIMARY KEY REFERENCES "auth_user" ("id"), "comment" varchar(512) NOT NULL, "expiry" date NULL, "change_password" bool NOT NULL, "is_demo_user" bool NOT NULL, "internal_auth" bool NOT NULL)',
                        'INSERT INTO webui_userprofile_backup SELECT user_id,comment,expiry,change_password,is_demo_user,internal_auth FROM webui_userprofile',
                        'DROP TABLE webui_userprofile',
                        'CREATE TABLE webui_userprofile("user_id" integer NOT NULL UNIQUE PRIMARY KEY REFERENCES "auth_user" ("id"), "comment" varchar(512) NOT NULL, "expiry" date NULL, "change_password" bool NOT NULL, "is_demo_user" bool NOT NULL, "internal_auth" bool NOT NULL)',
                        'INSERT INTO webui_userprofile SELECT user_id,comment,expiry,change_password,is_demo_user,internal_auth FROM webui_userprofile_backup',
                        'DROP TABLE webui_userprofile_backup',
                        'ALTER TABLE "webui_configuration" ADD COLUMN "smtp_port" integer NOT NULL default 25',
                        'ALTER TABLE "webui_server" ADD COLUMN "type" varchar(30) NOT NULL default "sftp"',
                        'ALTER TABLE "webui_server" ADD COLUMN "ftp_port" integer NULL default 21',
                        'ALTER TABLE "webui_server" ADD COLUMN "ftp_password" varchar(512) NULL',
                        'ALTER TABLE "webui_server" ADD COLUMN "ftp_passive" bool NOT NULL default 1',
                        'ALTER TABLE "webui_server" ADD COLUMN "ftp_ssl" bool NOT NULL default 1',
                        'ALTER TABLE "webui_server" ADD COLUMN "ftp_ssl_implicit" bool NOT NULL default 0',
                        'ALTER TABLE "webui_server" ADD COLUMN "cifs_password" varchar(512) NULL',
                        'ALTER TABLE "webui_server" ADD COLUMN "cifs_share" varchar(512) NOT NULL default ""',
                        'ALTER TABLE "webui_server" ADD COLUMN "cifs_port" integer NULL',
                        'CREATE TABLE webui_database("version" integer NOT NULL default 0)',
                        'DELETE FROM webui_database',
                        'INSERT INTO webui_database VALUES (3)',
                    ]
    count = 0
    for q in batch_queries:
        count += 1
        if count == int(round(len(batch_queries) / 5.0)):
            sys.stdout.write('.')
            sys.stdout.flush()
            count = 0
        try:
            db.do_query(q)
        except sqlite3.OperationalError, e:
            pass
    db.connection.commit()
    return backup_filename


if __name__ == "__main__":
    if not os.path.isfile(c.DB_FILE):
        print "ERROR: Can not find Fcombine database file at expected location '%s'" % db_path
        sys.exit(1)
    db = FC_Database(c.DB_FILE)
    current_db_version = db.get_version()
    if c.DB_EXPECTED_VERSION != current_db_version:
        sys.stdout.write("Upgrading Fcombine database from version %s to %s." % (current_db_version, c.DB_EXPECTED_VERSION))
        sys.stdout.flush()
        backup_file_path = update_db(db)
        db.close()
        print 'Done.\nA backup of the old DB is located at: %s' % backup_file_path
    else:
        print "Fcombine Database already up to date at version %s." % current_db_version

    





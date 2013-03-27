#!/usr/bin/python
############################################################################
# jobrunner.py - Fcombine Job Runner 
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

from datetime import datetime
import time
import subprocess
import re
import glob
# First, lock in the current time
# We do this before all the other import stuff, because it might take too long, by which time we might slip in to the next minute or something.
currentTime = datetime.now()
# Update the python path so we can import our django project
import sys
sys.path.append("/opt/fcombine/www")
import xsftp.webui.models
import xsftp.webui.constants
import shutil
import os
import signal
from xsftp.webui.constants import log, Log
import tempfile
import xsftp.webui.forms
import stat
from xsftp.common import email
from xsftp.webui.views import is_daemon_running
import xsftp.common.constants

# Parse CLI options - we are dangerously assuming here because we are the only ones calling this program and know its interface. #TODO add error checking in version 2
if len(sys.argv) == 3 and sys.argv[1] == "--runnow":
	runNow = True
	jobIDArg = sys.argv[2]
else:
	runNow = False
	jobIDArg = sys.argv[1]

# grab 2 instances of the job - one as a pristine source (used for updating the db and such), and the other to mangle with pre-script data which we expect to live only for the duration of this jobrunner process
job = xsftp.webui.models.Job.objects.get(id=jobIDArg)
job_temp = xsftp.webui.models.Job.objects.get(id=jobIDArg)

# set the umask to 000
os.umask(000)

###############################
# CONSTANTS
###############################

# This dictionary block defines each field that a prescript is allowed to pass back, as well as the regular expression that defines a valid value for that field
BOOL_PATTERN = re.compile(r"^true$|^false$", re.IGNORECASE)
field_dict = {
	"source_server_link" : xsftp.webui.forms.VALID_SERVERLINKNAME_PATTERN,
	"dest_server_link" : xsftp.webui.forms.VALID_SERVERLINKNAME_PATTERN,
	"dest_path" : re.compile(r"^.{,1024}$"),
	"delete_source" : BOOL_PATTERN,
	"continue_on_error" : BOOL_PATTERN,
	"use_post_script" : BOOL_PATTERN,
	"post_script" : xsftp.webui.forms.VALID_SCRIPTNAME_PATTERN,
	"alert_owner_on_success" : BOOL_PATTERN,
	"alert_owner_on_fail" : BOOL_PATTERN,
	"suppress_group_alerts" : BOOL_PATTERN,
	"cancel_job" : BOOL_PATTERN,
	"custom" : re.compile(r"^.{,4000}$"),
	"exist_action":re.compile(r"^[0123]$"),
	"source_file" : re.compile(r"^.{1,1024}$"),
}

# initialise the custom env var, used for the pre/pst script API
CUSTOM = ""

###############################
# CLASSES
###############################

class SigtermException(Exception):
	'''
	Raised by the sigterm handler function in event of reception of a terminate signal.
	'''
	pass


class FileInfo:
	# This will be used to track various info about each file or directory that has been selected for transfer
	# start_time - datetime object
	# end_time - datetime object
	# file_size - integer, in bytes
	# src_path - the format of this variable will change as we progress through the code
	# dest_path - a string representing the full path on the appliances file system. set to None if the destination exists, but we don't want to mark this file as failed
	# status - True for success, False for fail
	# message - a human readable string that is yay
	# attempted - boolean field that indicates whether or not the copy/move process was begun for this file

	def __init__(self, src_path, attempt=True, message=None):
		self.start_time = None
		self.end_time = None
		self.file_size = None
		self.src_path = src_path
		self.dest_path = None
		self.message = message
		self.status = True # Files are considered valid by default, until we find a problem with them. 
		self.attempt = attempt # whether or not to attempt to copy this file
		if not attempt:	
			self.status = False
		self.attempted = False

class JobReport:
	# start time
	# end time
	# status (success (True) or failure (False)) should be set to success by default, then set to fail if/when something goes wrong
	# pre_script output - a three-tuple (exit code - an integer, stdout - a big string, stderr - a string)
	# post_script output - a three-tuple (exit code - an integer, stdout - a big string, stderr - a string)
	# message - a human readable string that is yay
	
	def __init__(self):
		self.status = True
		self.start_time = currentTime
		self.source_files = list()
		self.message = None
		self.pre_script_output = None
		self.post_script_output = None

	def get_source_files_to_attempt(self):
		return [source_file for source_file in self.source_files if source_file.attempt]

	def render(self):
		self.render_to_syslog()
		# if this job has specified to send email alerts
		if job_temp.alert_owner_on_success or job_temp.alert_owner_on_fail or not job_temp.suppress_group_alerts:
			self.render_to_email()

	def render_to_email(self):
		recipients = list()
		if self.status:
			# Gather the 'alert on success' users
			# 1) Global Alert Users
			global_groups = xsftp.webui.models.Configuration.objects.all()[0].job_success_alert_groups.all()
			# global_groups is now just a list of groups
			# for each of those groups in global_groups, we want to get out all the users
			for group in global_groups:
				for user in group.users.all():
					if user not in recipients:
						recipients.append(user)
			# 2) Job Specific Groups
			if not job_temp.suppress_group_alerts:
				job_groups = job_temp.alert_groups_on_success.all()
				for group in job_groups:
					for user in group.users.all():
						if user not in recipients:
							recipients.append(user)
			# 3) Job Owner
			if job_temp.alert_owner_on_success and job_temp.owner not in recipients:
				recipients.append(job_temp.owner)
		else:
			# Gather the 'alert on fail' users
			# 1) Global Alert Users
			global_groups = xsftp.webui.models.Configuration.objects.all()[0].job_failure_alert_groups.all()
			# global_groups is now just a list of groups
			# for each of those groups in global_groups, we want to get out all the users
			for group in global_groups:
				for user in group.users.all():
					if user not in recipients:
						recipients.append(user)
			# 2) Job Specific Groups
			if not job_temp.suppress_group_alerts:
				job_groups = job_temp.alert_groups_on_fail.all()
				for group in job_groups:
					for user in group.users.all():
						if user not in recipients:
							recipients.append(user)
			# 3) Job Owner
			if job_temp.alert_owner_on_fail and job_temp.owner not in recipients:
				recipients.append(job_temp.owner)
		email_addresses = [user.email for user in recipients if user.email]
		# Generate some strings that will be used in the message
		# Duration String
		duration = self.end_time - self.start_time
		total_seconds = duration.seconds + (duration.days * 86400)
		hours = total_seconds / 3600
		minutes = total_seconds % 3600 / 60
		seconds = total_seconds % 3600 % 60
		duration_string = "%002d:%002d:%002d" % (hours, minutes, seconds)
		# Data Transferred string
		if self.source_files:
			total_data = reduce(lambda x, y: x + y, [f.file_size for f in self.source_files if f.file_size is not None] or [0])
		else:
			total_data = 0
		total_data = int(total_data)
		if total_data / 1024**3:
			data = "%.2f GB" % (float(total_data)/1024**3)
		elif total_data / 1024**2:
			data = "%.2f MB" % (float(total_data)/1024**2)
		elif total_data / 1024:
			data = "%.2f KB" % (float(total_data)/1024)
		else:
			data = "%s bytes" % total_data
		if not self.source_files:
			data = "0 (no source files selected for copy)"
		# PreScript String
		if job.use_pre_script:
			pre_script_string = "\nPrescript: %s" % job.pre_script.script_name
		else:
			pre_script_string = ""
		if job_temp.use_post_script:
			post_script_string = "\nPostscript: %s" % job_temp.post_script.script_name
		else:
			post_script_string = ""
		# generate the message
		# generate message, starting with pre-script and postscript message blocks
		pre_script_block = post_script_block = ""
		if self.pre_script_output:
			pre_script_block = "\nPre-Script Output\n=================\n***** Return Code:\n%s\n***** Output Data (stdout):\n%s\n***** Output Data (stderr):\n%s\n" % (
				self.pre_script_output[0],
				self.pre_script_output[1],
				(self.pre_script_output[2] or "None"),
			)
		if self.post_script_output:
			post_script_block = "\nPost-Script Output\n==================\n***** Return Code:\n%s\n***** Output Data (stdout):\n%s\n***** Output Data (stderr):\n%s\n" % (
				self.post_script_output[0],
				(self.post_script_output[1] or "None"),
				(self.post_script_output[2] or "None"),
			)
		# generate full message
		message = """
This is an automatic message from Fcombine: %(device_name)s

The Job '%(job_name)s' has %(statusString)s
See attachment for per-file details.

Job Information
===============
Job Name: %(job_name)s
Owner: %(owner)s
Comment: %(comment)s
Run Count: %(count)s%(prescript)s%(postscript)s
%(runnow)s

Transfer Details
================
Source Server Link: %(source)s
Destination Server Link: %(dest)s
Destination Path: %(dest_path)s

Job Results
===========
Status: %(status)s
Message: %(message)s
Start Time: %(start)s
End Time: %(end)s
Duration: %(dur)s
Data Transfer Size: %(data)s
%(pre_script_output)s
%(post_script_output)s
""" % {	"device_name":xsftp.webui.models.Configuration.objects.all()[0].device_name,
		"job_name":job.job_name,
		"owner":job.owner.username,
		"comment":job.comment,
		"count":job.run_count,
		"prescript":pre_script_string,
		"postscript":post_script_string,
		"status":["Success", "Fail"][[True, False].index(self.status)],
		"statusString": ["COMPLETED SUCCESSFULLY.", "FAILED."][[True, False].index(self.status)],
		"message":self.message,
		"start":self.start_time.ctime(),
		"end":self.end_time.ctime(),
		"dur":duration_string,
		"data":data,
		"source":job_temp.source_server.server_name,
		"dest":job_temp.dest_server.server_name,
		"dest_path":job_temp.dest_path,
		"runnow":["", "This job was invoked manually"][self.runnow],
		"pre_script_output":pre_script_block,
		"post_script_output":post_script_block,
		}
		# generate the attachment content
		attachment_content = """Source Files,Destination File Name,Size (bytes),Attempted,Status,Start Time,End Time,Duration (seconds),Message\n"""
		source_strip = len(xsftp.common.constants.SMP_DIR + str(job_temp.source_server.id))
		dest_strip = len(xsftp.common.constants.SMP_DIR + str(job_temp.dest_server.id))
		for f in self.source_files:
			sourceString = "%s:%s" % (job_temp.source_server.server_name, f.src_path[source_strip:])
			if f.dest_path:
				destString = "%s:%s" % (job_temp.dest_server.server_name, f.dest_path[dest_strip:])
			else:
				destString = "None"
			if f.start_time:
				start_string = f.start_time.ctime()
			else:
				start_string = ""
			if f.end_time:
				end_string = f.end_time.ctime()
			else:
				end_string = ""
			if f.end_time:
				duration = (f.end_time - f.start_time).seconds
			else:
				duration = None
			attachment_content += """%(src)s,%(dest)s,%(size)s,%(attempted)s,%(status)s,%(start)s,%(end)s,%(dur)s,%(msg)s\n""" % {"src":sourceString, "dest":destString, "size":f.file_size, "status":["Pass", "Fail"][[True, False].index(f.status)], "attempted":["Yes", "No"][[True, False].index(f.attempted)], "start":start_string, "end":end_string, "dur":duration, "msg":f.message or ""}
		try:
			email.send_email(subject="Fcombine Job Report for job '%s': %s" % (job.job_name, ["SUCCESS", "FAIL"][[True, False].index(self.status)]), body=message, to=email_addresses, attachments=[('Fcombine_Job_Details.csv', attachment_content, 'text/csv')])
		except xsftp.webui.constants.Email_Error, e:
			log("Error sending email report for job '%s': %s" % (job.job_name, e))

	def render_to_syslog(self): #TODO Gen2: give a bit more detail about the job in the logs, since this is the only place that the report data will be stored if the email report fails or needs to be retreived.
		if job_report.status:
			log("Job '%s' completed successfully" % (job.job_name))
		else:
			# no need to log here on failure as fail_job() function already logged it.
			pass

###############################
# UTILITY!!!!!!!!!! FUNCTIONS
###############################

def fail_job(message):
	log("Failed Job '%s',  message is '%s'" % (job.job_name, message))
	job_report.status = False
	job_report.message = message
	job_report.end_time = datetime.now()
	updateJobDetails()
	job_report.render()
	sys.exit(-1)

def updateJobDetails():
	''' This sets all the attributes of a job when it is time to finish '''
	job.running_now = False
	job.last_run_time = job_report.start_time
	job.last_run_status = job_report.status
	# calculate the job's duration in seconds
	duration = datetime.now() - job_report.start_time
	job.last_run_duration = duration.seconds + (duration.days*86400)
	job.pid = None
	job.message = job_report.message
	job.save()

def handleSigTerm(signal, frame):
	raise SigtermException

def stat_copy(src, dst, catch_errors=True):
	"""Copy all stat info (mode bits, atime and mtime) from src to dst"""
	st = os.stat(src)
	mode = stat.S_IMODE(st.st_mode)
	if hasattr(os, 'chmod'):
		try:
			os.chmod(dst, mode)
		except Exception, e:
			if catch__errors: raise e
			else: pass
	if hasattr(os, 'utime'):
		try:
			os.utime(dst, (st.st_atime, st.st_mtime))
		except Exception, e:
			if catch__errors: raise e
			else: pass


def file_copy(src, dst, catch_copy_metadata_errors=False):
	# copy the data
	if os.path.isdir(dst):
		dst = os.path.join(dst, os.path.basename(src))
	shutil.copyfile(src, dst)
	# copy the metadata
	stat_copy(src, dst, catch_copy_metadata_errors)


def tree_copy(src, dst, symlinks=False, catch_copy_metadata_errors=False):
	"""Recursively copy a directory tree using copy().

	The destination directory must not already exist.
	If exception(s) occur, an Error is raised with a list of reasons.

	If the optional symlinks flag is true, symbolic links in the
	source tree result in symbolic links in the destination tree; if
	it is false, the contents of the files pointed to by symbolic
	links are copied.

	If the optional catch_copy_metadata_errors flag is true, then errors
	seen while copying permission bits, last access time, last modification time,
	and flags from src to dst will be raised, otherwise they will be ignored.
	"""
	names = os.listdir(src)
	os.makedirs(dst)
	errors = []
	for name in names:
		srcname = os.path.join(src, name)
		dstname = os.path.join(dst, name)
		try:
			if symlinks and os.path.islink(srcname):
				linkto = os.readlink(srcname)
				os.symlink(linkto, dstname)
			elif os.path.isdir(srcname):
				tree_copy(srcname, dstname, symlinks, catch_copy_metadata_errors)
			else:
				file_copy(srcname, dstname, catch_copy_metadata_errors)
			# XXX What about devices, sockets etc.?
		except (IOError, os.error), why:
			errors.append((srcname, dstname, str(why)))
		# catch the Error from the recursive copytree so that we can
		# continue with other files
		except EnvironmentError, err:
			errors.extend(err.args[0])
	try:
		stat_copy(src, dst, catch_copy_metadata_errors)
	except WindowsError:
		# can't copy file access times on Windows
		pass
	except OSError, why:
		errors.extend((src, dst, str(why)))
	if errors:
		raise EnvironmentError, errors


###############################
#    CODE STARTS HERE
###############################

sys.stdout = sys.stderr = Log()
#----------------------------------
if not runNow:
	# Check if the job has an expiry, and if so check if it has expired, (all jobs)
	if job.expiry and job.expiry < currentTime:
		sys.exit(0)
	# If job is run_once, check that we have the right year
	if job.schedule_type == 0 and job.run_at.year != currentTime.year:
		sys.exit(0)
	log("Job '%s' received start signal from scheduler and is starting..." % job.job_name)
else:
	log("Job '%s' received 'Run Now' signal from user and is starting..." % job.job_name)
job_report = JobReport()
# Set appropriate details on job_report and job object, and save the job
job_report.runnow = runNow
job_report.start_time = job.start_time = datetime.now()
job.run_count += 1
job.pid = os.getpid()
job.running_now = True
# Register a handler for a SIGTERM
signal.signal(signal.SIGTERM, handleSigTerm)
try:
	job.save()
	# check if the job is sane
	if job.errorFlags:
		fail_job("Job failed sanity checks.")
	# check if daemon is running
	if not is_daemon_running():
		fail_job('The Fcombine service was not running')
	# Check if the source and dest servers are healthy
	if job.source_server.status:
		fail_job("Source server link '%s' was not available" % (job.source_server.server_name))
	if job.dest_server.status:
		fail_job("Destination server link '%s' was not available" % (job.dest_server.server_name))
	#---------------------------------
	source_files = [source_glob.glob for source_glob in job.glob_set.all()] # If the pre-script specifies and source globs, then it will overwrite source_files
	# If a prescript is set ...
	if job.use_pre_script:
		# First, generate an environment based on the job's attributes
		env = dict()
		env["fc_job_name"] = job.job_name
		env["fc_owner"] = job.owner.username
		env["fc_comment"] = job.comment
		if job.last_run_time:
			env["fc_last_run_time"] = time.mktime(job.last_run_time.timetuple())
		if job.last_run_status:
			env["fc_last_run_status"] = job.last_run_status
		if job.last_run_duration:
			env["fc_last_run_duration"] = job.last_run_duration
		env["fc_schedule_type"] = job.schedule_type
		if job.run_at:
			env["fc_run_at"] = time.mktime(job.run_at.timetuple())
		if job.minute:
			env["fc_minute"] = job.minute
		if job.hour:
			env["fc_hour"] = job.hour
		if job.day:
			env["fc_day"] = job.day
		if job.month:
			env["fc_month"] = job.month
		if job.dow:
			env["fc_dow"] = job.dow
		if job.expiry:
			env["fc_expiry"] = time.mktime(job.expiry.timetuple())
		env["fc_run_count"] = job.run_count
		env["fc_source_server_link"] = job.source_server.server_name
		env["fc_dest_server_link"] = job.dest_server.server_name
		env["fc_dest_path"] = job.dest_path
		env["fc_delete_source"] = job.delete_source
		env["fc_exist_action"] = job.exist_action
		env["fc_continue_on_error"] = job.continue_on_error
		env["fc_use_post_script"] = job.use_post_script
		if job.post_script:
			env["fc_post_script"] = job.post_script.script_name
		env["fc_alert_owner_on_success"] = job.alert_owner_on_success
		env["fc_alert_owner_on_fail"] = job.alert_owner_on_fail
		env["fc_suppress_group_alerts"] = job.suppress_group_alerts
		if job.alert_groups_on_success.all():
			env["fc_alert_groups_on_success"] = "\n".join([g.group_name for g in job.alert_groups_on_success.all()])
		if job.alert_groups_on_fail.all():
			env["fc_alert_groups_on_fail"] = "\n".join([g.group_name for g in job.alert_groups_on_fail.all()])
		env["fc_source_files"] = "\n".join([g.glob for g in job.glob_set.all()])
		# subprocess requires that all environment variables are strings, so the next two lines take care of that
		for key in env.keys():
			env[key] = str(env[key])
		# call the pre_script
		pre_script_process = subprocess.Popen(xsftp.webui.constants.SCRIPT_PATH + job.pre_script.file, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
		# collect the results
		pre_script_ret = pre_script_process.wait()
		pre_script_out = pre_script_process.stdout.read()
		pre_script_err = pre_script_process.stderr.read()
		# record prescript results in job_report
		job_report.pre_script_output = (pre_script_ret, pre_script_out, pre_script_err)

		################## Now affect the current job with the results from the prescript ######################
		# chop the results on \n
		lines = pre_script_out.split("\n")
		all_lines_ok = True
		fields = list()
		fail_job_message = None #empty message means job does not fail in this prescript-processing logic. We need to execute all of the pre-script processing logic before (if necessary) failing the job to ensure the job's characteristics are set (eg to ensure alerts are not sent inadvertantly if the prescript muted otherwise enabled alerts)
		# extract all the field=value pairs into a list of tuples
		for line in lines:
			if not line: # ignore empty lines
				continue
			# split the line on the first =
			line_parts = line.split("=", 1)
			# check that we get exactly two parts
			if len(line_parts) !=  2:
				fail_job_message = "Invalid line in pre-script output: '%s'" % line
			# assign each bit of line_parts to nice sounding variables
			field, value = (line_parts[0].strip(), line_parts[1].strip())
			# check for valid field name
			if field not in field_dict:
				fail_job_message = "Invalid field provided in pre-script output: '%s'" % line
			else:
				# check for valid value format
				if not field_dict[field].search(value):
					fail_job_message = "Invalid format for value in pre-script output: '%s'" % line
			# check that model referencing fields point to model instances that exist, and sanitise input fields and values
			if field == "source_server_link":
				if value not in [server.server_name for server in job.owner.userprofile.getAllReadServers()]:
					fail_job_message = "Invalid Server Link name provided in pre-script output: '%s'" % line
				else:
					field = "source_server"
					value = xsftp.webui.models.Server.objects.get(server_name=value)
			elif field == "dest_server_link":			
				if value not in [server.server_name for server in job.owner.userprofile.getEffectiveWriteServers()]:
					fail_job_message = "Invalid Server Link name provided in pre-script output: '%s'" % line
				else:
					field = "dest_server"
					value = xsftp.webui.models.Server.objects.get(server_name=value)
			elif field == "dest_path":
				pass
			elif field == "source_file":
				pass
			elif field == "delete_source":
				value = [False, True][value.lower() == "true"]
			elif field == "continue_on_error":
				value = [False, True][value.lower() == "true"]
			elif field == "use_post_script":
				value = [False, True][value.lower() == "true"]	
			elif field == "post_script":
				if value not in [script.script_name for script in job.owner.userprofile.getEffectiveScripts()]:
					fail_job_message = "Invalid Script name provided in pre-script output: '%s'" % line
				else:
					value = xsftp.webui.models.Script.objects.get(script_name=value)
			elif field == "alert_owner_on_success":
				value = [False, True][value.lower() == "true"]	
			elif field == "alert_owner_on_fail":
				value = [False, True][value.lower() == "true"]	
			elif field == "suppress_group_alerts":
				value = [False, True][value.lower() == "true"]	
			elif field == "cancel_job" and value.lower() == "true":
				fail_job_message = "Job was explicitly cancelled by pre-script"
			elif field == "exist_action":
				value = int(value) #value should match $[0123]^ as per regex check
			elif field == "custom":
				pass
			else:
				pass
			# OK, things look good, so add the field value pair to the list
			fields.append((field, value))
		if "source_file" in [thing[0] for thing in fields]:
			source_files = [thing[1] for thing in fields if thing[0] == "source_file"]
		# update job_temp accordingly
		for field, value in fields:
			if field == "custom":
				CUSTOM = value
			else:
				job_temp.__setattr__(field, value)
		if fail_job_message:
			fail_job(fail_job_message)
	
	#--------------------------------
	# Determine the source files based on the job's source globs, or whatever might have been returned by the pre-script, create a FileInfo object for each, and append them to the source_files list
	for source_file in source_files:
		# prepend each source_file with the source server links SMP
		full_glob = xsftp.common.constants.SMP_DIR + str(job_temp.source_server.id) + "/" + source_file
		file_list = glob.glob(full_glob)
		if not file_list:
			job_report.source_files.append(FileInfo(full_glob, attempt=False, message="No files match specified Source File"))
		else:
			for f in file_list:
				# Make sure they are not trying to break out of the designated source server
				f = os.path.realpath(f)
				if not f.startswith(xsftp.common.constants.SMP_DIR + str(job_temp.source_server.id)):
					fail_job("Invalid source file specified: %s" % f)
				job_report.source_files.append(FileInfo(f))

	# Clean up job_temp's dest_path, in case it starts with "/"s, which will fuck over os.path.join
	while job_temp.dest_path.startswith("/"):
		job_temp.dest_path = job_temp.dest_path[1:]

	# Try to create a temp file with an alpha-based name
	try:
		temp_handle, temp_name = tempfile.mkstemp(prefix="fcombine_temp_file", dir=os.path.join(xsftp.common.constants.SMP_DIR, str(job_temp.dest_server.id), job_temp.dest_path))
		#print temp_handle, temp_name
	except OSError: 
		# If that fails, try to create a directory
		try:
			temp_name = tempfile.mkdtemp(prefix="fcombine_temp_file", dir=os.path.join(xsftp.common.constants.SMP_DIR, str(job_temp.dest_server.id), job_temp.dest_path))
		except OSError:
			fail_job("Can not write to the specified destination path")
	temp_base_name = os.path.basename(temp_name)
	# vary the case of a letter for case-sensitive filesystem comparison
	different_name = os.path.join(xsftp.common.constants.SMP_DIR, str(job_temp.dest_server.id), job_temp.dest_path, "F" + temp_base_name[1:])
	#print "different name is %s" % different_name
	# Try to open the "different_name" file
	fs_case_sensitive = not os.path.exists(different_name)
	#print "Determined that fs_case_sensitive is %s" % fs_case_sensitive
	# Delete the temp file/directory
	try:
		if os.path.isfile(temp_name):
			os.unlink(temp_name)
		elif os.path.isdir(temp_name):
			shutil.rmtree(temp_name)
	except OSError: # TODO add a message to the job, or handle this somehow, because we couldn't delete the temp file/dir
		pass
	except Exception: # TODO - be less general
		pass

	#------------------------------
	# Now do some more reconnaisance on each source file ...
	all_dest_paths = list() # Stores each successful destination path, so that we can check whether or not these paths exist
	# for each file_info in source_files:
	for file_info in job_report.get_source_files_to_attempt():
		# by the time we get here, each file_info's src_path:
		#     - will be an absolute, realpathed path on the local appliance's file system
		#     - will NOT end in a slash.
		# we will also have a file_info.dest_path that:
		#     - must NOT start with a slash
		#     - must still be 'absolute' from the perspective of the destination server
		#     - must be a directory
		# set file_info.dest, based on dest_server/dest_path/src_name
		src_name = os.path.basename(file_info.src_path)
		#print "src_name is %s" % src_name
		# now we need to work out the destination name
		file_info.dest_path = os.path.join(xsftp.common.constants.SMP_DIR, str(job_temp.dest_server.id), job_temp.dest_path, src_name)
		file_info.dest_path = os.path.realpath(file_info.dest_path)
		#print "file_info.dest_path is %s " % file_info.dest_path
		# Check if the dest path is within the dest server tree
		if not file_info.dest_path.startswith(xsftp.common.constants.SMP_DIR + str(job_temp.dest_server.id)):
			fail_job("Invalid destination specified: %s" % file_info.dest_path)
		# if the file_info.dest_name already exists:
		if os.path.exists(file_info.dest_path) or file_info.dest_path in all_dest_paths or file_info.dest_path.lower() in [p.lower() for p in all_dest_paths if not fs_case_sensitive]: # Handle case sensitivity
			#print "file_info.dest_name already exists, either in the destination file system, or in all_dest_paths ..."
			#print "all_dest_paths is %s" % all_dest_paths
			if job_temp.exist_action == 0: # raise error
				file_info.message = "Destination exists"
				file_info.status = False
			elif job_temp.exist_action == 1: # skip the file
				file_info.message = "Destination exists: skipping file"
				file_info.dest_path = None # By setting to None, we can ignore this file when it comes time to copy it.
			elif job_temp.exist_action == 2: # overwrite existing, so we don't need to do anything
				# If we got here because the dest_path is in all_dest_paths, we need to fail the job to prevent data loss which might happen if we are in overwrite mode and we have two source files converging on the same destination name
				if file_info.dest_path in all_dest_paths or file_info.dest_path.lower() in [p.lower() for p in all_dest_paths if not fs_case_sensitive]:
					file_info.message = "Destination collides with previous file in this job when using Overwrite mode"
					file_info.status = False
				else:
					file_info.message = "Destination exists: overwriting"
					all_dest_paths.append(file_info.dest_path)
			elif job_temp.exist_action == 3: # auto_increment name
				#print "Entering auto-increment mode"
				suffix = 1
				while True:
					#print "Trying suffix %s" % suffix
					new_dest = "%s_%004d" % (file_info.dest_path, suffix)
					if not os.path.exists(new_dest) and not new_dest in all_dest_paths and not new_dest.lower() in [p.lower() for p in all_dest_paths if not fs_case_sensitive]:
						#print "Found an unused new name of %s" % new_dest
						file_info.dest_path = new_dest
						all_dest_paths.append(file_info.dest_path)
						file_info.message = "Destination exists: auto-incrementing filename"
						break # break out of the while loop
					suffix += 1
					if suffix > 9999: # if our suffix attempt has got too high, fail this file object
						file_info.status = False
						file_info.message = "Destination exists: filename auto-increment failed (increment count exceeded 9999) - error raised"
						break # break out of the while loop
		else:
			all_dest_paths.append(file_info.dest_path)
		# SET THE FILESIZE, and mark it in file_info.file_size
		# if the source is a file
		if os.path.isfile(file_info.src_path):
			file_info.file_size = os.stat(file_info.src_path).st_size
		# else if the source_path is a directory
		elif os.path.isdir(file_info.src_path):
			# add up the sizes of all files in the dir and its subdirs
			size = 0.0
			for (path, dirs, files) in os.walk(file_info.src_path):
				for f in files:
					if os.path.isfile(os.path.join(path, f)):
						size += os.path.getsize(os.path.join(path, f))
			file_info.file_size = size
		# else if it is neither a file or directory (eg a device node, a psuedofile or strange thing like that)
		else:
			file_info.file_size = 0.0
	
	# If the job is not set to continue on error, and any of the file_info.status's are fail, then fail the job
	if job_report.source_files and not job_temp.continue_on_error and not reduce(lambda x, y: x and y, [file_info.status for file_info in job_report.source_files]):
		fail_job("One or more files failed pre-copy checks")
	
	#==================================================
	#        START COPYING FILES
	#==================================================
	
	# run the job - by this stage, we have a list of source files in source_files
	# For each source (file or dir)
	for file_info in job_report.get_source_files_to_attempt():
		# skip any files which have bad status 
		if file_info.status == False or file_info.dest_path == None:
			break
		file_info.start_time = datetime.now()
		file_info.attempted = True
		# if the source is a file
		if os.path.isfile(file_info.src_path):
			try:
				# First, we need to check if the destination directory exists ...
				# So, get the endpoint directory
				dest_dir = file_info.dest_path[:file_info.dest_path.rfind("/")]
				# If the path doesn't yet exist ...
				if not os.path.exists(dest_dir):
					# create it
					os.makedirs(dest_dir)
				else:
					# the path exists already
					# if it's not a directory ...
					if not os.path.isdir(dest_dir):
						# bail out - the target 'directory' is in fact a file - not much we can do about that
						raise Exception("Destination directory is a file") #TODO - make our own exception for this
				file_copy(file_info.src_path, file_info.dest_path)
				file_info.message = "Success"
			except SigtermException:
				# we got a sigterm, fail this file and kill the job
				file_info.status = False
				file_info.message = "Job was forcibly terminated while copying this file"
				fail_job("Received termination signal - job was manually cancelled.")
			except IOError, e:
				# Got an IOError, could mean full destiantion disk
				file_info.status = False
				file_info.message = "An I/O error occurred while copying this file which could indicate a full disk on the destination system: %s" % (e)
				if not job_temp.continue_on_error:
					fail_job("An I/O Error occurred while copying file %s to %s which could indicate a full disk on the destination system: %s" % (file_info.src_path, file_info.dest_path, e))
			except Exception, e: #TODO be less general here
				# a bunch of shit could happen, deal with it accordingly.
				file_info.status = False
				file_info.message = "An unexpected Exception occurred while copying this file: %s" % (e)
				if not job_temp.continue_on_error:
					fail_job("An unexpected Exception occurred while copying file %s to %s: %s" % (file_info.src_path, file_info.dest_path, e))
		# else if the source is a directory
		elif os.path.isdir(file_info.src_path):
			if os.path.exists(file_info.dest_path):
				if os.path.isfile(file_info.dest_path):
					os.unlink(file_info.dest_path)
				elif os.path.isdir(file_info.dest_path):
					shutil.rmtree(file_info.dest_path)
				else:
					fail_job("Unable to remove destination path %s" % file_info.dest_path)
			try:
				tree_copy(file_info.src_path, file_info.dest_path)
				file_info.message = "Success"
			except SigtermException:
				# we got a sigterm, fail this file and kill the job
				file_info.status = False
				file_info.message = "Job was forcibly terminated while copying this directory"
				fail_job("Received termination signal - job was manually cancelled.")
			except Exception, e: #TODO be less general here
				file_info.status = False
				file_info.message = "An unexpected Exception occurred while copying this directory: %s" % (e)
				if not job_temp.continue_on_error:
					fail_job("An unexpected Exception occurred while copying file %s to %s: %s" % (file_info.src_path, file_info.dest_path, e))
		# else if the source is neither a file or a directory
		else:
			file_info.status = False
			file_info.message = "Error: Abnormal source '%s' is neither a file nor a directory" % file_info.src_path
			if not job_temp.continue_on_error:
				fail_job("Abnormal source error occurred while copying file %s to %s: Source was neither a file nor a directory" % (file_info.src_path, file_info.dest_path, file_info.src_path,))
		# if the job is set to delete source, so do it
		if job_temp.delete_source:
			try:
				if os.path.isfile(file_info.src_path):
					os.remove(file_info.src_path)
					file_info.message = "Removed source file"
				else:
					shutil.rmtree(file_info.src_path)
					file_info.message = "Removed source directory"
			except SigtermException:
				# we got a sigterm, fail this file and kill the job
				file_info.status = False
				file_info.message = "Job was forcibly terminated while deleting the source of this file/directory"
				fail_job("Received termination signal - job was manually cancelled.")
			except Exception, e:
				file_info.status = False
				file_info.message = "An Exception occurred while deleting the source of this file/directory: %s" % (e)
				if not job_temp.continue_on_error:
					fail_job("An Exception occurred while removing file/directory %s (who's destination was %s): %s" % (file_info.src_path, file_info.dest_path, e))
		file_info.end_time = datetime.now()
	
	###########################################
	# We've finished everything now, update job times ....
	updateJobDetails()
except SigtermException, e:
	# we got a sigterm, kill the job
	fail_job("Received termination signal - job was manually cancelled.")

#-----------------------------------
# run the postscript
# If a postscript is set...
if job_temp.use_post_script:
	# First, generate an environment
	env = dict()
	env["fc_job_name"] = job.job_name
	env["fc_owner"] = job.owner.username
	env["fc_comment"] = job.comment
	if job.last_run_time:
		env["fc_last_run_time"] = time.mktime(job.last_run_time.timetuple())
	env["fc_schedule_type"] = job.schedule_type
	if job.run_at:
		env["fc_run_at"] = time.mktime(job.run_at.timetuple())
	if job.minute:
		env["fc_minute"] = job.minute
	if job.hour:
		env["fc_hour"] = job.hour
	if job.day:
		env["fc_day"] = job.day
	if job.month:
		env["fc_month"] = job.month
	if job.dow:
		env["fc_dow"] = job.dow
	if job.expiry:
		env["fc_expiry"] = time.mktime(job.expiry.timetuple())
	env["fc_run_count"] = job.run_count # (alredy incremented)
	env["fc_source_server_link"] = job_temp.source_server.server_name
	env["fc_dest_server_link"] = job_temp.dest_server.server_name
	env["fc_dest_path"] = job_temp.dest_path
	env["fc_delete_source"] = job_temp.delete_source
	env["fc_exist_action"] = job.exist_action
	env["fc_continue_on_error"] = job_temp.continue_on_error
	env["fc_alert_owner_on_success"] = job_temp.alert_owner_on_success
	env["fc_alert_owner_on_fail"] = job_temp.alert_owner_on_fail
	env["fc_suppress_group_alerts"] = job_temp.suppress_group_alerts
	if job.alert_groups_on_success.all():
		env["fc_alert_groups_on_success"] = "\n".join([g.group_name for g in job_temp.alert_groups_on_success.all()])
	if job.alert_groups_on_fail.all():
		env["fc_alert_groups_on_fail"] = "\n".join([g.group_name for g in job_temp.alert_groups_on_fail.all()])
	env["fc_source_files"] = "\n".join(source_files)
	env["fc_runnow"] = runNow
	env["fc_custom"] = CUSTOM
	# subprocess requires that all environment variables are strings, so the next two lines take care of that
	for key in env.keys():
		env[key] = str(env[key])
	# call the post_script
	post_script_process = subprocess.Popen(xsftp.webui.constants.SCRIPT_PATH + job_temp.post_script.file, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
	# collect the results
	post_script_ret = post_script_process.wait()
	post_script_out = post_script_process.stdout.read()
	post_script_err = post_script_process.stderr.read()
	# record prescript results in job_report
	job_report.post_script_output = (post_script_ret, post_script_out, post_script_err)

# Finally end the job and render it
job_report.end_time = datetime.now()
job_report.render()
		


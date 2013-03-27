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

from django.core.files.uploadhandler import FileUploadHandler, StopFutureHandlers, SkipFile, StopUpload
from django.core.files.uploadedfile import UploadedFile
import subprocess
import pickle

class Upload_Handler(FileUploadHandler):

	def __init__(self, priv_exec_path, username, real_dir, debug_mode=False):
		self.debug_mode = debug_mode
		self.priv_exec_path = priv_exec_path
		self.username = username
		self.real_dir = real_dir
		self.messages = list()
		FileUploadHandler.__init__(self)
		if self.debug_mode:
			self.debug_file = file('/tmp/upload_handler.debug', 'a')

	def receive_data_chunk(self, raw_data, start):
        # Start dumping file data into privexec
		self.debug("Upload handler got a chunk: start at %s" % start)
		try:
			self.p.stdin.write(raw_data)
			self.p.stdin.flush()
			self.debug("Finished writing chunk to priv_exec process")
		except Exception, e: # XXX be more specific
			self.messages.append((False, "Error occurred while writing the file '%s': %s" % (self.file_name, e)))
			raise SkipFile()

	def file_complete(self, file_size):
		self.debug("Upload handler: file is finished")
		self.p.stdin.close()
		# Check that priv_exec got the same number of bytes as us
		try:
			priv_exec_output = self.p.stdout.read()
		except Exception, e:
			self.messages.append((False, "Error while reading from privexec for file '%s': %s" % (self.file_name, e)))
			self.debug("%s" % self.messages)
			return None
		try:
			priv_exec_output = pickle.loads(priv_exec_output)
		except Exception, e:
			self.messages.append((False, "Error while unpickling message from privexec for file '%s': %s" % (self.file_name, priv_exec_output)))
			self.debug("%s" % self.messages)
			return None
		if isinstance(priv_exec_output, Exception):
			self.messages.append((False, "Error uploading file '%s': %s" % (self.file_name, priv_exec_output)))
			return None
		else:
			byte_count = priv_exec_output
			if byte_count != file_size:
				self.messages.append((False, "Incorrect file size for file '%s': should be '%s' but got '%s'" % (self.file_name, file_size, byte_count)))
				return None
			# Return a basic UploadedFile object
			self.messages.append((True, "File '%s' successfully uploaded" % self.file_name))
		return UploadedFile()

	def new_file(self, field_name, file_name, content_type, content_length, charset):
		self.debug("Upload handler: starting new file - %s, %s, %s, %s, %s" % (field_name, file_name, content_type, content_length, charset))
		self.file_name = file_name
		# Open up a new privexec
		privexec_args = ["sudo", self.priv_exec_path, "--explorer_upload",  self.real_dir, self.file_name]
		self.p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
		# Check that everything opened up OK - ie we got a 200
		status = self.p.stdout.readline()
		status_num = status[:3]
		status_message = status[4:]
		if status_num != "200":
			self.messages.append((False, "Error uploading file '%s': %s" % (self.file_name, status_message)))
			raise SkipFile()

	def debug(self, msg):
		if self.debug_mode:
			self.debug_file.write("UPLOAD_H: %s\n" % msg)
			self.debug_file.flush()


class Max_Size_Upload_Handler(FileUploadHandler):
	'''
	A simple in-line upload handler that sets a max size limit on uploading files.
	Insert this handler at position 0 in request.request.upload_handlers
	'''

	def __init__(self, max_size):
		self.size_so_far = 0
		self.max_size = max_size
		self.message = ""
		FileUploadHandler.__init__(self)

	def receive_data_chunk(self, raw_data, start):
		self.size_so_far += len(raw_data)
		if self.size_so_far > self.max_size:
			self.message = "Uploaded file must not exceed %s. Upload aborted." % self.pretty_filesize(self.max_size)
			raise StopUpload
		return raw_data

	def file_complete(self, file_size):
		return None

	def pretty_filesize(self, bytes):
		if bytes >= 1073741824:
			return str(bytes / 1024 / 1024 / 1024) + ' GB'
		elif bytes >= 1048576:
			return str(bytes / 1024 / 1024) + ' MB'
		elif bytes >= 1024:
			return str(bytes / 1024) + ' KB'
		elif bytes < 1024:
			return str(bytes) + ' bytes'

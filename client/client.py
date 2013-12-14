import os
from subprocess import call
import cmd
import sys

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir)

from api2 import *
from path import *

def parse(arg):
	return tuple(map(str, arg.split()))

class LoginClient(cmd.Cmd):
	intro = "Welcome to the filesystem.  Type 'help' at any time to see a list of commands"
	prompt = "Enter 'login [username] [password]' to login or 'register [username] [password]' to create an account: "

	def do_login(self, arg):
		(username, password) = parse(arg)
		if api_login(username, password):
			fclient = FileClient()
			fclient.set_username(username)
			fclient.cmdloop()
		else:
			print "Username and password did not match"
				
	def do_register(self, arg):
		(username, password) = parse(arg)
		if api_create_user(username, password):
			fclient = FileClient()
			fclient.set_username(username)
			fclient.cmdloop()
		else:
			print "Registration failed"
	
class FileClient(cmd.Cmd):
	intro = "Welcome to the filesystem.  Type 'help' at any time to see a list of commands"

	def set_username(self, username):
		self.current_dir = "/" + username
		self.username = username
		self.prompt = "file-server:" + self.current_dir + " " + self.username + "$ "
		self.help_message = {"logout":"",\
												"ls":"",\
												"cd":"[path]",\
												"touch":"[path]",\
												"rm":"[path]",\
												"mv":"[path] [path]",\
												"mkdir":"[-r][path]",\
												"vim":"[path]",\
												"emacs":"[path]",\
												"verify":"[path]",\
												"rebuild":"[path]",\
												"logout":""}

	def do_help(self, arg):
		print "Supported commands:"
		for i in self.help_message.keys():
			print i, self.help_message[i]

	def do_ls(self, arg):
		args = parse(arg)
		if len(args) == 0:
			dir_contents = api_list_dir(self.current_dir)
		else:
			print "Error: ls takes no arguments"
			return
		ret = ""
		for  (name, ftype) in dir_contents:
			ret = ret + name + '\t'
		if ret != "":
			print ret
			
	def do_cd(self, arg):
		args = parse(arg)
		if len(args) == 0:
			self.current_dir = "/" + self.username
		elif len(args) == 1:
			path = get_absolute_path(self.current_dir, args[0])
			try:
				api_list_dir(path)
				self.current_dir = path
				self.prompt = "file-server:" + self.current_dir + " " + self.username + "$ "
			except:
				print "No such file or directory"
				return
		else:
			print "Error: cd takes argument(s) " + self.help_message["cd"]

	def do_touch(self, arg):
		args = parse(arg)
		if len(args) == 1:
			(path, fname) = split_path(get_absolute_path(self.current_dir, args[0]))
			try:
				api_list_dir(path)
				handle = api_create_file(get_absolute_path(path, fname))
				api_fwrite(handle, "")
				api_fflush(handle)
				api_fclose(handle)
			except:
				print "No such file or directory"
		else:
			print "Error: touch takes argument(s) " + self.help_message["touch"]
	
	def do_rm(self, arg):
		args = parse(arg)
		if len(args) == 1:
			(path, fname) = split_path(get_absolute_path(self.current_dir, args[0]))
			try:
				api_list_dir(path)
				api_rm(get_absolute_path(path, fname))
			except:
				print "No such file or directory"
		elif len(args) == 2:
			if args[0] == "-r":
				(path, fname) = split_path(get_absolute_path(self.current_dir, args[1]))
				try:
					api_list_dir(path)
					api_rm(get_metafile_path(get_absolute_path(path, fname)))
				except:
					print "No such file or directory"
		else:
			print "Error: rm takes argument(s) " + self.help_message["rm"]
	
	def do_mv(self, arg):
		args = parse(arg)
		if len(args) == 2:
			(path1, fname1) = split_path(get_absolute_path(self.current_dir, args[0]))
			(path2, fname2) = split_path(get_absolute_path(self.current_dir, args[1]))
			try:
				api_list_dir(path1)
				api_list_dir(path2)
				api_mv(get_absolute_path(path1, fname1), get_absolute_path(path2, fname2))
			except:
				print "No such file or directory"
		else:
			print "Error: mv takes argument(s) " + self.help_message["mv"]

	def do_mkdir(self, arg):
		args = parse(arg)
		if len(args) == 1:
			(path, fname) = split_path(get_absolute_path(self.current_dir, args[0]))
			try:
				api_list_dir(path)
				api_mkdir(get_absolute_path(self.current_dir, args[0]))
			except:
				print "No such file or directory"
		else:
			print "Error: mkdir takes argument(s) " + self.help_message["mkdir"]
	
	def do_vim(self, arg):
		run_editor('vim', arg, self.current_dir, self.help_message)

	def do_emacs(self, arg):
		run_editor('emacs', arg, self.current_dir, self.help_message)

	def do_logout(self, arg):
		api_logout()
		return True

	def do_verify(self,arg):
		args = parse(arg)
		if len(args) == 1:
			(path, fname) = split_path(get_absolute_path(self.current_dir, args[0]))
			try:
				handle = api_fopen(get_absolute_path(self.current_dir, args[0]),'r')
				if not verify_file(handle):
					raise Exception('Verify Failed')
				print "file verified"
			except Exception as inst:
				print type(inst)
				print inst
		else:
			print "Error: verify takes argument(s) " + self.help_message["verify"]
			
	def do_rebuild(self,arg):
		args = parse(arg)
		if len(args) == 1:
			(path, fname) = split_path(get_absolute_path(self.current_dir, args[0]))
			try:
				handle = api_fopen(get_absolute_path(self.current_dir, args[0]),'r')
				if not verify_file(handle):
					raise Exception('Verify Failed: Difflog inconsistent')
				rebuild_file(handle, True)
			except Exception as inst:
				print type(inst)
				print inst
		else:
			print "Error: rebuild takes argument(s) " + self.help_message["rebuild"]
		
def run_editor(which, arg, current_dir, help_message):
	args = parse(arg)
	if len(args) == 1:
		(path, fname) = split_path(get_absolute_path(current_dir, args[0]))
		try:
			api_list_dir(path)
			EDITOR = os.environ.get('EDITOR', which) #that easy!
			handle = api_fopen(get_absolute_path(current_dir, args[0]),'r')
			contents = api_fread(handle)

			tempfile = open('.temp.'+args[0],'w')
			tempfile.write(contents)
			tempfile.flush()
			call([EDITOR, tempfile.name])
			tempfile.flush()
			tempfile.close()
			temp_filename = '.temp.'+split_path(args[0])[1]
			tempfile = open(temp_filename,'r')
			new_contents = tempfile.read()
			handle = api_fopen(get_absolute_path(current_dir, args[0]),'w')
			api_fwrite(handle, new_contents)
			api_fflush(handle)
			api_fclose(handle)
			tempfile.close()
			os.remove(temp_filename)
		except:
			print "No such file or directory"
	else:
		print "Error: " + which + " takes argment(s) " + help_message[which]

def start_new_client():
	test = LoginClient()
	test.cmdloop()

start_new_client()

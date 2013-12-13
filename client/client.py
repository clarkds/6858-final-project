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
												"ls":"[path]",\
												"cd":"[path]",\
												"touch":"[file]",\
												"rm":"[file]",\
												"mv":"[path][path]",\
												"mkdir":"[path]",\
												"vim":"[file]",\
												"emacs":"[file]",\
												"share":"[user][file]",\
												"logout":""}


	def do_logout(self, arg):
		return True

	def do_help(self, arg):
		print "Supported commands:"
		for i in self.help_message.keys():
			print i, self.help_message[i]

	def do_ls(self, arg):
		args = parse(arg)
		if len(args) == 0:
			dir_contents = api_list_dir(self.current_dir)
		elif len(args) == 1:
			path = get_absolute_path(self.current_dir, args[0])
			if api_path_exists(path):
				dir_contents = api_list_dir(path)
			else:
				print "No such file or directory"
		ret = ""
		for  in dir_contents:
			ret = ret + name + '\t'
		print ret
			
	def do_cd(self, arg):
		args = parse(arg)
		if len(args) == 0:
			self.current_dir = "/" + username
		elif len(args) == 1:
			path = get_absolute_path(self.current_dir, args[0])
			if api_path_exists(path):
				self.current_dir = get_absolute_path(self.current_dir, args[0])
			else:
				print "No such file or directory"
		self.prompt = "file-server:" + self.current_dir + " " + self.username + "$ "

	def do_touch(self, arg):
		args = parse(arg)
		if len(args) == 1:
			api_create_file(get_absolute_path(self.current_dir, args[0]))
		else:
			print "Error"
	
	def do_rm(self, arg):
		args = parse(arg)
		if len(args) == 1:
			api_rm(get_parent_directory(get_absolute_path(self.current_dir, args[0])), get_absolute_path(self.current_dir, args[0]).split('/')[-1])
		else:
			print "Error"
	
	def do_mv(self, arg):
		args = parse(arg)
		if len(args) == 2:
			api_mv(get_absolute_path(args[0]), get_absolute_path(args[1]))
		else:
			print "Error"

	def do_mkdir(self, arg):
		args = parse(arg)
		if len(args) == 1:
			api_mkdir("/" + get_absolute_path(self.current_dir, args[0]))
		else:
			print "Error"
	
	def do_vim(self, arg):
		args = parse(arg)
		if len(args) == 1:
			EDITOR = os.environ.get('EDITOR','vim') #that easy!
			handle = api_fopen(get_absolute_path(self.current_dir, args[0]),'r')
			contents = api_fread(handle)

			tempfile = open('.temp.'+args[0],'w')
			tempfile.write(contents)
			tempfile.flush()
			call([EDITOR, tempfile.name])
			tempfile.flush()
			tempfile.close()
			tempfile = open('.temp.'+split_path(args[0])[1],'r')
			new_contents = tempfile.read()
			handle = api_fopen(get_absolute_path(self.current_dir, args[0]),'w')
			api_fwrite(handle, new_contents)
			api_fflush(handle)
			api_fclose(handle)

  
	def do_emacs(self, arg):
		args = parse(arg)
		pass
	
	def do_share(self, arg):
		args = parse(arg)
		pass

	def do_logout(self, arg):
		api_logout()
		return True
		
def start_new_client():
	test = LoginClient()
	test.cmdloop()

start_new_client()

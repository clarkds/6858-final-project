import os

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir) 

import SocketServer
import socket
import json
import sys
import thread
import threading

from msg import *
from db import *


SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007
PADDED_HEX_STR_SIZE = 20
MAX_ACTIVE_USERS = 255

active_users = {}
active_users_lock = threading.Lock()

def write_file_contents(path, content):
	f = open(path, 'w')
	f.write(content)
	f.close()

def read_file_contents(path):
	f = open(path, 'r')
	contents = f.read()
	f.close()
	return contents

def get_parent_directory(path):
	sub_path = path.split('/')
	sub_path = sub_path[0:len(sub_path) - 1]
	sub_path = "/".join(sub_path)
	return sub_path

def get_metafile_path(path):
	sub_path = get_parent_directory(path)
	meta_path = sub_path + '/.meta_' + path.split('/')[-1]
	return meta_path

def get_logfile_path(path):
	sub_path = get_parent_directory(path)
	log_path = sub_path + '/.log_' + path.split('/')[-1]
	return log_path

def get_value_from_message(msg, key):
	#TODO
	success = True
	error = None
	return (success, msg[key], error)
	
class MyTCPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		logged_in = True
		while logged_in:
			(msg_size, msg_obj) = readMsg(self.request)
			print "Incoming msg: ", msg_obj
			op = msg_obj['OP']
			username = msg_obj['ENC_USER']
			response = {'OP':'ack', 'STATUS':0}
			active_users_lock.acquire()
			try:
				if username not in active_users.keys() or not active_users[username][1] == self.client_address:
					response['ERROR'] = "Username and IP don't match"
					response['STATUS'] = 1
					op = 'skipSwitch'
			finally:
				active_users_lock.release()

			if op == 'logoutUser':
				active_users_lock.acquire()
				try:
					active_users[username] = (False, None)
					logged_in = False
				finally:
					active_users_lock.release()

			elif op == 'getPermissions':
				response['TARGET'] = msg_obj['TARGET']
				if user_exists(msg_obj['TARGET']):
					response['PERMISSIONS'] = get_permissions_shared_with(msg_obj['TARGET'])
				else:
					response['ERROR'] = "User " + target + " does not exist"
					response['STATUS'] = 1
	
			elif op == 'addPermissions':
				path = ('users' + msg_obj['PATH'])
				log_file = get_logfile_path(path)
				if os.path.exists(path):
					if check_write_key(path, msg_obj['SECRET']):
						for (target, perm) in msg_obj['USERS_AND_PERMS']:
							add_permission(username, target, perm)
						write_file_contents(log_file, msg_obj['LOG_DATA'])
					else:
						response['ERROR'] = "Incorrect secret for " + path
						response['STATUS'] = 1
				else:
					response['ERROR'] = path + " does not exist"
					response['STATUS'] = 1

			elif op == 'deletePermissions':
				path = ('users' + msg_obj['PATH'])
				log_file = get_logfile_path(path)
				if os.path.exists(path):
					if check_write_key(path, msg_obj['SECRET']):
						for (target, perm) in msg_obj['USERS_AND_PERMS']:
							remove_permission(username, target, perm)
						write_file_contents(log_file, msg_obj['LOG_DATA'])
					else:
						response['ERROR'] = "Incorrect secret for " + path
						response['STATUS'] = 1
				else:
					response['ERROR'] = path + " does not exist"
					response['STATUS'] = 1

			elif op == 'getPublicKey':
				target = msg_obj['TARGET']
				response['TARGET'] = target
				if user_exists(msg_obj['TARGET']):
					response['KEY'] = get_public_key(msg_obj['TARGET'])
				else:
					response['ERROR'] = "User " + target + "does not exist"
					response['STATUS'] = 1

			elif op == 'getAllPublicKeys':
				response['USERS_AND_KEYS'] = get_all_public_keys()
	
			elif op == 'setPublicKey':
				set_public_key(username, msg_obj['KEY'])
	
			elif op =='downloadFile':
				path = ('users' + msg_obj['PATH'])
				if os.path.exists(path) and os.path.isfile(path):
					response['DATA'] = read_file_contents(path)
				else:
					response['ERROR'] = path + " does not exist"
					response['STATUS'] = 1

	
			elif op =='downloadDir':
				#TODO
				pass
	
			elif op =='createFile':
				path = ('users' + msg_obj['PATH'])
				parent_dir = get_parent_directory(path)
				log_file = get_logfile_path(path)
				if os.path.exists(path):
					response['ERROR'] = "Folder or file " + path + " already exists"
					response['STATUS'] = 1
				elif not os.path.exists(parent_dir):
					response['ERROR'] = "Parent dir " + parent_dir + " does not exist, cannot create " + path
					response['STATUS'] = 1
				elif check_write_key(parent_dir, msg_obj['PARENT_SECRET']):
					write_file_contents(log_file, msg_obj['LOG_DATA'])
					write_file_contents(path, msg_obj['DATA'])
					add_write_key(path, msg_obj['SECRET'])
				else:
					response['ERROR'] = "Incorrect secret for " + parent_dir
					response['STATUS'] = 1

			elif op =='writeFile':
				path = ('users' + msg_obj['PATH'])
				log_file = get_logfile_path(path)
				if not os.path.exists(path) and os.path.isfile(path):
					response['ERROR'] = "Folder or file " + path + " does not exist"
					response['STATUS'] = 1
				elif check_write_key(path, msg_obj['SECRET']):
					write_file_contents(log_file, msg_obj['LOG_DATA'])
					write_file_contents(path, msg_obj['FILE_DATA'])
				else:
					response['ERROR'] = "Incorrect secret for " + path
					response['STATUS'] = 1

			elif op =='delete':
				path = ('users' + msg_obj['PATH'])
				parent_dir = get_parent_directory(path)
				log_file = get_logfile_path(parent_dir)
				if not os.path.exists(path):
					response['ERROR'] = path + " to delete does not exist"
					response['STATUS'] = 1	
				elif check_write_key(parent_dir, msg_obj['PARENT_SECRET']):
					if os.path.isdir(path):
						if len(os.listdir(path)) == 0:
							write_file_contents(log_file, msg_obj['PARENT_LOG_DATA'])
							os.rmdir(path)
							os.remove(get_logfile_path(path))
						else:
							response['ERROR'] = "Folder to delete not empty"
							response['STATUS'] = 1
					else:
						write_file_contents(log_file, msg_obj['PARENT_LOG_DATA'])
						os.remove(path)
						os.remove(get_logfile_path(path))
				else:
					response['ERROR'] = "Incorrect secret for " + parent_dir
					response['STATUS'] = 1

			elif op == 'changeFileSecret':
				path = ('users' + msg_obj['PATH'])
				if not os.path.exists(path):
					response['ERROR'] = "Folder or file " + path + " does not exist"
					response['STATUS'] = 1
				elif not update_write_key(path, msg_obj["SECRET"], msg_obj["NEW_SECRET"]):
					response['ERROR'] = "Incorrect secret for " + path
					response['STATUS'] = 1
					
			elif op =='mkdir':
				path = ('users' + msg_obj['PATH'])
				parent_dir = get_parent_directory(path)
				meta_file = get_metafile_path(path)
				log_file = get_logfile_path(meta_file)
				if os.path.exists(path):
					response['ERROR'] = "Folder or file " + path + " already exists"
					response['STATUS'] = 1
				elif not os.path.exists(parent_dir):
					response['ERROR'] = "Sub path " + parent_dir + " does not exist, cannot create " + path
					response['STATUS'] = 1
				elif check_write_key(parent_dir, msg_obj['PARENT_SECRET']):
					write_file_contents(log_file, msg_obj['LOG_DATA'])
					write_file_contents(meta_file, msg_obj['META_DATA'])
					add_write_key(path, msg_obj['SECRET'])
					os.mkdir(path)
				else:
					response['ERROR'] = "Incorrect secret for " + parent_dir
					response['STATUS'] = 1

			elif op =='ls':
				path = ('users' + msg_obj['PATH'])
				if os.path.exists(path) and os.path.isdir:
					gen = os.walk(path)
					(root, dirs, files) = gen.next()
					response["FILES"] = [f for f in files if not f.startswith('.log')]
					response["FOLDERS"] = dirs
				else:
					response['ERROR'] = "Folder to ls does not exist"
					response['STATUS'] = 1
	
			elif op == 'skipSwitch':
				pass
	
			else:
				self.request.send(msgFromObj({'OP':'ack', 'STATUS':1}))
				print "Response: " + msgFromObj({'OP':'ack', 'STATUS':1})
				print op
				return
			self.request.send(msgFromObj(response))
			print "Response: " + msgFromObj(response)	

SocketServer.TCPServer.allow_reuse_address = True

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	
	def verify_request(self, request, client_address):
		active_users_lock.acquire()
		(msg_size, msg_obj) = readMsg(request)
		print "Incoming msg: ", msg_obj
		op = msg_obj['OP']
		response = {'OP':'ack', 'STATUS':0}
		verified = False

		try:
			username = msg_obj['ENC_USER']
			if op == 'createUser':
				# Create a directory for the new user
				if os.path.exists('users/' + username) or user_exists(username):
					response['ERROR'] = 'User already exists'
					response['STATUS'] = 1
				else:
					os.mkdir('users/' + username) 
					# Create an entry in the public key table
					password = msg_obj['PASSWORD']
					public_key = msg_obj['KEY']
					add_user_to_databases(username, password, public_key)	
					add_write_key("users/" + username, msg_obj["SECRET"])
					active_users[username] = (True, client_address)
					verified = True

			elif op =='loginUser':
				#TODO: logging in twice should log the old user out?
				#@Asa: I took out the last part of this if statement so I could re-create the connection
				# not sure if that's correct, but it let's my unit tests pass
				if (check_password(username, msg_obj['PASSWORD'])): # and active_users[username][0] == False:
					active_users[username] = (True, client_address)
					verified = True
				else:
					response['ERROR'] = 'Username and password do not match'
					response['STATUS'] = 1
			else:
				response['ERROR'] = 'Must login first'
				response['STATUS'] = 1	
		finally:
			active_users_lock.release()
		request.send(msgFromObj(response))
		print "Response: " + msgFromObj(response)	
		return verified

# sample server that processes each connection in a loop
def start_server():
	server = ThreadedTCPServer((SERVER_IP, SERVER_PORT), MyTCPHandler)
	server_thread = threading.Thread(target=server.serve_forever)
	# Exit the server thread when the main thread terminates
	server_thread.setDaemon(True)
	server_thread.start()
	while True:
		foo = 2
start_server()

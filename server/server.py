import SocketServer
import socket
import json
import sys
import thread
import os
import threading

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir) 
from msg import *
from db import *


SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007
PADDED_HEX_STR_SIZE = 20
MAX_ACTIVE_USERS = 255

active_users = {}
active_users_lock = threading.Lock()

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
				if not active_users[username][1] == self.client_address:
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
					response['ERROR'] = "User does not exist"
					response['STATUS'] = 1
	
			elif op == 'addPermission':
				if user_exists(msg_obj['TARGET']):
					add_permission(username, msg_obj['TARGET'], msg_obj['PERMISSION'])
				else:
					response['ERROR'] = "User does not exist"
					response['STATUS'] = 1
	
			elif op == 'getPublicKey':
				response['TARGET'] = msg_obj['TARGET']
				if user_exists(msg_obj['TARGET']):
					response['KEY'] = get_public_key(msg_obj['TARGET'])
				else:
					response['ERROR'] = "User does not exist"
					response['STATUS'] = 1
	
			elif op == 'setPublicKey':
				set_public_key(username, msg_obj['KEY'])
	
			elif op =='downloadFile':
				#TODO
				pass
	
			elif op =='downloadDir':
				#TODO
				pass
	
			elif op =='createFile':
				#TODO
				path = ('users/' + username + '/' + msg_obj['PATH'])
				if os.path.exists(path):
					response['ERROR'] = "File to delete does not exist"
					response['STATUS'] = 1
				else:
					open(path, 'a').close()
					os.utime(path, None)
					#TODO Write folder difflog	
			elif op =='writeFile':
				#TODO
				pass
	
			elif op =='deleteFile':
				path = ('users/' + username + '/' + msg_obj['PATH'])
				if os.path.exists(path) and os.path.isfile:
					os.remove(path)
					#TODO Write folder difflog
				else:
					response['ERROR'] = "File to delete does not exist"
					response['STATUS'] = 1	

			elif op =='mkdir':
					#TODO Write folder difflog
				path = ('users/' + username + '/' + msg_obj['PATH'])
				sub_path = path.split('/')
				sub_path = sub_path[0:len(sub_path) - 1]
				sub_path = "/".join(sub_path)
				if os.path.exists(path):
					response['ERROR'] = "Folder " + path + " already exists"
					response['STATUS'] = 1
				elif not os.path.exists(sub_path):
					response['ERROR'] = "Sub path " + sub_path + " does not exist"
					response['STATUS'] = 1
				else:	
					os.mkdir(path)
	
			elif op =='rmdir':
				path = ('users/' + username + '/' + msg_obj['PATH'])
				if os.path.exists(path) and os.path.isdir:
					if len(os.listdir(path)) == 0:
						os.rmdir(path)
					#TODO Write folder difflog
					else:
						response['ERROR'] = "Folder to delete not empty"
						response['STATUS'] = 1
				else:
					response['ERROR'] = "Folder to delete does not exist"
					response['STATUS'] = 1
	
			elif op =='ls':
				path = ('users/' + username + '/' + msg_obj['PATH'])
				if os.path.exists(path) and os.path.isdir:
					gen = os.walk(path)
					(root, dirs, files) = gen.next()
					response["FILES"] = files
					response["FOLDERS"] = dirs
				else:
					response['ERROR'] = "Folder to ls does not exist"
					response['STATUS'] = 1
	
			elif op == 'skipSwitch':
				pass
	
			else:
				self.request.send(msgFromObj({'OP':'ack', 'STATUS':1}))
			self.request.send(msgFromObj(response))
			print "Response: " + msgFromObj(response)	
	
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
					active_users[username] = (True, client_address)
					verified = True

			elif op =='loginUser':
				if (check_password(username, msg_obj['PASSWORD'])) and active_users[username][0] == False:
					active_users[username] = (True, client_address)
					verified = True
				else:
					response['ERROR'] = 'Username and password do not match'
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

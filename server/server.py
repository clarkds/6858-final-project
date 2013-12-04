import socket
import json
import sys
import thread
import os

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir) 
from msg import *
from serverdb import *


SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007
PADDED_HEX_STR_SIZE = 20
MAX_ACTIVE_USERS = 255

active_users = {}

def server_send_by_un(username, msgObj):
	active_users[username][0].send(msgFromObj(msgObj))

def server_send(conn, msgObj):
	conn.send(msgFromObj(msgObj))

def clientthread(conn):
	while True:
		(msg_size, msg_obj) = readMsg(conn)
		op = msg_obj['OP']
		username = msg_obj['ENC_USER']
		response = {'OP':'ack', 'STATUS':0}
		if op == 'getPermissions':
			db = permissions_setup()
			permissions = db.query(Permissions).get(username)
			response['permissions'] = permissions.permissions

		elif op =='download':
			#TODO
			response['filedata'] = 'TODO'
		elif op =='createUser':
		  # TODO 
			response['STATUS'] = 0
		else:
			server_send(conn, {'OP':'ack', 'STATUS':1}) 
		server_send(conn, response)	

def login_user(username, conn, addr):
	active_users[username] = (conn, addr)
	print 'Logged in user ' + username
	server_send_by_un(username, {'OP':'ack', 'STATUS':0})
# Send a bunch of stuff to client
# Fork process to listen in on connection 
	thread.start_new_thread(clientthread,(conn,))

# sample server that processes each connection in a loop
def start_server():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((SERVER_IP, SERVER_PORT))
	s.listen(MAX_ACTIVE_USERS)

	while True:
		conn, addr = s.accept()
		print 'Connected to address:', addr
		(msg_size, msg_obj) = readMsg(conn)
		print "Incoming msg: ", msg_obj
		op = msg_obj['OP']
		username = msg_obj['ENC_USER']
		if op == 'login':
			login_user(username, conn, addr)
start_server()	

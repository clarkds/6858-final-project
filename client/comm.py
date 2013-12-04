import socket
import json
import sys
import os

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir) 
import msg

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007
PADDED_HEX_STR_SIZE = 20


# sends a msg_obj to the server and reads a msg_obj in reply
# returns NONE on failure
def client_send(msg_obj):
	# TODO: socket should come from a pool of sockets
	# TODO: add a timeout, try/catch
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((SERVER_IP, SERVER_PORT))
	s.send(msg.msgFromObj(msg_obj))
	(msg_size, msg_obj) = msg.readMsg(s)
	s.close()
	return msg_obj

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "usage: comm.py <server|client>"
		sys.exit(1)
	username = sys.argv[1]
	print client_send({'OP': "login", 'ENC_USER': username})

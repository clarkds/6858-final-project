import socket
import json
import sys
import os

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir) 
from msg import *

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007
PADDED_HEX_STR_SIZE = 20

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# sends a msg_obj to the server and reads a msg_obj in reply
def client_send(msg_obj):
	# TODO: socket should come from a pool of sockets
	# TODO: add a timeout, try/catch
	s.send(msgFromObj(msg_obj))
	(msg_size, msg_obj) = readMsg(s)
	return msg_obj

def client_setup():
	s.connect((SERVER_IP, SERVER_PORT))
	while True:
		msg = raw_input()
		msg = json.loads(msg)
		print client_send(msg)
client_setup()

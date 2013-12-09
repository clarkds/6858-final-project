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

s0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# sends a msg_obj to the server and reads a msg_obj in reply
def client_send(s, msg_obj):
	# TODO: socket should come from a pool of sockets
	# TODO: add a timeout, try/catch
	print "Sent: " + str(msg_obj)
	s.send(msgFromObj(msg_obj))
	(msg_size, msg_obj) = readMsg(s)
	print "Received: " + str(msg_obj)
	return msg_obj

def create_user_test():
	s0.connect((SERVER_IP, SERVER_PORT))
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"createUser", "PASSWORD":"penis", "KEY":"55555"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"addPermission", "TARGET":"asaj", "PERMISSION":"22222"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"addPermission", "TARGET":"asaj", "PERMISSION":"11111"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][0][2] == "22222"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][1][2] == "11111"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPublicKey", "TARGET":"asaj"})["KEY"] == "55555"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"mkdir", "PATH":"test"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"createFile", "PATH":"test/test.txt"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"mkdir", "PATH":"test/secondtest"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"mkdir", "PATH":"noexist/secondtest"})["STATUS"] == 1
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"ls", "PATH":"test"})["FILES"] == ["test.txt"]
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"ls", "PATH":"test"})["FOLDERS"] == ["secondtest"]
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"deleteFile", "PATH":"test/test.txt"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"rmdir", "PATH":"test/secondtest"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"rmdir", "PATH":"test"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"logoutUser"})["STATUS"] == 0
	s0.close()
	s1.connect((SERVER_IP, SERVER_PORT))
	s2.connect((SERVER_IP, SERVER_PORT))
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"loginUser", "PASSWORD":"penis"})["STATUS"] == 0
	assert client_send(s2, {"ENC_USER":"jasa", "OP":"createUser", "PASSWORD":"penis", "KEY":"88888"})["STATUS"] == 0
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][0][2] == "22222"
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][1][2] == "11111"
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"getPublicKey", "TARGET":"asaj"})["KEY"] == "55555"
	assert client_send(s1, {"ENC_USER":"jasa", "OP":"logoutUser"})["STATUS"] == 1
	assert client_send(s2, {"ENC_USER":"asaj", "OP":"logoutUser"})["STATUS"] == 1
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"logoutUser"})["STATUS"] == 0
	assert client_send(s2, {"ENC_USER":"jasa", "OP":"logoutUser"})["STATUS"] == 0
	s1.close()
	
create_user_test()

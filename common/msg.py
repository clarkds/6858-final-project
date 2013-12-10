import socket
import json
import sys

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007
PADDED_HEX_STR_SIZE = 20

# read exactly nbytes from socket s, return as string
def blockRead(s, nbytes):
	buf = bytearray(nbytes)
	view = memoryview(buf)
	while nbytes > 0:
		count = s.recv_into(view, nbytes)
		view = view[nbytes:] # slicing views is cheap
		nbytes -= count
	return buf.decode("utf-8")

# construct message from object
# message format:
# 	[length of json-encoded msg_obj in hex left padded with zeros][space][json-encoded msg_obj] 
def msgFromObj(msg_obj):
	msg = json.dumps(msg_obj, separators=(',',':'))
	msg = hex(len(msg)).zfill(PADDED_HEX_STR_SIZE) + " " + msg
	return msg

# reads a message from socket and returns (msg_size, msg_obj)
def readMsg(s):
	msg_size_str = blockRead(s, PADDED_HEX_STR_SIZE)
	msg_size_str = msg_size_str[msg_size_str.find('0x'):]
	msg_size = int(msg_size_str, 16)
	blockRead(s, 1)		# read the space
	msg_obj = json.loads(blockRead(s, msg_size))
	return (msg_size, msg_obj)

# sends a msg_obj to the server and reads a msg_obj in reply
def client_send(s, msg_obj):
	# TODO: socket should come from a pool of sockets
	# TODO: add a timeout, try/catch
	print "Sent: " + str(msg_obj)
	s.send(msgFromObj(msg_obj))
	(msg_size, msg_obj) = readMsg(s)
	print "Received: " + str(msg_obj)
	return msg_obj
	
def create_client_socket(server_ip, server_port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server_ip, server_port))
	return s
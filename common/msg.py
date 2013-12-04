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


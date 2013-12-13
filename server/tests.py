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

def create_user_test():
	s0.connect((SERVER_IP, SERVER_PORT))
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"createUser", "PASSWORD":"test", "KEY":"55555", "SECRET":"00000", "LOG_DATA":"Added asaj folder", "META_DATA":"Added asaj folder"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPublicKey", "TARGET":"asaj"})["KEY"] == "55555"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/.meta_asaj"})["DATA"] == "Added asaj folder"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/.log_asaj"})["DATA"] == "Added asaj folder"

	# Update meta for /asaj in preperation for making /asaj/test
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"writeFile", "PATH":"/.meta_asaj", "SECRET":"00000", "FILE_DATA":"Adding test folder", "LOG_DATA":"Added test dir"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/.log_.meta_asaj"})["DATA"] == "Added test dir"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/.meta_asaj"})["DATA"] == "Adding test folder"

	# Make /asaj/test
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"mkdir", "PATH":"/asaj/test", "PARENT_SECRET":"00000", "SECRET":"54321", "LOG_DATA":"Created", "META_DATA":"Created test dir"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/.log_test"})["DATA"] == "Created"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/.meta_test"})["DATA"] == "Created test dir"

  # Update meta for /asaj/test in preperation for making /asaj/test/test.txt
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"writeFile", "PATH":"/asaj/.meta_test", "SECRET":"54321", "FILE_DATA":"added test.txt", "LOG_DATA":"Added test.txt"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/.meta_test"})["DATA"] == "added test.txt"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/.log_.meta_test"})["DATA"] == "Added test.txt"

	# Make /asaj/test/test.txt and write to it
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"createFile", "PATH":"/asaj/test/test.txt", "PARENT_SECRET":"54321", "SECRET":"12345", "LOG_DATA":"Created", "FILE_DATA":"Checksum"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"writeFile", "PATH":"/asaj/test/test.txt", "SECRET":"12345", "FILE_DATA":"This is a test", "LOG_DATA":"Added this is a test"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/test/test.txt"})["DATA"] == "This is a test"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/test/.log_test.txt"})["DATA"] == "Added this is a test"

	# Give myself permissions for /asaj/test/test.txt and remove one of them
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"addPermissions", "PATH":"/asaj/test/test.txt", "SECRET":"12345", "LOG_DATA":"Shared with asaj", "USERS_AND_PERMS":[("asaj", "11111"), ("asaj", "22222")]})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/test/.log_test.txt"})["DATA"] == "Shared with asaj"
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][0] == ["asaj", "asaj", "11111"]
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][1] == ["asaj", "asaj", "22222"]
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"deletePermissions", "PATH":"/asaj/test/test.txt", "SECRET":"12345", "LOG_DATA":"Unshared with asaj", "USERS_AND_PERMS":[("asaj", "11111")]})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][0] == ["asaj", "asaj", "22222"]
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/test/.log_test.txt"})["DATA"] == "Unshared with asaj"

	
	# Try to do some stuff with nonexistant paths
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"mkdir", "PATH":"/asaj/noexist/secondtest"})["STATUS"] == 1
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"createFile", "PATH":"/asaj/noexist/secondtest.txt"})["STATUS"] == 1

	# Make sure ls doesn't give us meta or log files
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"ls", "PATH":"/asaj/test"})["FILES"] == ["test.txt"]
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"ls", "PATH":"/asaj/test"})["FOLDERS"] == []
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"ls", "PATH":"/asaj"})["FILES"] == []
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"ls", "PATH":"/asaj"})["FOLDERS"] == ["test"]

	# Update meta for /asaj/test in preperation for deleting /asaj/test/test.txt
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"writeFile", "PATH":"/asaj/.meta_test", "SECRET":"54321", "FILE_DATA":"", "LOG_DATA":"deleted test.txt"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/.meta_test"})["DATA"] == ""
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/asaj/.log_.meta_test"})["DATA"] == "deleted test.txt"

	# Change the secret for /asaj/test
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"changeFileSecret", "PATH":"/asaj/test", "SECRET":"54321", "NEW_SECRET":"88888"})["STATUS"] == 0

	# Delete /asaj/test/test.txt
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"delete", "PATH":"/asaj/test/test.txt", "PARENT_SECRET":"88888"})["STATUS"] == 0

	# Update meta for /asaj in preperation for deleting /asaj/test
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"writeFile", "PATH":"/.meta_asaj", "SECRET":"00000", "FILE_DATA":"", "LOG_DATA":"deleted test"})["STATUS"] == 0
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/.meta_asaj"})["DATA"] == ""
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"downloadFile", "PATH":"/.log_.meta_asaj"})["DATA"] == "deleted test"

	# Delete /asaj/test/test.txt
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"delete", "PATH":"/asaj/test", "PARENT_SECRET":"00000"})["STATUS"] == 0

	# Logout
	assert client_send(s0, {"ENC_USER":"asaj", "OP":"logoutUser"})["STATUS"] == 0
	s0.close()
	"""
	s1.connect((SERVER_IP, SERVER_PORT))
	s2.connect((SERVER_IP, SERVER_PORT))
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"loginUser", "PASSWORD":"test"})["STATUS"] == 0
	assert client_send(s2, {"ENC_USER":"jasa", "OP":"createUser", "PASSWORD":"test", "KEY":"88888"})["STATUS"] == 0
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][0][2] == "22222"
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"getPermissions", "TARGET":"asaj"})["PERMISSIONS"][1][2] == "11111"
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"getAllPublicKeyS", "TARGET":"asaj"})["KEY"] == "55555"
	assert client_send(s1, {"ENC_USER":"jasa", "OP":"logoutUser"})["STATUS"] == 1
	assert client_send(s2, {"ENC_USER":"asaj", "OP":"logoutUser"})["STATUS"] == 1
	assert client_send(s1, {"ENC_USER":"asaj", "OP":"logoutUser"})["STATUS"] == 0
	assert client_send(s2, {"ENC_USER":"jasa", "OP":"logoutUser"})["STATUS"] == 0
	s1.close()
	"""
create_user_test()

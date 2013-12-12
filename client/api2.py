import os

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir)

import socket
import json
import sys
import msg
import traceback
import crypt
import binascii
import string
import time
import re
import difflog
import pickle
import random
import shutil

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5007

"""
single dataDir for all users
dataDir
	/user0
		/secrets
		/data
			/user0
			/user1
"""

#~~~~~~~~~~~~~~~~~~~~~~file formats~~~~~~~~~~~~~~~~~~~~~~~~~
"""
file on server:
watermark
4-byte len, checksum
4-byte len, CPK
4-byte len, edit_number
4-byte len, contents

log for file on server:
watermark
4-byte len, secret_number
4-byte len, CSK
4-byte len, edit_list

metadata file for directory:
watermark
4-byte len, checksum
4-byte len, CPK
4-byte len, edit_number
contents -> rm filename or add filename

log for directory on server:
watermark
4-byte len, secret_number
4-byte len, CSK
4-byte len, edit_list
"""
#~~~~~~~~~~~~~~~~~~~~~~Global variables ~~~~~~~~~~~~~~~~~~~~~~~~~

client_err_msgs = ""

TESTING_ON = True
TESTING_ALLOW_RECREATE_USER = True
WATERMARK = crypt.watermark()
SOCKET_TIMEOUT = 5
SECRET_LEN = 24

client_open_export_files={}
client_all_public_keys={} 	#key=det(user), val = public key of users
client_user = None #the user who is logged in 
client_encUser = None
client_passw = None
client_working_dir = None
client_secrets = {}
#TODO: change loggedIn to false
client_loggedIn = True		#True or False. all functions throw an exception if not client_loggedIn
client_keys = {}			#key = enc_path, val = (file_RK, file_WK)
client_path_key = {}
client_enc_path_key = {}
client_socket = None
client_open_files = {}		#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata

# tuple-indices for values in client_open_files
PATH = 0
ENC_PATH = 1
METADATA = 2
CONTENTS_PATH_ON_DISK = 3
LOG_PATH_ON_DISK = 4
PATH_TO_OLD_FILE=5
MODE = 6

def reset_client_vars():
	global client_all_public_keys
	global client_user
	global client_encUser
	global client_passw
	global client_working_dir
	global client_secrets
	global client_loggedIn
	global client_keys
	global client_path_key
	global client_enc_path_key
	global client_socket
	global client_open_files
	
	client_all_public_keys={}
	client_user = None
	client_encUser = None
	client_passw = None
	client_working_dir = None
	client_secrets = {}
	client_loggedIn = True	#TODO: change loggedin to false
	client_keys = {}
	client_path_key = {}
	client_enc_path_key = {}
		
	if client_socket is not None:
		try:
			client_socket.close()
		except:
			pass
	client_socket = None
		
	client_open_files = {}
	return

reset_client_vars()

#~~~~~~~~~~~~~~~~~~~~~~~ helper functions ~~~~~~~~~~~~~~~~~~~~~~~

def bytesToStr(data):
	return binascii.hexlify(data)
	
def strToBytes(string):
	return binascii.unhexlify(string)

def randomword(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))

# returns a msg obj on success, None on error
def send_to_server(msg_obj):
	global client_socket, client_err_msgs
	global TESTING_ON, TESTING_ALLOW_RECREATE_USER
	
	try:
		resp = msg.client_send(client_socket, msg_obj)
	except Exception as e:
		print "-------------------"
		traceback.print_exc()
		print "--------------------"
		client_err_msgs += "exception when sending " + json.dumps(msg_obj) + "\n"
		client_err_msgs += str(e)
		api_logout()
		return None
		
	if resp["STATUS"] != 0:
		if "ERROR" in resp.keys():
			if TESTING_ON:
				# for unit tests, since they re-create same user
				if TESTING_ALLOW_RECREATE_USER and resp["ERROR"] == 'User already exists':
					resp["STATUS"] = 0
					setup_socket()
					assert msg.client_send(client_socket, {"ENC_USER":"asaj", "OP":"loginUser", "PASSWORD":"test"})["STATUS"] == 0
					return resp

			client_err_msgs += resp["ERROR"] + "\n"
		return None
		
	return resp

def setup_socket():
	global client_socket
	if client_socket is not None:
		try:
			client_socket.close()
		except:
			pass
	client_socket = msg.create_client_socket(SERVER_IP, SERVER_PORT, SOCKET_TIMEOUT)
	return (client_socket is not None)

def test_send_to_server():
	setup_socket()
	assert send_to_server({"ENC_USER":"asaj", "OP":"mkdir", "PATH":"xxxxxnoexist/secondtest"}) is None
	setup_socket()
	assert send_to_server({"ENC_USER":"asaj", "OP":"createUser", "PASSWORD":"penis", "KEY":"55555", "PARENT_SECRET":"00000"})["STATUS"] == 0

	print "YAYY"
	client_socket.close()

def sanitize_path(path):
# returns clean string of path. If path doesn't start with a /, prefixes global path to beginning of string or eror
	print path, "*****"
	global client_working_dir
	if path[0]!='/' and client_working_dir!=None:
		path=client_working_dir+'/'+path
	elif path[0]!='/' and client_working_dir==None:
		path='ERROR - NO CLIENT WORKING DIRECTORY'
	path_parts = path.split('/')
	path_parts = [path_parts[0]] + filter(None, path_parts[1:])	# remove empty strings from list
	new_path_parts=[]
	for a in path_parts:
		if a!='..':
			new_path_parts.append(a)
	clean_path = string.join(new_path_parts,'/')
	return clean_path

def test_sanitize_path():
	global client_working_dir
	client_working_dir='bobby/w'
	if sanitize_path('a/b/c')!='bobby/w/a/b/c':
		return False
	if sanitize_path('/a/b/..//c')!='/a/b/c':
		return False
	return True

def encrypt_path(path):
	global client_path_key
	
	assert(path.startswith('/'))
	try:
		enc_path = client_path_key[path]
		return enc_path
	except:
		return None
		
	"""
	# THIS IS BE WRONG
	assert(path.startswith('/'))
	try:
		oldpath = path.split('/')
		newpath = oldpath[:]
		newpath[1]=crypt.det(newpath[1])
		for part in range(2,len(newpath)):
			previousPath=string.join(oldpath[0:part+1],'/')
			(cipher_len, ciphertext) = crypt.sym_enc(client_keys[previousPath][0], newpath[part])
			newpath[part] = ciphertext
		return string.join(newpath,'/')
	except:
		return None
	"""
	return path

def test_encrypt_path():
	global client_keys
	
	user = "leo"
	home_dir = "/" + user
	(key_len, home_dir_key) = crypt.create_sym_key(crypt.hash(user), home_dir, user)
	enc_user = crypt.sym_enc(home_dir_key, user)
	# TODO...

# any_path can be non-encrypted or encrypted
def log_path(path):
	# appens .log_ to begining of last part of the path
	newpath=sanitize_path(path).split('/')
	newpath[-1]='.log_'+newpath[-1]
	return string.join(newpath,'/')

def test_log_path():
	if log_path('/a/b/c')=='/a/b/.log_c':
		return True
	else:
		return False
		
def dir_path(path):
	newpath=newpath=sanitize_path(path).split('/')
	newpath.pop(-1)
	return string.join(newpath,'/')

def meta_path(path):
	# appens .log_ to begining of last part of the path
	newpath=sanitize_path(path).split('/')
	newpath[-1]='.meta_'+newpath[-1]
	return string.join(newpath,'/')

def test_meta_path():
	if log_path('/a/b/c')=='/a/b/.meta_c':
		return True
	else:
		return False

def write_secrets():
	global client_user
	global client_secrets
	global client_passw
	if client_passw==None:
		return False
	#creates paths for separate users, returns True or False
	try:
		if os.path.exists('data')==False:
			os.mkdir('data')
		pickled=pickle.dumps(client_secrets)
		enc_pickle=crypt.sym_enc(client_passw, pickled)[1]
		if os.path.exists('data/'+client_user)==False:
			os.mkdir('data/'+client_user)
		if os.path.exists('data/'+client_user+'/data'):
			os.mkdir('data/'+client_user+'/data')
		
		secret_file=open('data/'+client_user+'/secrets','w')
		secret_file.write(enc_pickle)
		secret_file.close()
		ans=True
	except:
		ans=False
	return ans
	


	
def load_secrets():
	try:
		global client_user
		global client_secrets
		global client_passw
		secret_file=open('data/'+client_user+'/secrets','r')
		decrypted_pickle=crypt.sym_dec(client_passw, secre_file.read())
		client_secrets=pickle.loads(decrypted_pickle)
		secret_file.close()
		return True
	except:
		return False



def test_write_secrets():
	global client_working_dir
	client_working_dir='bobby/w'
	global client_secrets
	client_secrest={'time':'boby'}
	test={'time':'boby'}
	global client_user
	client_user='bbbb'
	global client_passw
	client_passw=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	m=write_secrets()
	w=load_secrets()
	if test==client_secrets:
		return True
	else:
		return False

def update_keys():
	global client_keys
	global client_encUser
	global client_secrets
	global client_path_key
	global client_enc_path_key
	
	client_keys = {}
	client_path_key = {}
	client_enc_path_key = {}
	resp = send_to_server({"OP": "getPermissions", "ENC_USER": client_encUser, "TARGET": client_encUser})
	if resp is None:
		return False
	print "******* decrypting perm with user sk *********************"
	for perm_tuple in resp["PERMISSIONS"]:
		#print perm_tuple[2]
		(enc_pathname, read_key, write_key) = json.loads(crypt.asym_dec(client_secrets["user_sk"], perm_tuple[2]))
		#print enc_pathname,read_key,write_key
		client_keys[enc_pathname] = (read_key, write_key)
	print "KOBE BRYANTTTTTT"
	enc_path_list = client_keys.keys()
	
	enc_path_list = [i.split('/')[1:] for i in enc_path_list]
	enc_path_list = sorted(enc_path_list, key = lambda x: len(x))
	
	for enc_path in enc_path_list:
		path = []
		full_enc_path = '/' + string.join(enc_path, '/')
		if len(enc_path) == 2:
			path.append(enc_path[0])
			name = crypt.sym_dec(client_keys[full_enc_path][0],enc_path[1])
			path.append(name)
		else:
			path.append(client_path_key[string.join(enc_path[:-1],'/')])
			name = crypt.sym_Dec(client_keys[full_enc_path][0], enc_path[-1])
			path.append(name)
		full_path = '/' + string.join(path, '/')
		
		client_path_key[full_path] = full_enc_path
		client_enc_path_key[full_enc_path] = full_path
		
	return True

def test_update_keys():
	setup_socket()
	global client_keys
	global client_user
	global client_encUser
	global client_secrets
	
	client_user = "asaj"
	client_encUser = 'asaj'
	
	(len_key, key) = crypt.create_sym_key("test","test.txt","asaj")
	(len_pub,pub,len_priv, priv) = crypt.create_asym_key_pair()
	enc_file = crypt.sym_enc(key, "test.txt")[1]
	client_keys[enc_file] = (key,key)
	client_secrets["user_sk"] = priv
	
	file_path = "/asaj/" + enc_file
	perm = crypt.asym_enc(pub, (json.dumps((file_path,key,key))))[1]
	print "1"
	
	
	assert send_to_server({"ENC_USER":"asaj", "OP":"createUser", "PASSWORD":"test", "KEY":pub, "SECRET":"00000"})["STATUS"] == 0
	
	assert send_to_server({"ENC_USER":"asaj", "OP":"createFile", "PATH":file_path, "PARENT_SECRET":"00000", "SECRET":"12345", "DATA":"Added test.txt", "LOG_DATA":"Created"})["STATUS"] == 0

	assert send_to_server({"ENC_USER":"asaj", "OP":"addPermissions", "TARGET":"asaj", "USERS_AND_PERMS": [("asaj",perm)], "PATH":file_path, "SECRET":"12345", "LOG_DATA":"random_string"})["STATUS"] == 0
	
	print "everything sent to server"
	print "calling update_keys()"
	assert update_keys()
	print "checking client keys"
	assert client_keys[file_path] == (key,key)
	print "checking path mapping"
	for key,value in client_path_key.iteritems():
		print key,value
	for key,value in client_enc_path_key.iteritems():
		print key,value

def get_metadata(handle):
	return client_open_files[handle][METADATA]

def get_log_path_on_disk(handle):
	return client_open_files[handle][LOG_PATH_ON_DISK]

# data is decrypted
def parse_metadata_and_contents_for_file(data):
	#returns tuple of (metadata_map,contents) or None
	try:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
		if watermark!=WATERMARK:
			return None
		bp+=len(watermark)
		checkSum_Hex=data[bp:bp+10]
		checkSum_len=int(checkSum_Hex,16)
		bp+=10
		checkSum=data[bp:bp+checkSum_len]
		bp+=checkSum_len
		CPK_Hex=data[bp:bp+10]
		CPK_len=int(CPK_Hex,16)
		bp+=10
		CPK=data[bp:bp+CPK_len]
		bp+=CPK_len
		edit_number_Hex=data[bp:bp+10]
		edit_number_len=int(edit_number_Hex,16)
		bp+=10
		edit_number=data[bp:bp+edit_number_len]
		bp+=edit_number_len
		contents_Hex=data[bp:bp+10]
		contents_len=int(contents_Hex,16)
		bp+=10
		contents=data[bp:bp+contents_len]
		metadata={'checksum':checkSum,'cpk':CPK,'edit_number':edit_number}
		return (metadata,contents)
	except:
		return None
		
def test_parse_metadata_and_contents_for_file():
	global WATERMARK
	WATERMARK='HI there'
	data='HI there0x00000002210x0000000120x0000000130x000000014'
	if parse_metadata_and_contents_for_file(data)==({'checksum': '21', 'cpk': '2', 'edit_number': '3'}, '4'):
		return True
	else:
		return False

def hex_string(data):
	#takes as input a string and returns the length in a hex of 4 bytes
	data_len= sys.getsizeof(data)
	m=str(hex(data_len))
	if len(m)<10:
		newm=m.split('x')
		newm[0]='0x'
		while len(newm[1])<8:
			newm[1]='0'+newm[1]
	return string.join(newm,'')
	
def test_hex_string():
	w='what in the world is going on?'
	if hex_string(w)!='0x00000043':
		return False
	return True
#print test_hex_string()

def parse_log(data):
	#returns datalog object
	if True:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
		if watermark!=WATERMARK:
			print 'theres not watermark!@!!'
			return False
		bp+=len(watermark)
		contents_Hex=data[bp:bp+10]
		contents_len=int(contents_Hex,16)
		bp+=10

		contents=data[bp:bp+contents_len]
		diffObj=pickle.loads(contents)
		###need to figure out how this works
		return diffObj
	else:
		return False

	
def test_parse_log():
	datapickle=pickle.dumps({'hi':'by'})
	size=hex_string(datapickle)
	data='HI there'+size+datapickle
	if parse_log(data)!={'hi':'by'}:
		return False
	else:
		return True


def parse_metadata_for_dir(data):
	#returns (metadata_map,contents) or None
	try:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
		if watermark!=WATERMARK:
			return None
		bp+=len(watermark)
		checkSum_Hex=data[bp:bp+10]
		checkSum_len=int(checkSum_Hex,16)
		bp+=10
		checkSum=data[bp:bp+checkSum_len]
		bp+=checkSum_len
		CPK_Hex=data[bp:bp+10]
		CPK_len=int(CPK_Hex,16)
		bp+=10
		CPK=data[bp:bp+CPK_len]
		bp+=CPK_len
		edit_number_Hex=data[bp:bp+10]
		edit_number_len=int(edit_number_Hex,16)
		bp+=10
		edit_number=data[bp:bp+edit_number_len]
		bp+=edit_number_len
		contents_Hex=data[bp:bp+10]
		contents_len=int(contents_Hex,16)
		bp+=10
		contents=data[bp:bp+contents_len]
		metadata={'checksum':checkSum,'cpk':CPK,'edit_number':edit_number}
		return (metadata,contents)
	except:
		return None
	
def test_parse_metadata_for_dir():
	WATERMARK='HI there'
	data='HI there0x00000002210x0000000120x0000000130x000000014'
	if parse_metadata_for_dir(data)==({'checksum': '21', 'cpk': '2', 'edit_number': '3'}, '4'):
		return True
	else:
		return False



def path_parent(path):
	parts = path.split("/")
	filename = parts[-1]
	#print path
	#print string.join(parts, "/"), "**********"
	if len(parts) > 1:
		parent = string.join(parts[0:-1], "/")
	else:
		parent = None
	return (parent, filename)

def save_file(data, path_on_disk):
	(parent, filename) = path_parent(path_on_disk)
	if parent is not None:
		try:
			if not os.path.exists(parent):
				os.makedirs(parent)
		except:
			pass
	try:
		f = open(path_on_disk, "w")
		f.write(data)
		f.close()
	except:
		return False
	
	return True

def test_path_parent():
	assert path_parent("a") == (None, 'a')
	assert path_parent("a/b") == ('a', 'b')
	assert path_parent("a/b/c") == ('a/b', 'c')
	assert path_parent("/a/b/c") == ('/a/b', 'c')

# contents is a string
def verify_checksum(metadata_map, contents):
	return crypt.asym_dec(metadata_map["cpk"], metadata_map["checksum"]) == crypt.hash(contents + metadata_map["cpk"] + metadata_map["edit_number"])

def create_checksum(metadata_map, contents, csk):
	hashed = crypt.hash(contents + metadata_map["cpk"] + metadata_map["edit_number"])
	return crypt.asym_enc(csk, hashed)

def test_verify_and_create_checksum():
	(len_pk, cpk, len_sk, csk) = crypt.create_asym_key_pair()
	contents = "this semester is so long"
	metadata_map = {}
	metadata_map["cpk"] = cpk
	metadata_map["edit_number"] = "123456"
	checksum = create_checksum(metadata_map, contents, csk)

def valid_user_pass(user, passw):
	# allowed: alphanumeric + underscores and dashes
	return re.match('^[\w_-]+$', user) and len(passw) >= 6

#~~~~~~~~~~~~~~~~~~~~~~~ API functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~

def api_get_err_log():
	return client_err_msgs

def api_create_user(user, passw):	# LEO
	api_logout()
	global client_user
	global client_secrets
	global client_passw
	global client_loggedIn
	
	if not valid_user_pass(user, passw):
		return False
	
	client_user = user
	client_passw = passw
	
	(len_pk, user_pk, len_sk, user_sk) = crypt.create_asym_key_pair()
	homedir_secret = randomword(SECRET_LEN)
	setup_socket()
	resp = send_to_server({
		"ENC_USER": crypt.det(user),
		"OP": "createUser",
		"PASSWORD": passw,
		"KEY": user_pk,
		"PARENT_SECRET":homedir_secret})
	if resp is None:
		return False
	client_secrets["user_pk"] = user_pk
	client_secrets["user_sk"] = user_sk
	write_secrets()
	client_loggedIn = True
	return True
	
def test_api_create_user():
	global TESTING_ALLOW_RECREATE_USER
	
	assert api_create_user("leo?", "123456") == False
	assert api_create_user("leo", "123") == False
	TESTING_ALLOW_RECREATE_USER = False
	assert api_create_user("leo", "123456")
	assert api_create_user("leo", "123456") == False
	TESTING_ALLOW_RECREATE_USER = True

def api_login(user, passw, secretsFile=None):	# LEO
	if api_login_helper(user, passw, secretsFile):
		return True
	else:
		api_logout()
		return False

def api_login_helper(user, passw, secretsFile):	# LEO
	global client_user
	global client_encUser
	global client_working_dir
	global client_passw
	global client_secrets
	global client_all_public_keys
	global client_loggedIn
	
	if not valid_user_pass(user, passw):
		return False

	client_user = user
	client_encUser = crypt.det(user)
	client_working_dir = "/" + client_user
	client_passw = passw
	
	write_secrets()	# call this to all the user directories on disk
	if secretsFile is not None:
		try:
			shutil.copy(src, "data/"+client_user+"/secrets")
		except:
			traceback.print_exc()
			return False
	success = load_secrets()
	if not success:
		return False

	success = setup_socket()
	if not success:
		return False

	resp = send_to_server({
		"ENC_USER": client_encUser,
		"OP": "loginUser",
		"PASSWORD": client_passw})
	if resp is None:
		return False

	resp = send_to_server({
		"ENC_USER": client_encUser,
		"OP": "getAllPublicKeys",
		"PASSWORD": client_passw})
	if resp is None:
		return False

	client_all_public_keys = {}
	for userAndKey in resp["USERS_AND_KEYS"]:
		client_all_public_keys[userAndKey[0]] = userAndKey[1]

	if client_secrets["user_pk"] != client_all_public_keys[client_encUser]:
		return False
	
	if not update_keys():	#TODO: re-fetch public keys during updateKey (use lines above)
		return False
	
	client_loggedIn = True

	return True
	

def test_api_login():
	assert api_login("leo", "123456")

def api_logout(keepfiles=False):	# logout
	global client_loggedIn
	global client_open_files
	global client_user
	
	for handle in client_open_files.keys():
		try:
			handle.close()
		except:
			pass
	if not keepfiles:
		try:
			shutil.rmtree("data/" + client_user + "/data")
		except:
			pass
	reset_client_vars()
	client_loggedIn = False	# TODO: take this out after fixing reset_client_vars()

def test_api_fopen():
	pass
	assert not api_fopen("/leo/leo", "r")

# mode = "r|w"
def api_fopen(path, mode):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")

	global client_encUser
	#global client_loggedIn
	global client_keys
	global client_open_files
	
	#here
	
	if mode != "r" and mode != "w":
		return False
	
	path = sanitize_path(path)
	enc_path = encrypt_path(path)	
	enc_log_path = log_path(enc_path)
	contents_path_on_disk = "data" + path	#path has a leading slash

	if enc_path not in client_keys:
		update_keys()
		if enc_path not in client_keys:
			if mode == "r":
				return False
			else:	#mode == "w"
				return api_create_file(path)	
	
	if mode == "w" and client_keys[enc_path][1] is None:
		return 0
		
	resp = send_to_server({
		"ENC_USER": client_encUser,
		"OP": "downloadFile",
		"PATH": enc_path})
	if resp is None:
		return False
		
	data = crypt.sym_dec(client_keys[enc_path][0], resp["DATA"])
	parsed = parse_metadata_and_contents_for_file(data)
	if parsed is None:
		return False
	(metadata_map, contents) = parsed
	if not verify_checksum(metadata_map, contents):
		return False
	success = save_file(contents, contents_path_on_disk)
	if not success:
		return False

	if client_keys[enc_path][1] is not None:
		resp = send_to_server({
			"ENC_USER": client_encUser,
			"OP": "downloadFile",
			"PATH": enc_log_path})
		if resp is None:
			return False
		log_path_on_disk = log_path(contents_path_on_disk)
		data = crypt.sym_dec(client_keys[enc_path][1], resp["DATA"])
		success = save_file(resp["data"], log_path_on_disk)
		if not success:
			return False
	else:
		log_path_on_disk = None

	try:
		if mode == "r":
			handle = open(contents_path_on_disk, "r")
		else: #mode == "w"
			handle = open(contents_path_on_disk, "w+")
	except:
		traceback.print_exc()
		return False

	try:
		shutil.copy(contents_path_on_disk, original_path(contents_path_on_disk))
	except:
		traceback.print_exc()
		return False

	client_open_files[handle] = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, original_path(contents_path_on_disk), mode)

	return handle

def api_fseek(handle, offset, whence=1):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	return handle.seek(offset,whence)

def api_ftell(handle):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	return handle.tell()

def api_fwrite(handle,data):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	return handle.write(data)
	
def api_fread(handle,n=None):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	if n==None:
		return handle.read()
	else:
		return handle.read(n)

def api_fflush(handle):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	handle.flush()
	return api_fflush_helper(handle,0)


def test_fseek_ftell_fwrite_fread_fflush():
	global client_open_files
	data='n'
	newfile=open('testingfile','w+')
	api_fwrite(newfile,'this is a test of the fwrite function')
	api_fflush(newfile)
	api_fseek(newfile,0,0)
	if api_fread(newfile,10)!='this is a ':
		return False
	if api_ftell(newfile)!=10:
		return False
	newfile.close()
	return True

def api_fflush_helper(handle, attempt_num):	#LEO???
	global client_keys
	global client_loggedIn
	global ENC_PATH
	global METADATA
	global LOG_PATH_ON_DISK
	global WATERMARK
	global client_keys
	global client_user
	global client_secrets
	global client_open_files
	global CONTENTS_PATH_ON_DISK
	global PATH_TO_OLD_FILE
	global client_encUser
	
	if client_loggedIn==False:
		return 0
	if attempt_num>1:
		return 0
	enc_path=client_open_files[handle][ENC_PATH]
	enc_log_path=log_path(enc_path)
	if client_keys[enc_path][1]==None:
		return 0
	success=handle.flush()
	if success==0:	
		return 0
	place_holder=api_ftell(handle)
	api_fseek(handle,0,0)
	log=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	log_data=log.read()
	diff_obj=parse_log(log_data)
	csk=diff_obj.csk
	filepassw=diff_obj.password
	contents=api_fread(handle)
	
	#creating entire file fron contents and metadata and updating editnumber
	client_open_files[handle][METADATA]['edit_number']=str(int(client_open_files[handle][METADATA]['edit_number'])+1)
	####update_checksum(handle,csk)
	checksum=client_open_files[handle][METADATA]['checksum']
	edit_number=client_open_files[handle][METADATA]['edit_number']
	cpk=client=client_open_files[handle][METADATA]['cpk']
	data=WATERMARK+hex_string(checksum)+checksum+hex_string(edit_number)+edit_number+hex_string(cpk)+cpk+hex_string(contents)+contents
	enc_data=crypt.sym_enc(client_keys[client_open_files[handle][ENC_PATH]][0],data)
	
	#creating new diff on log
	diff_obj.create_diff(client_user,client_secrets["user_sk"],client_open_files[handle][PATH_TO_OLD_FILE],client_open_files[handle][CONTENTS_PATH_ON_DISK]) #NO comments for right now
	client_secrets[client_open_files[handle][CONTENTS_PATH_ON_DISK]]=client_open_files[handle][METADATA]['edit_number'] #updates last edit_number per user
	pickled=pickle.dumps(diff_obj)
	#updating log file on local disk
	update_log_file=open(client_open_files[handle][LOG_PATH_ON_DISK],'w')
	update_log_file.write(pickled)
	update_log_file.close()
	
	newlog=WATERMARK+hex_string(pickled)+pickled
	enc_log_data=crypt.sym_enc(client_keys[client_open_files[handle][ENC_PATH]][1],newlog)
	
	
	message={'OP': "writeFile", 'ENC_USER': client_encUser,"PATH": enc_path,"SECRET": filepassw, "FILE_DATA": enc_data, "LOG_DATA": enc_log_data}
	
	
	if send_to_server(message)==None:
		api_fflush_helper(handle, attempt_num+1)
	
	#updating the oldfile
	old_file=open(client_open_files[handle][PATH_TO_OLD_FILE],'w')
	old_file.write(contents)
	old_file.close()
	api_fseek(handle,place_holder,0)
	
	return 1
	


def test_api_fflush_helper():
	global client_encUser
	global client_keys
	global client_loggedIn
	global ENC_PATH
	global METADATA
	global LOG_PATH_ON_DISK
	global WATERMARK
	global client_keys
	global client_user
	client_user='sally'
	global client_passw
	global client_loggedIn
	client_loggedIn=True
	global client_public_keys
	global client_keys
	client_keys={}
	global client_encUser
	client_encUser='sally'
	global client_open_files
	global WATERMARK
	WATERMARK='hey there!'
	disk_place='testdifflog'
	otherfile='testfile'
	m=open(otherfile,'w+')
	m.write('hey there!0x00000002210x0000000120x0000000130x000000014')
	secrets=crypt.create_asym_key_pair()
	people_secrets=crypt.create_asym_key_pair()
	client_secrets['user_sk']=people_secrets[-1]
	writesecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	readsecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	client_keys[encrypt_path(otherfile)]=[readsecret,writesecret]
	filepassw=crypt.hash('abcdefghijklmnop')
	client_open_files[m]=[otherfile,encrypt_path(otherfile),{'checksum':secrets[-1],'edit_number':'7','cpk':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1]},otherfile,disk_place,'boby','w+']
	#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata
	
	client_public_keys={'hi':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'bye':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'sally':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'tommy':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1]}
	testdif=difflog.diff_log(secrets[-1],filepassw)
	testdif.update_perm(['hi'],['bye'])
	store=pickle.dumps(testdif)
	store_len=hex_string(store)
	pickledtestdif=WATERMARK+store_len+store
	testing=open(disk_place,'w')
	testing.write(pickledtestdif)
	testing.close()
	
	print api_fflush_helper(m, 0)



def api_fclose(handle):	# fclose
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_open_files
	global MODE
	if client_loggedIn==False:
		return (0,'client not logged int')
	if client_open_files[handle][MODE]=='w+':
		if api_fflush(handle)==0:
			return (0,'couldnt flush')
	del client_open_files[handle]
	return handle.close()

def test_api_fclose():
	global client_open_files
	m=open('testing2','w+')
	client_open_files[m]=[1,2,3,4,5,6,7]
	print api_fclose(m)
	try:
		print client_open_files[m]
		return 'doesnt work!'
	except:
		return True

def api_chdir(path):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_working_dir
	
	spec_split = path.split('../')
	client_path_list = client_working_dir.split('/')
	index = len(client_path_list)-len(spec_split)+1
	client_path_list = client_path_list[:index]
	client_working_dir = string.join(client_path_list, '/')
	new_client_path = sanitize_path(spec_slit[-1])
	
	client_working_dir = new_client_path



def api_mkdir(parent, new_dir_name):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_open_files
	global LOG_PATH_ON_DISK
	global client_keys
	global client_password
	global client_user
	global client_encUser
	global WATERMARK
	if client_loggedIn==False:
		return (0,'not logged in')
	directory=dir_path(path)
	path_filename=path_name(path)
	enc_dir=encrypt_path(dir_path)
	dir_handle=api_opendir(dir_path)
	log_file=open(client_open_files[dir_handle][LOG_PATH_ON_DISK],'r')
	data=log_file.read()
	diff_obj=parse_log(data)
	parent_secret=diff_obj.password
	api_fread(dir_handle)
	api_fwrite(dir_handle,'\n add'+path_filename+'\n')
	api_fflush(dir_handle)
	
	#Create filepassw
	filepassw=randomword(40)
	#create csk and cpk
	secret=crypt.create_asym_key_pair()
	#create read and write key
	new_read_key=crypt.create_sym_key(crypt.hash(client_password), path_filename, directory)[1]
	new_write_key=crypt.create_sym_key(crypt.hash(client_password), path_filename, directory)[1]
	enc_filename=crypt.sym_enc(new_read_key, path_filename)[1]
	
	enc_path=encrypt_path(directory)+enc_filename
	client_keys[enc_path]=(new_read_key,new_write_key)
	store = pickle.dumps((enc_path, new_read_key, new_write_key))
	my_new_perm  = (client_encUser, crypt.sym_enc(client_public_keys[client_encUser],store))
	new_log=difflog.diff_log(secret[-1],filepassw)
	new_log.update_perm([],[my_new_perm])
	enc_log=crypt.sym_enc(new_write_key, WATERMARK+hex_string(pickle.dumps(new_log))+pickle.dumps(new_log))

	meta={'edit_number':'0','cpk':secret[1],'checksum':''}
	checksum=create_checkSum(meta,'',secret[-1])
	data=crypt.sym_enc(new_read_key, WATERMARK+hex_string(checksum)+checksum+hex_string(meta['cpk'])+meta['cpk']+hex_string(meta['edit_number'])+meta['edit_number']+'0x00000000')
	create_msg={"ENC_USER":client_encUser, "OP":"mkDir", "PARENT_SECRET":file_secret,"SECRET":filepassw,"LOG_DATA":enc_log,"DATA":data}
	if send_to_server(create_msg)==None:
		return (0,'could not create file')
	send_perm={}
	new_message={"ENC_USER":client_encUser, "OP":"addPermissions", "USERS_AND_PERMS":my_new_perm}
	if send_to_server(new_message)==None:
		return (0,'my new permission')	
	
	return api_fopen(path)

# can only move a single file at the time ->
def api_mv(old_path, new_path):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_open_files
	global METADATA
	global LOG_PATH_ON_DISK
	global CONTENTS_PATH_ON_DISK
	if client_loggedIn==False:
		return (0,'client not logged in')
	handle1=api_open(old_parent,'w+')
	handle2=api_open(new_path,'w+')
	contents=api_fread(handle1)
	client_open_files[handle2][METADATA]=client_open_files[handle1][METADATA]
	client_open_files[handle2][LOG_PATH_ON_DISK]=client_open_files[handle1][LOG_PATH_ON_DISK]
	client_open_files[handle2][CONTENTS_PATH_ON_DISK]=client_open_files[handle1][CONTENTS_PATH_ON_DISK]
	if api_fflush(handle2)!=1:
		return (0,'flush failed')
	if api_rm(handle1)!=1:
		return (0,'rm failed')
		
#def test_api_mv():
	##cant test yet
	pass

def api_opendir(path):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	meta=meta_path(path)
	return api_fopen(meta, 'w+')


def api_rm(filename,parent_path=client_working_dir):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_working_dir
	global client_open_files
	global LOG_PATH_ON_DISK
	global CONTENTS_PATH_ON_DISK
	if client_loggedIn==False:
		return (0,'client not logged int')
	parent_path=sanitize_path(parent_path)
	meta=api_opendir(parent_path)
	totalpath=parent_path+filename
	check=False
	for m in client_open_files:
		if m[CONTENTS_PATH_ON_DISK]==totalpath:
			check=True
	if check==True:
		return (0,'file cannot be removed because it is open')
	api_fread(meta)
	api_fwrite(meta,'\nrm filename\n')
	api_fflush(meta)
	log_file=open(client_open_files[meta][LOG_PATH_ON_DISK],'r')
	log_data=log_file.read()
	diff_obj=parse_log(log_data)
	filepassw=diff_obj.password
	if api_set_permissions(sanitize_path(meta_path(path)), meta, [], [],True)==False:
		return (0,'could not set permissions')
	message={"ENC_USER":client_encUser, "OP":"Delete", "PARENT_SECRET":old_filepassw,"PARENT_LOG_DATA":new_filepassw}
	if send_to_server(message)==None:
		return False
	return True
	
	
def test_api_rm():
	###Can't be tested untill fopen is created
	print api_rm('boby','a/b/c')	
	

def api_list_dir(path):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	enc_path = encrypted_path(path)
	list_directory = {"ENC_USER":client_encUser, "OP":"ls", "PATH":enc_path}
	response = send_to_server(list_directory)
	if response==None:
		return (0,'listing directory')
		
	directory_contents = []
	for object in directory_contents["FILES"]:
		obj_enc_path = enc_path + object
		if obj_enc_path in client_keys:
			file_key = client_keys[obj_enc_path][0]
			file_name = crypt.sym_dec(file_key, object)
			directory_contents.append((file_name, "FILE"))
			
	for object in directory_contents["FOLDERS"]:
		obj_enc_path = enc_path + object
		if obj_enc_path in client_keys:
			dir_key = client_keys[obj_enc_path][0]
			dir_name = crypt.sym_dec(dir_key, object)
			directory_contents.append((dir_name, "FOLDER"))
			
	return directory_contents

def api_closedir(handle):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	#api_fclose(handle)
	pass



def read_permissions_list(handle): ### returns permissons of a file by reading the log of the file
	LOG_PATH_ON_DISK=4
	ENC_PATH=1
	global client_open_files
	global client_keys
	diff=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=diff.read()#crypt.sym_dec(client_keys[client_open_files[handle][ENC_PATH]][1],diff.read())
	diff.close()
	diff_obj=parse_log(dec_diff)
	if diff_obj==False:
		return False
	return diff_obj.perm
	
	
def write_permissions_and_secrets(handle,new_permissions,new_filepassw,new_csk,old_write_key):
	#takes handle of file, as well as new permissions, new filepassw, and new csk and overwrites log file with new things
	LOG_PATH_ON_DISK=4
	ENC_PATH=1
	global client_open_files
	global WATERMARK
	global client_keys
	diff=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=diff.read()#crypt.sym_dec(old_write_key,diff.read())
	diff.close()
	diff_obj=parse_log(dec_diff)
	old_filepassw=diff_obj.password
	if diff_obj==False:
		return False
	diff_obj.update_perm(new_permissions[0],new_permissions[1])
	diff_obj.update_secrets(new_csk,new_filepassw)
	pickled_diff=pickle.dumps(diff_obj)
	
	new_log=WATERMARK+hex_string(pickled_diff)+pickled_diff
	new_log_file=new_log#crypt.sym_enc(client_keys[client_open_files[handle][ENC_PATH]][1],new_log)[1]
	
	newdiff=open(client_open_files[handle][LOG_PATH_ON_DISK],'w')
	newdiff.write(new_log_file)
	newdiff.close()
	return (True,old_filepassw)



def test_read_and_write_to_log():
	global client_user
	global client_passw
	global client_loggedIn
	global client_public_keys
	global client_keys
	client_keys={}
	global client_encUser
	global client_open_files
	global WATERMARK
	WATERMARK='hey there!'
	disk_place='testdifflog'
	otherfile='testfile'
	m=open(otherfile,'w+')
	secrets=crypt.create_asym_key_pair()
	writesecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	readsecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	client_keys[encrypt_path(otherfile)]=[readsecret,writesecret]
	filepassw=crypt.hash('abcdefghijklmnop')
	client_open_files[m]=[otherfile,encrypt_path(otherfile),{'checksum':secrets[-1],'edit_number':'hithere','cpk':secrets[1]},otherfile,disk_place,'boby','w+']
	
	#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata
	testdif=difflog.diff_log(secrets[-1],filepassw)
	testdif.update_perm(['hi'],['bye'])
	store=pickle.dumps(testdif)
	store_len=hex_string(store)
	pickledtestdif=str(WATERMARK+store_len+store)
	testing=open(disk_place,'w')
	testing.write(pickledtestdif)
	testing.close()
	if read_permissions_list(m)!=[['hi'],['bye']]:
		return False
	writesecret1=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	readsecret1=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	client_keys[encrypt_path(otherfile)]=[readsecret1,writesecret1]
	write_permissions_and_secrets(m,[['a'],['b']],'someday','bob',writesecret)
	if read_permissions_list(m)!=[['a'],['b']]:
		return False
	return True

def update_checksum(handle,csk):
	if True:
		global WATERMARK
		global client_open_files
		global METADATA
		print client_open_files
		hold_place=api_ftell(handle)
		api_fseek(handle,0,0)
		contents=api_fread(handle)
		new_checksum=create_checksum(client_open_files[handle][METADATA],contents,csk)
		client_open_files[handle][METADATA]['checksum']=new_checksum
		api_fseek(handle,hold_place,0)
		return True
	else:
		return False
	
def test_update_checksum():
	global WATERMARK
	WATERMARK='HI there'
	global client_open_files
	
	testing=open('testing','w+')
	csk=crypt.create_asym_key_pair()[-1]
	testing.write('HI there0x00000002210x0000000120x0000000130x000000014')
	client_open_files[testing]=[1,2,{'checksum':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'cpk':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'edit_number':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1]}]
	print update_checksum(testing,csk)
	print 'done_updating'
	api_fseek(testing,0,0)
	print api_fread(testing)
#test_send_to_server()
#test_encrypt_path()
#test_update_keys()
#test_path_parent()
#test_verify_and_create_checksum()
#test_api_login()

def api_set_permissions(path, handle, new_readers_list, new_writers_list,delete_my_permission=False):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_user
	global client_passw
	global client_public_keys
	global client_keys
	global client_encUser
	
	if client_loggedIn==False:
		return (0,'not logged in')
	permissions_list = read_permissions_list(handle)
	if permissions_list==False:
		return(0,'permissions could not be read')
	enc_path = encrypt_path(path)
	(old_readers_list, old_writers_list) = permissions_list
	new_permissions = [new_readers_list, new_writers_list]

	(old_read_key,old_write_key)=client_keys[enc_path]
	(new_rk, new_wk) = (crypt.create_sym_key(client_passw, enc_path, client_user)[1], crypt.create_sym_key(client_passw+'writer', enc_path, client_user)[1])
	old_permissions=[]
	for readers in old_readers_list:
		if readers not in old_writers_list:
			reader=readers
			store=pickle.dumps((enc_path,old_read_key,None))
			old_permissions.append((reader, crypt.sym_enc(client_public_keys[reader], store)))
	
			
	for writers in old_writers_list:
		writer=writers
		store=pickle.dumps((enc_path,old_read_key,old_write_key))
		old_permissions.append((writer,crypt.sym_enc(client_public_keys[writer], store)))
	###old_permissions=json.dumps(old_permissions)
	client_keys[path]=(new_rk, new_wk)
	store = pickle.dumps((enc_path, new_rk, new_wk))
	my_new_perm  = (client_encUser, crypt.sym_enc(client_public_keys[client_encUser],store))
	###my_new_perm=json.dumps(my_new_perm)
	store = pickle.dumps((enc_path,old_read_key,old_write_key))
	my_old_perm  = (client_encUser, crypt.sym_enc(client_public_keys[client_encUser],store))
	old_permissions.append(my_old_perm)
	
	new_filepassw=randomword(40)
	(le,new_cpk,le2,new_csk)=crypt.create_asym_key_pair()
	diff_old=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff_old=diff.read()#crypt.sym_dec(client_keys[client_open_files[handle][ENC_PATH]][1],diff.read())
	enc_diff_old=crypt.sym_enc(client_keys[enc_path][1],dec_diff)
	change=write_permissions_and_secrets(handle,new_permissions,new_filepassw,new_csk,old_write_key)
	
	diff=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=diff.read()#crypt.sym_dec(client_keys[client_open_files[handle][ENC_PATH]][1],diff.read())
	enc_diff=crypt.sym_enc(client_keys[enc_path][1],dec_diff)
	if change==False:
		return (0,'could not change permissions')
	else:
		old_filepassw=change[1]
	#update checksum of file	
	up=update_checksum(handle,new_csk)
	if up==False:
		return (0,'could not update checksum')
	
	new_permissions=[]
	for readers in new_readers_list:
		reader=readers
		if readers not in new_writers_list:
			store=pickle.dumps((enc_path,old_read_key,None))
			new_permissions.append((reader, crypt.sym_enc(client_public_keys[readers], store)))
	
	for writers in new_writers_list:
		store=pickle.dumps((enc_path,old_read_key,old_write_key))
		writer=writers
		new_permissions.append((writer,crypt.sym_enc(client_public_keys[writer], store)))


	if delete_my_permission==False:
		new_message={"ENC_USER":client_encUser, "OP":"addPermissions", "USERS_AND_PERMS":my_new_perm}
		if send_to_server(new_message)==None:
			return (0,'my new permission')
			
	change_secret={"ENC_USER":client_encUser, "OP":"changeFileSecret", "NEW_SECRET":old_filepassw,"OLD_SECRET":new_filepassw}
	if send_to_server(change_secret)==None:
		return (0,'changing the secret')
	##change the key
	if api_fflush(handle)==None:
		return (0,'flushing log')
		
	removed_perm={"ENC_USER":client_encUser, "OP":"deletePermissions", "USERS_AND_PERMS":old_permissions}
	if send_to_server(removed_perm)==None:
		return (0,'revoking permissions')

	added_perm={"ENC_USER":client_encUser, "OP":"addPermissions", "USERS_AND_PERMS":new_permissions}
	if send_to_server(added_perm)==None:
		return (0,'adding new permissions')

	return 1

def api_list_permissions(handle):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")

	return read_permissions_list(handle)

def test_set_perms():
	global client_user
	client_user='sally'
	global client_passw
	global client_loggedIn
	client_loggedIn=True
	global client_public_keys
	global client_keys
	client_keys={}
	global client_encUser
	client_encUser='sally'
	global client_open_files
	global WATERMARK
	WATERMARK='hey there!'
	disk_place='testdifflog'
	otherfile='testfile'
	m=open(otherfile,'w+')
	m.write('hey there!0x00000002210x0000000120x0000000130x000000014')
	secrets=crypt.create_asym_key_pair()
	writesecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	readsecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	client_keys[encrypt_path(otherfile)]=[readsecret,writesecret]
	filepassw=crypt.hash('abcdefghijklmnop')
	client_open_files[m]=[otherfile,encrypt_path(otherfile),{'checksum':secrets[-1],'edit_number':'hithere','cpk':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1]},otherfile,disk_place,'boby','w+']
	#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata
	
	client_public_keys={'hi':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'bye':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'sally':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1],'tommy':crypt.create_sym_key(randomword(40), randomword(40), randomword(40))[1]}
	testdif=difflog.diff_log(secrets[-1],filepassw)
	testdif.update_perm(['hi'],['bye'])
	store=pickle.dumps(testdif)
	store_len=hex_string(store)
	pickledtestdif=WATERMARK+store_len+store
	testing=open(disk_place,'w')
	testing.write(pickledtestdif)
	testing.close()
	
	print api_set_permissions(otherfile, m, ['sally'], ['tommy'],False)
#test_set_perms()


#### so we can edit in any way we want
def export(handle,text_file):
	global client_open_files
	global client_export_files
	api_fseek(handle,0,0)
	contents=api_fread(handle)
	temp=open(text_file,'w')
	temp.write(contents)
	temp.close()
	found=False
	numb=0
	while found==False:
		if numb not in client_export_files:
			client_export_files[numb]=handle
			found=True
			break
		else:
			numb+=1
	return numb
	
def import_and_flush(number,text_file):
	global client_export_files
	temp=open(text_file,'r')
	contents=temp.read()
	temp.close()
	handle=client_export_files[number]
	api_fseek(handle,0,0)
	api_fwrite(handle,contents)
	api_fflush(handle)
	del client_export_files[number]
	return 1


def test_import_and_export():
	global client_open_files
	
def path_name(path):
	print path, "****"
	newpath=newpath=sanitize_path(path).split('/')
	name=newpath.pop(-1)
	return name
	
	
def api_create_file(path):
	global client_loggedIn
	if not client_loggedIn:
		raise Exception("not logged in")
	
	global client_open_files
	global LOG_PATH_ON_DISK
	global client_keys
	global client_password
	global client_user
	global client_encUser
	global WATERMARK
	if client_loggedIn==False:
		return (0,'not logged in')
	directory=dir_path(path)
	path_filename=path_name(path)
	enc_dir=encrypt_path(directory)
	dir_handle=api_opendir(directory)
	log_file=open(client_open_files[dir_handle][LOG_PATH_ON_DISK],'r')
	data=log_file.read()
	diff_obj=parse_log(data)
	parent_secret=diff_obj.password
	api_fread(dir_handle)
	api_fwrite(dir_handle,'\n add'+path_filename+'\n')
	api_fflush(dir_handle)
	
	#Create filepassw
	filepassw=randomword(40)
	#create csk and cpk
	secret=crypt.create_asym_key_pair()
	#create read and write key
	new_read_key=crypt.create_sym_key(crypt.hash(client_password), path_filename, directory)[1]
	new_write_key=crypt.create_sym_key(crypt.hash(client_password), path_filename, directory)[1]
	enc_filename=crypt.sym_enc(new_read_key, path_filename)[1]
	
	enc_path=encrypt_path(directory)+enc_filename
	client_keys[enc_path]=(new_read_key,new_write_key)
	store = pickle.dumps((enc_path, new_read_key, new_write_key))
	my_new_perm  = (client_encUser, crypt.sym_enc(client_public_keys[client_encUser],store))
	new_log=difflog.diff_log(secret[-1],filepassw)
	new_log.update_perm([],[my_new_perm])
	enc_log=crypt.sym_enc(new_write_key, WATERMARK+hex_string(pickle.dumps(new_log))+pickle.dumps(new_log))

	meta={'edit_number':'0','cpk':secret[1],'checksum':''}
	checksum=create_checkSum(meta,'',secret[-1])
	data=crypt.sym_enc(new_read_key, WATERMARK+hex_string(checksum)+checksum+hex_string(meta['cpk'])+meta['cpk']+hex_string(meta['edit_number'])+meta['edit_number']+'0x00000000')
	create_msg={"ENC_USER":client_encUser, "OP":"createFile", "PARENT_SECRET":file_secret,"SECRET":filepassw,"LOG_DATA":enc_log,"DATA":data}
	if send_to_server(create_msg)==None:
		return (0,'could not create file')
	send_perm={}
	new_message={"ENC_USER":client_encUser, "OP":"addPermissions", "USERS_AND_PERMS":my_new_perm}
	if send_to_server(new_message)==None:
		return (0,'my new permission')	
	
	return api_fopen(path)
	
#def test_api_create_file():
#	#need api_fopen to test
#	print api_create_file('/a/b/c')
#print 'testing createfile'
#test_api_create_file()
 
test_update_keys()

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
import random

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

client_all_public_keys={} 	#key=det(user), val = public key of users
client_user = None
client_encUser = None
client_passw = None
client_working_dir = None
client_secrets = {}
client_loggedIn = False		#True or False. all functions throw an exception if not client_loggedIn
client_keys = {}			#key = enc_path, val = (file_RK, file_WK)
client_permissions_handle = None
client_socket = None
client_open_files = {}		#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata

# tuple-indices for values in client_open_files
PATH = 0
ENC_PATH = 1
METADATA = 2
CONTENTS_PATH_ON_DISK = 3
LOG_PATH_ON_DISK = 4
MODE = 5

def reset_client_vars():
	global client_all_public_keys
	global client_user
	global client_encUser
	global client_passw
	global client_working_dir
	global client_secrets
	global client_loggedIn
	global client_keys
	global client_permissions_handle
	global client_socket
	global client_open_files
	
	client_all_public_keys={}
	client_user = None
	client_encUser = None
	client_passw = None
	client_working_dir = None
	client_secrets = {}
	client_loggedIn = False
	client_keys = {}
	client_permissions_handle = None
		
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
					assert msg.client_send(client_socket, {"ENC_USER":"asaj", "OP":"loginUser", "PASSWORD":"penis"})["STATUS"] == 0
					return resp

			client_err_msgs += resp["ERROR"] + "\n"
		return None
		
	return resp

def setup_socket():
	global client_socket
	client_socket = msg.create_client_socket(SERVER_IP, SERVER_PORT, SOCKET_TIMEOUT)

def test_send_to_server():
	setup_socket()
	assert send_to_server({"ENC_USER":"asaj", "OP":"mkdir", "PATH":"xxxxxnoexist/secondtest"}) is None
	setup_socket()
	assert send_to_server({"ENC_USER":"asaj", "OP":"createUser", "PASSWORD":"penis", "KEY":"55555", "PARENT_SECRET":"00000"})["STATUS"] == 0

	print "YAYY"
	client_socket.close()

def sanitize_path(path):
# returns clean string of path. If path doesn't start with a /, prefixes global path to beginning of string or eror

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

def write_secrets():
	# creates path for data/user/data and data/user/secrets if there is none, writes in new secrets, returns True or False if all operations succeeded
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
		print crypt.sym_enc(client_passw, pickled)
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
	
def test_write_secrets():
	global client_working_dir
	client_working_dir='bobby/w'
	global client_secrets
	client_secrest={'time':'boby'}
	global client_user
	client_user='bbbb'
	global client_passw
	client_passw=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')[1]
	m=write_secrets()
	if m==False:
		return False
	testFile=open('data/bbbb/secrets')
	testString=testFile.read()
	decrypted_pickled=crypt.sym_dec(client_passw, testString)
	test=pickle.loads(decrypted_pickled)
	print test
	if test==client_secrets:
		return True
	else:
		return False

def update_keys():
	global client_keys
	global client_encUser
	global client_secrets
	
	client_keys = {}
	resp = send_to_server({"OP": "getPermissions", "ENC_USER": client_encUser, "TARGET": client_encUser})
	if resp is None:
		return False
	print "******* decrypting perm with user sk *********************"
	for perm_tuple in resp["PERMISSIONS"]:
		(enc_pathname, read_key, write_key) = json.loads(crypt.asym_dec(client_secrets["user_sk"], perm_tuple[2]))
		client_keys[enc_pathname] = (read_key, write_key)
	print "KOBE BRYANTTTTTT"
	return True

def test_update_keys():
	setup_socket()
	global client_keys
	global client_encUser
	global client_secrets
	
	print "1"
	(len_pk, pk, len_sk, sk) = crypt.create_asym_key_pair()
	client_secrets["user_sk"] = sk;
	client_encUser = "asaj"
	perm_len, perm = crypt.asym_enc(pk, json.dumps(("enc_pathname", "read_key", "write_key")))
	perm = (client_encUser, perm)
	
	print "2"
	
	assert send_to_server({"ENC_USER":"asaj", "OP":"createUser", "PASSWORD":"penis", "KEY":"55555", "PARENT_SECRET":"00000"})["STATUS"] == 0
	assert send_to_server({"ENC_USER":"asaj", "OP":"addPermissions", "TARGET":"asaj", "USERS_AND_PERMS": [perm]})["STATUS"] == 0
	
	assert update_keys()
	
	assert client_keys["enc_pathname"] == ("read_key", "write_key")

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

def parse_log_for_file(data):
	"""
	return (secret_number, CSK, edit_list),  None on failure
	"""

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

def parse_log_for_dir(data):
	"""
	return (secret_number, edit_CSK, edit_list),  None on failure
	"""

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
	"""
	//check that user is alphanumeric
	create user_pk, user_sk
	{OP: "createUser", ENC_USER: encUser, passw: passw, user_pk: (len, user_pk)}
	{OP: "ack", STATUS: 0 on success}
	if successful:
		client_secrets ["user_pk"] = (len, user_pk)
		client_secrets ["user_sk"] = (len, user_sk)
		write_secrets()
	"""
	global client_user
	global client_secrets
	global client_passw
	
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
	client_secrets ["user_pk"] = (len_pk, user_pk)
	client_secrets ["user_sk"] = (len_sk, user_sk)
	write_secrets()
	return True
	
def test_api_create_user():
	assert api_create_user("leo?", "123456") == False
	assert api_create_user("leo", "123") == False
	TESTING_ALLOW_RECREATE_USER = False
	api_create_user("leo", "123456")
	TESTING_ALLOW_RECREATE_USER = True

def api_login(user, passw, secretsFile=None):	# LEO
	"""
	if api_login_helper(user, passw, secretsFile):
		passw
	else:
		api_logout()
	"""

def api_login_helper(user, passw, secretsFile):	# LEO
	"""
	//check that user is alphanumeric
	client_user = user
	client_encUser = det(user)
	client_working_dir = "/" + client_user
	client_passw = passw

	if secretsFile is None:
		client_secrets = sym_dec(hash(passw), dataDir/user0/secrets)
		user_sk = client_secrets ["user_sk"]
		user_pk = client_secrets ["user_pk"]
	else:
		client_secrets = sym_dec(hash(passw), dataDir/user0/secrets)
		user_sk = client_secrets ["user_sk"]
		user_pk = client_secrets ["user_pk"]
	client_socket = comm.create_client_socket()
	{OP: "login", ENC_USER: client_enc, User, passw: passw, all_public_keys: all_public_keys}		
	client_all_public_keys = all_public_keys

	{OP: "ack", STATUS: 0 on success, user_pk: (len, user_pk)}
	if status == 0:
		if client_secrets["user_pk"] != all_public_keys[client_enc_user] from server:
			return False
		mkdir dataDir, dataDir/user0 dataDir/user0/data if they don't exist
		if secretsFile != None:
			copy secretsFile to dataDir/user0/secrets
	
		if not update_keys():
			return False
	
		client_permissions_handle = fopen("user0/granted_permissions")
		if client_permissions_handle == 0:
			return False
	
		return True
	else:
		return False
	"""

def api_logout(keepfiles=False):	# logout
	#TODO: close all open files
	#TODO: if !keepfiles, remove dataDir/user/data
	reset_client_vars()

# mode = "r|w"
def api_fopen(path, mode):
	"""
	path = sanitize_path(path)
	enc_path = encrypt_path(path)
	enc_log_path = log_path(enc_path)
	contents_path_on_disk =dataDir/data + path
	
	if enc_path not in client_keys:
		update_keys()
		if enc_path not in client_keys:
			return 0
	if mode =='w' and enc_path not in  client_keys:
		update_keys()
		if enc_path not in client_keys:
			cpk,csk=create_asym_key_pair()
			edit_number=rand
			checksum=asym_enc(csk, hash(''))
			metadata_map={}
			success = save_file("", contents_path_on_disk)	
			if !success:
				return 0
			log_path_on_disk = log_path(contents_path_on_disk)
			metadata_map["checksum"] = checksum
			metadata_map["cpk"] = cpk
			metadata_map["edit_number"] = edit_number			
			metadata_map["secret_number"] = secret_number

			success = save_file(, log_path_on_disk)
			if !success:
				return 0
			dir_handle = api_opendir(dir_path(path))
			if dir_handle == 0:
				return 0
			
			
			
			handle = open(contents_path_on_disk, mode)
			if handle == 0:
				return 0
			old_handle=open(original_path(contents_path_on_disk),mode)
			if old_handle ==0:
				return 0
			client_open_files[handle] = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, original_path(contents_path_on_disk),mode)
			return handle
			
	elif mode == "w" and client_keys[enc_path][1] is None:
		return 0
	else:
		passw
	
	{OP: "downloadFile", ENC_USER: client_encUser, filepath: enc_filepath}
	{OP: "ack", STATUS: 0 on success, data: string}
	if status != 0:
		return 0
	
	data = sym_dec(client_keys[path][0], data)
	parsed = parse_metadata_and_contents_for_file(data)
	if parsed is None:
		return 0
	(metadata_map, contents) = parsed
	
	if not verify_checksum(metadata_map, contents):
		return 0
	
	success = save_file(contents, contents_path_on_disk)	
	if !success:
		return 0

	if client_keys[enc_path][1] is not None:
		{OP: "downloadFile", ENC_USER: client_encUser, filepath: enc_log_path }
		{OP: "ack", STATUS: 0 on success, data: string}
		if status != 0:
			return 0
		log_path_on_disk = log_path(contents_path_on_disk)
		success = save_file(data, log_path_on_disk)
		if !success:
			return 0
	else:
		log_path_on_disk = None

	handle = open(contents_path_on_disk, mode)
	if handle == 0:
		return 0
	oldhandle=open(original_path(contents_path_on_disk),mode)
	if oldhandle==0:
		return 0
	client_open_files[handle] = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, original_path(contents_path_on_disk), mode)

	return handle
	"""

def api_fseek(handle, offset, whence=1):
	return handle.seek(offset,whence)

def api_ftell(handle):
	return handle.tell()

def api_fwrite(handle,data):
	return handle.write(data)

def api_fread(handle,n):
	return handle.read(n)

def api_fflush(handle):
	return handle.flush()


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
	"""
	if attempt_num > 1:
		return 0
	enc_path = client_open_files[handle][ENC_PATH]
	enc_log_path = log_path(enc_path)
	if client_keys[enc_path][1] is None:
		update_keys()
		if client_keys[enc_path][1] is None:
			return 0
	success = fflush(handle)
	if !success:
		return 0
	enc_file_data = create_enc_file_data(handle)
	(enc_log_data, secret_number) = update_enc_log_data_and_get_secret(handle)
	{
		OP: "write_file",
		ENC_USER: client_enc_user,
		enc_file_path: enc_path,
		enc_log_path: enc_log_path
		"secret_number": secret_number}
		enc_file_data: enc_file_data
		enc_log_data: enc_log_data
	}
	if !success
		recursive call (attempt_num+1)
	"""

def api_fclose(handle):	# fclose
	"""
	if mode == "w":
		api_fflush()
	fclose(handle)
	del client_open_files[handle] 
	"""

def api_mkdir(path):
	passw

def api_chdir(path):
	"""
	if path is relative:
		client_working_dir += resolve ".."
	if path is absolute:
		client_working_dir = resolve ".."
	"""

# permissions file contains un-encrypted user names
def api_list_permissions(path):
	"""
	permissions_map = read_permissions_map()
	enc_path = encrypt_path(path)
	if enc_path not in permissions_map:
		return [[],[]]
	else:
		retval = permissions_map[enc_path]
	"""

# the file is f-opened
def api_set_permissions(path, new_readers_list, new_writers_list,delete_my_permission=False):	# JOE
	"""
	permissions_map = read_permissions_map()
	enc_path = encrypt_path(path)
	[old_readers_list, old_writers_list] = permissions_map[enc_path]
	permissions_map[enc_path] = [new_readers_list, new_writers_list]
	write_permissions_map(permissions_map)
	success = api_fflush(client_permissions_handle)
	(old_read_key,old_write_key)=client_keys[path]

	(new_rk, new_wk) = create_sym_key(hash(client_enc_passw), enc_path, client_enc_username), create_sym_key(hash(client_enc_passw), enc_path, client_enc_username)
	
	old_permissions=[]
	for readers in old_readers_list:
		if readers not in old_writers_list:
			store=json (enc_path,old_read_key,None)
			old_permissons.append((det(reader), sym_enc(client_public_keys[det(reader)], store)
	
	for writers in old_writers_list:
		store=joson(enc_path,old_read_key,old_write_key)
		old_permissons.append((det(reader),sym_enc(client_public_keys[det(reader)], store)
	client_keys[path]=(new_rk, new_wk)
	store = json(enc_path, new_rk, new_wk)
	my_new_perm  = (client_enc_user, sym_enc(client_public_key[client_enc_user]))
	
	client_keys[path]=(old_rk, old_wk)
	store = json(enc_path,old_read_key,old_write_key)
	my_old_perm  = (client_enc_user, sym_enc(client_public_key[client_enc_user]))

	new_permissions=[]
	for readers in new_readers_list:
		if readers not in new_writers_list:
			store=json (enc_path,old_read_key,None)
			new_permissons.append((det(reader), sym_enc(client_public_keys[det(reader)], store)
	
	for writers in new_writers_list:
		store=joson(enc_path,old_read_key,old_write_key)
		new_permissons.append((det(reader),sym_enc(client_public_keys[det(reader)], store)

	if !success
		return 0
	if !delete_my_permssion
		{
			OP: "addPermissions",
			ENC_USER: client_enc_user,
			users_and_perms: [my_new_perm]
		}
		if !success
			return 0
	change the key
	api_fflush(permissions_file_handle)
	{
		OP: "removePermissions"
		ENC_USER: client_enc_user
		users_and_perms: [my_old_perm]+old_permissions
	}
	if !success
		return 0
	{
		OP: "addPermissions", 
		ENC_USER=client_enc_user,
		users_and_perms: [new_perms]+new_permissions
		
	}
	if !success
		return 0
	
	return 1
	"""

def api_mkdir(parent, new_dir_name):
	"""
	//filename does not have ".." or slashes
	//make sure new_dir_name contains no slashes
	handle=api_opendir(parent,'w')
	api_fseek(handle) to end
	api_fwrite(handle, "mkdir new_dir_name\n")
	//fflush this
	//tell server to mkdir with secret_number
	api_fclose(handle)
	"""

# same as mv old_parent/old_filename to new_parent/new_filename
def api_mv(old_parent, old_filename, new_parent, new_filename):
	"""
	//filename does not have ".." or slashes
	//TODO: check that you have write access to all children
	handle1 = api_fopen(old_parent)
	return 0 if handle1 == 0
	handle2 = api_fopen(new_parent)
	return 0 if handle2 == 0
	fwrite(handle1, "mv old_parent/old_filename to new_parent/new_filename")
	fwrite(handle2, "mv old_parent/old_filename to new_parent/new_filename")
	fflush(handle1)
	fflush(handle2)
	tell server to do the mv (with secret number)
	fclose(handle1)
	fclose(handle2)
	recursive set perms using api_ls and a queue
	"""

def api_rm(parent_dir, filename):
	"""
	//filename does not have ".." or slashes
	//TODO: check that you have write access to all children
	//make sure new_dir_name contains no slashes
	handle=api_opendir(parent,'w')
	api_fseek(handle) to end
	api_fwrite(handle, "rm filename\n")
	//fflush this
	//tell server to rm while presenting secret number
	setPermissions([],[], True)
	api_fclose(handle)
	"""

def api_opendir(path, mode):
	#handle = api_fopen(dir_metadata_path(path), mode)
	pass

def api_list_dir(handle):
	"""
	compute encrypted dir path by removing the last /.metadata
	ask server to ls enc_dir_path, and send raw data for metadata + log
	decrypt and parse metadata using helper method (?)
	verify_checksum on encrypted filenames
	if not verified
		return false
	listing = []
	iterate through encrypted files
		if you have key:
			listing += [decrypt]
	returning listing
	"""

def api_closedir(handle):
	#api_fclose(handle)
	pass

test_send_to_server()
test_encrypt_path()
test_update_keys()
test_path_parent()
test_verify_and_create_checksum()
#test_api_create_user()
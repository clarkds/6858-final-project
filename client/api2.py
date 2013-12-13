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

import client_globals as client
from config import *
from path import *

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

#All global variables and config constants have been moved to client_clobals.py and config.py

def reset_client_vars():
	
	client.public_keys = {}
	client.user = None
	client.encUser = None
	client.passw = None
	client.working_dir = None
	client.secrets = {}
	client.loggedIn = False
	client.keys = client.DirKey()
	client.path_key = client.DirKey()
	client.enc_path_key = client.DirKey()
		
	if client.socket is not None:
		try:
			client.socket.close()
		except:
			pass
	client.socket = None
		
	client.open_files = {}
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
	try:
		resp = msg.client_send(client.socket, msg_obj)
	except Exception as e:
		print "-------------------"
		traceback.print_exc()
		print "--------------------"
		client.err_msgs += "exception when sending " + json.dumps(msg_obj) + "\n"
		client.err_msgs += str(e)
		clear_state()
		return None
		
	if resp["STATUS"] != 0:
		if "ERROR" in resp.keys():
			client.err_msgs += resp["ERROR"] + "\n"
		return None
		
	return resp

def setup_socket():
	if client.socket is not None:
		try:
			client.socket.close()
		except:
			pass
	client.socket = msg.create_client_socket(SERVER_IP, SERVER_PORT, SOCKET_TIMEOUT)
	return (client.socket is not None)

def encrypt_path(path):	
	assert(path.startswith('/'))
	
	if path == "/":
		return "/"
	
	
	
	path_parts = path.split('/')
	if len(path_parts) == 2:
		return "/" + crypt.det(path_parts[1])
	
	try:
		enc_path = client.path_key[path]
	except:
		enc_path = None
		
	if enc_path is None:
		try:
			path_parts[1] = crypt.det(path_parts[1])
			path = string.join(path_parts,'/')
			enc_path = client.path_key[path]
		except:
			enc_path = None
			print path, "you're fucked"
	
	return enc_path

def write_secrets():
	if client.passw==None:
		return False
	#creates paths for separate users, returns True or False
	try:
		if os.path.exists('data')==False:
			os.mkdir('data')
		pickled=pickle.dumps(client.secrets)
		(len_passw_key, passw_key) = crypt.create_sym_key(client.passw, client.passw, client.passw, False)
		enc_pickle=crypt.sym_enc(passw_key, pickled)[1]
		if os.path.exists('data/'+client.user)==False:
			os.mkdir('data/'+client.user)
		if os.path.exists('data/'+client.user+'/data'):
			os.mkdir('data/'+client.user+'/data')
		
		secret_file=open('data/'+client.user+'/secrets','w')
		secret_file.write(enc_pickle)
		secret_file.close()
		return True
	except:
		traceback.print_exc()
		return False
	
def load_secrets():
	try:
		secret_file=open('data/'+client.user+'/secrets','r')
		(len_passw_key, passw_key) = crypt.create_sym_key(client.passw, client.passw, client.passw, False)
		decrypted_pickle = crypt.sym_dec(passw_key, secret_file.read())
		client.secrets = pickle.loads(decrypted_pickle)
		secret_file.close()
		return True
	except:
		traceback.print_exc()
		return False

def update_keys():
	client.keys = client.DirKey()
	client.path_key = client.DirKey()
	client.enc_path_key = client.DirKey()
	resp = send_to_server({"OP": "getPermissions", "ENC_USER": client.encUser, "TARGET": client.encUser})
	if resp is None:
		return False
	for perm_tuple in resp["PERMISSIONS"]:
		(enc_pathname, read_key, write_key) = json.loads(crypt.asym_dec_long(client.secrets["user_sk"], perm_tuple[2]))
		client.keys[enc_pathname] = (read_key, write_key)
	
	enc_path_list = client.keys.keys()
	
	enc_path_list = [i.split('/')[1:] for i in enc_path_list]
	enc_path_list = sorted(enc_path_list, key = lambda x: len(x))	
	
	for enc_path in enc_path_list:
		path = []
		full_enc_path = '/' + string.join(enc_path, '/')
		if len(enc_path) == 1:
			path.append(enc_path[0])
		elif len(enc_path) == 2:
			path.append(enc_path[0])
			name = crypt.sym_dec(client.keys[full_enc_path][0],enc_path[1])
			path.append(name)
		else:
			path.append(client.enc_path_key["/" + string.join(enc_path[:-1],'/')])
			name = crypt.sym_dec(client.keys[full_enc_path][0], enc_path[-1])
			path.append(name)
		full_path = '/' + string.join(path, '/')
		full_path = sanitize_path(full_path)
		
		client.path_key[full_path] = full_enc_path
		client.enc_path_key[full_enc_path] = full_path
		
	return True

def get_metadata(handle):
	return client.open_files[handle][METADATA]

def get_log_path_on_disk(handle):
	return client.open_files[handle][LOG_PATH_ON_DISK]

# data is decrypted
def parse_metadata_and_contents_for_file(data):
	#returns tuple of (metadata_map,contents) or None
	try:
		bp=0
		watermark=data[0:len(crypt.watermark())]
		if watermark!=crypt.watermark():
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
		traceback.print_exc()
		return None
	
def hex_string(data):
	#takes as input a string and returns the length in a hex of 4 bytes
	data_len= len(data)
	m=str(hex(data_len))
	if len(m)<10:
		newm=m.split('x')
		newm[0]='0x'
		while len(newm[1])<8:
			newm[1]='0'+newm[1]
	return string.join(newm,'')
	

def parse_log(data):
	#returns datalog object
	try:
		bp=0
		watermark=data[0:len(crypt.watermark())]
		if watermark!=crypt.watermark():
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
	except:
		traceback.print_exc()
		return False	

def save_file(data, path_on_disk):
	(parent, filename) = split_path(path_on_disk)
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

# contents is a string
def verify_checksum(metadata_map, contents, printing=False):
	plaintext = contents + metadata_map["cpk"] + metadata_map["edit_number"]
	signature = metadata_map["checksum"]
	public_key = metadata_map["cpk"]
	if printing:
		print "verify ***************\n***************\n******************\n**************"
		print (public_key, plaintext, signature)
	return crypt.verify_dig_sig(public_key, plaintext, signature)
	"""
	hashed = crypt.hash(contents + metadata_map["cpk"] + metadata_map["edit_number"])
	return crypt.asym_dec(metadata_map["cpk"], metadata_map["checksum"]) == hashed
	"""

def create_checksum(metadata_map, contents, csk, printing=False):
	plaintext = contents + metadata_map["cpk"] + metadata_map["edit_number"]
	(len_sig, sig) = crypt.generate_dig_sig(csk, plaintext)
	if printing:
		print "create_checksum ***************\n***************\n******************\n**************"
		print (csk, plaintext)
		print sig
	return (len_sig, sig)
	"""
	hashed = crypt.hash(contents + metadata_map["cpk"] + metadata_map["edit_number"])
	crypt.asym_dec(metadata_map["cpk"], crypt.asym_enc(csk, hashed)[1])
	return crypt.asym_enc(csk, hashed)
	"""

def valid_user_pass(user, passw):
	# allowed: alphanumeric + underscores and dashes
	return re.match('^[\w_-]+$', user) and len(passw) >= 6

def verify_file(file_handle, diff_log):
	for i in diff_log:
		if not verify_dig_sig(client.public_keys[client.encUser], i.patch, i.signature):
			return False
	api_fseek(file_handle,0,0)
	if not verify_checksum(client_openfiles[file_handle][METADATA], api_fread(file_handle)):
		return False
	if not client_openfiles[file_handle][METADATA]["edit_number"] == diff_log[-1].edit_number:
		return False
	return True

#~~~~~~~~~~~~~~~~~~~~~~~ API functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~

def api_get_err_log():
	return client.err_msgs

def api_create_user(user, passw):	# LEO
	clear_state()

	if not valid_user_pass(user, passw):
		return False
	
	client.user = user
	client.encUser = crypt.det(client.user)
	client.passw = passw
	
	(len_pk, user_pk, len_sk, user_sk) = crypt.create_asym_key_pair()
	homedir_secret = randomword(SECRET_LEN)
	setup_socket()
	
	(lenPub, pubKey, lenPriv, privKey) = crypt.create_asym_key_pair()
	new_read_key=crypt.create_sym_key(crypt.hash(client.passw), crypt.det(client.user), '/')[1]
	new_write_key=crypt.create_sym_key(crypt.hash(client.passw), crypt.det(client.user), '/')[1]
	filepassw=randomword(40)
	client.keys['/'+crypt.det(user)]=(new_read_key,new_write_key)
	store = json.dumps(("/" + crypt.det(client.user), new_read_key, new_write_key))
	my_new_perm  = (client.encUser, crypt.asym_enc_long(user_pk,store)[1])
	new_log=difflog.diff_log(privKey,filepassw)
	new_log.update_perm([],[my_new_perm])
	enc_log=crypt.sym_enc(new_write_key, crypt.watermark()+hex_string(pickle.dumps(new_log))+pickle.dumps(new_log))[1]

	meta={'edit_number':'0','cpk':pubKey,'checksum':''}
	checksum=create_checksum(meta,'',privKey)[1]
	data=crypt.sym_enc(new_read_key, crypt.watermark()+hex_string(checksum)+checksum+hex_string(meta['cpk'])+meta['cpk']+hex_string(meta['edit_number'])+meta['edit_number']+'0x00000000')[1]
	
	create_user = {
		"ENC_USER": crypt.det(user),
		"OP": "createUser",
		"PASSWORD": passw,
		"KEY": user_pk,
		"SECRET":filepassw, "META_DATA":data,"LOG_DATA":enc_log}
	create_resp=send_to_server(create_user)
	if create_resp is None:
		return False
	add_perm={
		"ENC_USER":client.encUser,
		"OP":"addPermissions",
		"USERS_AND_PERMS":[my_new_perm],
		"PATH": "/.meta_" + crypt.det(client.user),
		"SECRET": filepassw,
		"LOG_DATA": enc_log
	}
	add_perm_resp = send_to_server(add_perm)
	if add_perm_resp is None:
		return False
	client.secrets["user_pk"] = user_pk
	client.secrets["user_sk"] = user_sk
	success = write_secrets()
	if not success:
		return False
	return login_helper(user, passw, None, True)
	
def api_login(user, passw, secretsFile=None):
	clear_state()
	if login_helper(user, passw, secretsFile, False):
		return True
	else:
		clear_state()
		return False

def login_helper(user, passw, secretsFile, alreadyConnected):	
	client.user = user
	client.encUser = crypt.det(user)
	client.working_dir = "/" + client.user
	client.passw = passw
	
	if secretsFile is not None:
		write_secrets()	# call this to create all the user directory + secret file
		try:
			shutil.copy(secretsFile, "data/"+client.user+"/secrets")
		except:
			traceback.print_exc()
			return False
	
	success = load_secrets()
	if not success:
		return False

	if not alreadyConnected:
		success = setup_socket()
		if not success:
			return False
		resp = send_to_server({
			"ENC_USER": client.encUser,
			"OP": "loginUser",
			"PASSWORD": client.passw})
		if resp is None:
			return False

	resp = send_to_server({
		"ENC_USER": client.encUser,
		"OP": "getAllPublicKeys",
		"PASSWORD": client.passw})
	if resp is None:
		return False

	client.public_keys = {}
	for userAndKey in resp["USERS_AND_KEYS"]:
		client.public_keys[userAndKey[0]] = userAndKey[1]

	if client.secrets["user_pk"] != client.public_keys[client.encUser]:
		return False
	
	if not update_keys():	#TODO: re-fetch public keys during updateKey (use lines above)
		return False
	
	client.loggedIn = True

	return True
	


def api_logout(keepfiles=False):
	send_to_server({'OP': "logoutUser", "ENC_USER": client.encUser})
	clear_state(keepfiles)

def clear_state(keepfiles=False):
	for handle in client.open_files.keys():
		try:
			handle.close()
		except:
			pass
	if not keepfiles:
		try:
			shutil.rmtree("data/" + client.user + "/data")
		except:
			pass
	reset_client_vars()
	client.loggedIn = False	# TODO: take this out after fixing reset_client_vars()

# mode = "r|w"
def api_fopen(path, mode):	
	if not client.loggedIn:
		raise Exception("not logged in")
	
	if mode != "r" and mode != "w":
		print "invalid mode"
		return False
	path = resolve_path(path)
	contents_path_on_disk = "data" + path	#path has a leading slash

	is_dir = (strip_meta(path) != path)
	path = strip_meta(path)
	enc_path = encrypt_path(path)
	if is_dir:
		enc_path = get_metafile_path(enc_path)

	if enc_path is None or strip_meta(enc_path) not in client.keys:
		update_keys()
		enc_path = encrypt_path(path)
		if is_dir:
			enc_path = get_metafile_path(enc_path)		
		
		if enc_path is None or strip_meta(enc_path) not in client.keys:
			if mode == "r":
				print "file does not exist, can't fopen with read mode"
				return False
			else:	#mode == "w"
				return api_create_file(path)	
	
	enc_log_path = get_logfile_path(enc_path)
	
	if mode == "w" and client.keys[enc_path][1] is None:
		print "you don't have write access"
		return False
		
	resp = send_to_server({
		"ENC_USER": client.encUser,
		"OP": "downloadFile",
		"PATH": enc_path})
	if resp is None:
		print "downloadFile (actual file) failure"
		return False
	
	data = crypt.sym_dec(client.keys[enc_path][0], resp["DATA"])
	
	parsed = parse_metadata_and_contents_for_file(data)
	if parsed is None:
		print "parse metadata failed"
		return False
	(metadata_map, contents) = parsed
	
	if not verify_checksum(metadata_map, contents, True):
		print "verify checksum failed"
		return False
	success = save_file(contents, contents_path_on_disk)
	if not success:
		print "save actual file on disk failed"
		return False

	if client.keys[enc_path][1] is not None:
		resp = send_to_server({
			"ENC_USER": client.encUser,
			"OP": "downloadFile",
			"PATH": enc_log_path})
		if resp is None:
			print "downloadFile (log) failed"
			return False
		log_path_on_disk = get_logfile_path(contents_path_on_disk)
		
		data = crypt.sym_dec(client.keys[enc_path][1], resp["DATA"])
		success = save_file(data, log_path_on_disk)
		if not success:
			print "save log on disk failed"
			return False
	else:
		log_path_on_disk = None

	try:
		if mode == "r":
			handle = open(contents_path_on_disk, "r")
		else: #mode == "w"
			handle = open(contents_path_on_disk, "a+")
	except:
		traceback.print_exc()
		return False

	try:
		shutil.copy(contents_path_on_disk, get_original_path(contents_path_on_disk))
	except:
		traceback.print_exc()
		return False

	client.open_files[handle] = (
		path,
		enc_path,
		metadata_map,
		contents_path_on_disk,
		log_path_on_disk,
		get_original_path(contents_path_on_disk),
		mode
	)

	return handle

def api_fseek(handle, offset, whence=1):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	return handle.seek(offset,whence)

def api_ftell(handle):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	return handle.tell()

def api_fwrite(handle,data):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	return handle.write(data)
	
def api_fread(handle,n=None):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	if n==None:
		return handle.read()
	else:
		return handle.read(n)

def api_fflush(handle):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	handle.flush()
	return api_fflush_helper(handle, 0)

def api_fflush_helper(handle, attempt_num):
	if not client.loggedIn:
		raise Exception("not logged in")
	if attempt_num>1:
		return 0
	enc_path=client.open_files[handle][ENC_PATH]
	enc_log_path=get_logfile_path(enc_path)
	
	if client.keys[enc_path][1]==None:
		return 0
	success=handle.flush()
	if success==0:	
		return 0
	place_holder=api_ftell(handle)
	api_fseek(handle,0,0)
	log=open(client.open_files[handle][LOG_PATH_ON_DISK],'r')
	log_data=log.read()

	diff_obj=parse_log(log_data)
	csk=diff_obj.csk
	filepassw=diff_obj.password
	contents=api_fread(handle)
	
	#creating entire file fron contents and metadata and updating editnumber
	client.open_files[handle][METADATA]['edit_number'] = str(int(client.open_files[handle][METADATA]['edit_number'])+1)
	update_checksum(handle,csk)
	checksum=client.open_files[handle][METADATA]['checksum']
	
	edit_number=client.open_files[handle][METADATA]['edit_number']
	cpk=client.open_files[handle][METADATA]['cpk']
	data = crypt.watermark() + hex_string(checksum) + checksum + hex_string(cpk) + cpk + hex_string(edit_number) + edit_number + hex_string(contents) + contents
	enc_data=crypt.sym_enc(client.keys[client.open_files[handle][ENC_PATH]][0],data)
	
	#creating new diff on log
	diff_obj.create_diff(client.user,client.secrets["user_sk"],client.open_files[handle][PATH_TO_OLD_FILE],client.open_files[handle][CONTENTS_PATH_ON_DISK]) #NO comments for right now
	client.secrets[client.open_files[handle][CONTENTS_PATH_ON_DISK]]=client.open_files[handle][METADATA]['edit_number'] #updates last edit_number per user
	pickled=pickle.dumps(diff_obj)
	#updating log file on local disk
	update_log_file=open(client.open_files[handle][LOG_PATH_ON_DISK],'w')
	update_log_file.write(crypt.watermark()+hex_string(pickled)+pickled)
	update_log_file.close()
	
	newlog=crypt.watermark()+hex_string(pickled)+pickled
	enc_log_data=crypt.sym_enc(client.keys[client.open_files[handle][ENC_PATH]][1],newlog)
	
	
	message={'OP': "writeFile", 'ENC_USER': client.encUser,"PATH": enc_path,"SECRET": filepassw, "FILE_DATA": enc_data[1], "LOG_DATA": enc_log_data[1]}
	
	
	if send_to_server(message) is None:
		api_fflush_helper(handle, attempt_num+1)
	
	#updating the oldfile
	old_file=open(client.open_files[handle][PATH_TO_OLD_FILE],'w')
	old_file.write(contents)
	old_file.close()
	api_fseek(handle,place_holder,0)
	
	return 1

def api_fclose(handle):	# fclose
	if not client.loggedIn:
		raise Exception("not logged in")

	if client.loggedIn==False:
		return (0,'client not logged int')
	if client.open_files[handle][MODE]=='a+':
		if api_fflush(handle)==0:
			return (0,'couldnt flush')
	del client.open_files[handle]
	print 'FCLOSE----------------'
	print client.loggedIn
	return handle.close()


def api_chdir(path):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	spec_split = path.split('../')
	client_path_list = client.working_dir.split('/')
	index = len(client_path_list)-len(spec_split)+1
	client_path_list = client_path_list[:index]
	client.working_dir = string.join(client_path_list, '/')
	new_client_path = resolve_path(spec_slit[-1])
	
	client.working_dir = new_client_path

def api_mkdir(path):
	if not client.loggedIn:
		raise Exception("not logged in")	

	path = resolve_path(path)
	(dir_path, dir_name) = split_path(path)
	
	#????enc_dir = encrypt_path(dir_path)
	
	dir_handle = api_opendir(dir_path)
	log_file = open(client.open_files[dir_handle][LOG_PATH_ON_DISK],'r')
	data = log_file.read()
	diff_obj = parse_log(data)
	parent_secret = diff_obj.password
	api_fread(dir_handle)
	api_fwrite(dir_handle,'\n add'+dir_name+'\n')
	api_fflush(dir_handle)
	api_fclose(dir_handle)
	
	#Create filepassw
	filepassw = randomword(40)
	#create csk and cpk
	(lenPub, pubKey, lenPriv, privKey) = crypt.create_asym_key_pair()
	#create read and write key
	new_read_key = crypt.create_sym_key(crypt.hash(client.passw), dir_name, dir_path)[1]
	new_write_key = crypt.create_sym_key(crypt.hash(client.passw), dir_name, dir_path)[1]
	enc_filename = crypt.sym_enc(new_read_key, dir_name)[1]
	
	enc_path = encrypt_path(dir_path) + "/" + enc_filename
	client.keys[enc_path] = (new_read_key,new_write_key)
	client.path_key[path] = enc_path
	client.path_key[enc_path] = path
	
	store = json.dumps((enc_path, new_read_key, new_write_key))
	my_new_perm  = (client.encUser, crypt.asym_enc_long(client.public_keys[client.encUser],store)[1])
	new_log = difflog.diff_log(privKey,filepassw)
	new_log.update_perm([],[my_new_perm])
	enc_log = crypt.sym_enc(new_write_key, crypt.watermark()+hex_string(pickle.dumps(new_log))+pickle.dumps(new_log))

	meta = {'edit_number':'0','cpk':pubKey,'checksum':''}
	checksum = create_checksum(meta,'',privKey)[1]
	meta["checksum"] = checksum
	data = crypt.sym_enc(new_read_key, crypt.watermark() + hex_string(checksum) + checksum + hex_string(meta['cpk'])
		 + meta['cpk'] + hex_string(meta['edit_number']) + meta['edit_number'] + '0x00000000')
	create_msg = {
		"ENC_USER":client.encUser,
		"OP":"mkdir",
		"PARENT_SECRET":parent_secret,
		"SECRET":filepassw,
		"LOG_DATA":enc_log[1],
		"META_DATA":data[1],
		"PATH": enc_path}
	if send_to_server(create_msg)==None:
		return (0,'could not create file')
	send_perm = {}
	
	new_message = {
		"ENC_USER":client.encUser,
		"OP":"addPermissions",
		"USERS_AND_PERMS":[my_new_perm],
		"PATH": get_metafile_path(enc_path),
		"SECRET": filepassw,
		"LOG_DATA": enc_log[1]
	}
	
	if send_to_server(new_message)==None:
		return (0,'my new permission')	
	
	return api_fopen(get_metafile_path(path), "w")

# can only move a single file at the time ->
def api_mv(old_path, new_path):
	if not client.loggedIn:
		raise Exception("not logged in")
		
	handle1 = api_fopen(old_path,'w')
	handle2 = api_fopen(new_path,'w')
	contents = api_fread(handle1)
	client.open_files[handle2][METADATA] = client.open_files[handle1][METADATA]
	client.open_files[handle2][LOG_PATH_ON_DISK] = client.open_files[handle1][LOG_PATH_ON_DISK]
	client.open_files[handle2][CONTENTS_PATH_ON_DISK] = client.open_files[handle1][CONTENTS_PATH_ON_DISK]
	if api_fflush(handle2) != 1:
		return (0,'flush failed')
	if api_rm(handle1) != 1:
		return (0,'rm failed')
	
def api_opendir(path):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	meta=get_metafile_path(path)
	return api_fopen(meta, 'w')
	# TODO: api_fopen should take a prefix that it adds in front of encrypted thingy


def api_rm(path):
	print client.loggedIn
	#if not client.loggedIn:
	#	raise Exception("not logged in")
	
	path = resolve_path(path)
	(parent_path, filename) = split_path(path)
	meta = api_opendir(parent_path)
	check = False
	for m in client.open_files.keys():
		if client.open_files[m][PATH] == path:
			check = True
			break
	if check == True:
		return (0,'file cannot be removed because it is open')
	print client.loggedIn
	api_fread(meta)
	api_fwrite(meta,'\nrm '+filename+'\n')
	api_fflush(meta)
	log_file = open(client.open_files[meta][LOG_PATH_ON_DISK],'r')
	log_data = log_file.read()
	diff_obj = parse_log(log_data)
	filepassw = diff_obj.password
	#TODO: test this
	#if api_set_permissions(resolve_path(get_metafile_path(path)), meta, [], [],True)[0] == 0:
	#	return (0,'could not set permissions')
	message = {"ENC_USER":client.encUser, "OP":"delete", "PARENT_SECRET":filepassw, "PATH":encrypt_path(path)}
	if send_to_server(message) == None:
		return False
	return True
	
def api_path_exists(path):
	if not client.loggedIn:
		raise Exception("not logged in")
	
	enc_path = encrypt_path(path)
	list_directory = {"ENC_USER":client.encUser, "OP":"ls", "PATH":enc_path}
	response = send_to_server(list_directory)
	return response != None

def api_list_dir(path):
	
	if not client.loggedIn:
		raise Exception("not logged in")
	
	enc_path = encrypt_path(path)
	list_directory = {"ENC_USER":client.encUser, "OP":"ls", "PATH":enc_path}
	response = send_to_server(list_directory)
	if response==None:
		return (0,'listing directory')
		
	directory_contents = []
	for object in response["FILES"]:
		obj_enc_path = enc_path + "/" + object
		try:
			file_key = client.keys[obj_enc_path][0]
			file_name = crypt.sym_dec(file_key, object)
			directory_contents.append((file_name, "FILE"))
		except:
			pass
			
	for object in response["FOLDERS"]:
		obj_enc_path = enc_path + "/" + object
		try:
			dir_key = client.keys[obj_enc_path][0]
			dir_name = crypt.sym_dec(dir_key, object)
			directory_contents.append((dir_name, "FOLDER"))
		except:
			pass
			
	return directory_contents

def api_closedir(handle):
	
	if not client.loggedIn:
		raise Exception("not logged in")
	
	#api_fclose(handle)
	pass



def read_permissions_list(handle): ### returns permissons of a file by reading the log of the file

	diff=open(client.open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=diff.read()#crypt.sym_dec(client.keys[client.open_files[handle][ENC_PATH]][1],diff.read())
	diff.close()
	diff_obj=parse_log(dec_diff)
	if diff_obj==False:
		return False
	return diff_obj.perm
	
	
def write_permissions_and_secrets(handle,new_permissions,new_filepassw,new_csk,old_write_key):
	#takes handle of file, as well as new permissions, new filepassw, and new csk and overwrites log file with new things

	diff=open(client.open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=diff.read()#crypt.sym_dec(old_write_key,diff.read())
	diff.close()
	diff_obj=parse_log(dec_diff)
	old_filepassw=diff_obj.password
	if diff_obj==False:
		return False
	diff_obj.update_perm(new_permissions[0],new_permissions[1])
	diff_obj.update_secrets(new_csk,new_filepassw)
	pickled_diff=pickle.dumps(diff_obj)
	
	new_log=crypt.watermark()+hex_string(pickled_diff)+pickled_diff
	new_log_file=new_log#crypt.sym_enc(client.keys[client.open_files[handle][ENC_PATH]][1],new_log)[1]
	
	newdiff=open(client.open_files[handle][LOG_PATH_ON_DISK],'w')
	newdiff.write(new_log_file)
	newdiff.close()
	return (True,old_filepassw)

def update_checksum(handle,csk):
	if True:
		hold_place=api_ftell(handle)
		api_fseek(handle,0,0)
		contents=api_fread(handle)
		new_checksum=create_checksum(client.open_files[handle][METADATA],contents,csk)
		client.open_files[handle][METADATA]['checksum']=new_checksum[1]
		api_fseek(handle,hold_place,0)
		return True
	else:
		return False
	
def api_set_permissions(handle, new_readers_list, new_writers_list,delete_my_permission=False):
	
	if not client.loggedIn:
		raise Exception("not logged in")
	path = client.open_files[handle][PATH]
	is_directory = strip_path(path) != path
	
	if delete_my_permission==False:
		if client.enc_user not in new_writers_list:
			new_writers_list.append(client.enc_user)
		
	permissions_list = read_permissions_list(handle)
	if permissions_list==False:
		return(0,'permissions could not be read')
		
	enc_path = client.open_files[handle][ENC_PATH]
	[old_readers_list, old_writers_list] = permissions_list
	new_permissions = [new_readers_list, new_writers_list]

	(old_read_key,old_write_key)=client.keys[enc_path]
	(new_rk, new_wk) = (crypt.create_sym_key(client.passw, enc_path, client.user)[1],
		crypt.create_sym_key(client.passa+'writer', enc_path, client.user)[1])
	
	#creates permissions to delete
	old_permissions=[]
	for reader in old_readers_list:
		if reader not in old_writers_list:
			store=json.dumps((enc_path,old_read_key,None))
			old_permissions.append((reader, crypt.asym_enc_long(client.public_keys[reader], store)[1]))
	for writer in old_writers_list:
		store=json.dumps((enc_path,old_read_key,old_write_key))
		old_permissions.append((writer,crypt.asym_enc_long(client.public_keys[writer], store)[1]))
	client.keys[enc_path]=(new_rk, new_wk)

	#creates new secret
	new_filepassw=randomword(40)
	(len_csk,new_csk,len_cpk,new_cpk)=crypt.create_asym_key_pair()
	change=write_permissions_and_secrets(handle,new_permissions,new_filepassw,new_csk,old_write_key)
	new_diff=open(client.open_files[handle][LOG_PATH_ON_DISK],'r')
	new_diff_data=new_diff.read()
	enc_diff_new_data=crypt.sym_enc(client.keys[enc_path][1],new_diff_data)
	
	if change==False:
		return (0,'could not change permissions')
	else:
		old_filepassw=change[1]
	#update checksum of file	
	up=update_checksum(handle,new_csk)
	if up==False:
		return (0,'could not update checksum')
	
	new_permissions=[]
	for reader in new_readers_list:
		if reader not in new_writers_list:
			store=json.dumps((enc_path,new_read_key,None))
			new_permissions.append((reader, crypt.asym_enc_long(client.public_keys[reader], store)[1]))
	
	for writer in new_writers_list:
		store=json.dumps((enc_path,new_read_key,new_write_key))
		new_permissions.append((writer,crypt.asym_enc_long(client.public_keys[writer], store)[1]))

	add_perm = {
		"ENC_USER":client.encUser,
		"OP":"addPermissions",
		"USERS_AND_PERMS":new_permissions,
		"PATH": enc_path,
		"SECRET": old_filepassw,
		"LOG_DATA": enc_diff_new_data
	}
			
	add_perm_resp = send_to_server(add_perm)
	
	change_secret = {"ENC_USER":client.encUser, "OP":"changeFileSecret",
		"NEW_SECRET":old_filepassw,"OLD_SECRET":new_filepassw}
	if send_to_server(change_secret)==None:
		return (0,'changing the secret')
		
	removed_perms={"ENC_USER":client.encUser,
		"OP":"deletePermissions",
		"USERS_AND_PERMS":old_permissions,
		"PATH": enc_path,
		"SECRET": new_filepassw,
		"LOG_DATA": enc_diff_new_data}

	if send_to_server(removed_perms)==None:
		return (0,'revoking permissions')
	return (1,'yay!')

def api_list_permissions(handle):	
	if not client.loggedIn:
		raise Exception("not logged in")

	return read_permissions_list(handle)

#### so we can edit in any way we want
def export(handle,text_file):
	
	api_fseek(handle,0,0)
	contents=api_fread(handle)
	temp=open(text_file,'w')
	temp.write(contents)
	temp.close()
	found=False
	numb=0
	while found==False:
		if numb not in client.export_files:
			client.export_files[numb]=handle
			found=True
			break
		else:
			numb+=1
	return numb
	
def import_and_flush(number,text_file):
	temp=open(text_file,'r')
	contents=temp.read()
	temp.close()
	handle=client.export_files[number]
	api_fseek(handle,0,0)
	api_fwrite(handle,contents)
	api_fflush(handle)
	del client.export_files[number]
	return 1
	
	
def api_create_file(path):
	
	if not client.loggedIn:
		raise Exception("not logged in")
	
	directory=get_parent_directory(path)
	path_filename=split_path(path)[1]
	enc_dir=encrypt_path(directory)
	dir_handle=api_opendir(directory)
	log_file=open(client.open_files[dir_handle][LOG_PATH_ON_DISK],'r')
	data=log_file.read()
	diff_obj=parse_log(data)
		
	parent_secret=diff_obj.password
	api_fread(dir_handle)
	api_fwrite(dir_handle,'\n add'+path_filename+'\n')
	api_fflush(dir_handle)
	
	file_secret = randomword(40)
	#create csk and cpk
	(lenPub, pubKey, lenPriv, privKey) = crypt.create_asym_key_pair()
	#create read and write key
	new_read_key=crypt.create_sym_key(crypt.hash(client.passw), path_filename, directory)[1]
	new_write_key=crypt.create_sym_key(crypt.hash(client.passw), path_filename, directory)[1]
	enc_filename=crypt.sym_enc(new_read_key, path_filename)[1]
	
	enc_path = encrypt_path(directory) + "/" + enc_filename
	client.keys[enc_path]=(new_read_key,new_write_key)
	store = json.dumps((enc_path, new_read_key, new_write_key))
	
	my_new_perm  = (client.encUser, crypt.asym_enc_long(client.public_keys[client.encUser],store)[1])
	new_log=difflog.diff_log(privKey,file_secret)
	new_log.update_perm([],[my_new_perm])
	enc_log=crypt.sym_enc(new_write_key, crypt.watermark()+hex_string(pickle.dumps(new_log))+pickle.dumps(new_log))

	meta={'edit_number':'0','cpk':pubKey,'checksum':''}
	checksum=create_checksum(meta,'',privKey, True)[1]
	
	data=crypt.sym_enc(new_read_key, crypt.watermark()+hex_string(checksum)+
		checksum+hex_string(meta['cpk'])+meta['cpk']+hex_string(meta['edit_number'])+
		meta['edit_number']+'0x00000000')
		
	create_msg={"ENC_USER":client.encUser, "OP":"createFile", "PATH": enc_path,
		"PARENT_SECRET":parent_secret,"SECRET":file_secret,"LOG_DATA":enc_log[1],"FILE_DATA":data[1]}
	
	if send_to_server(create_msg)==None:
		return (0,'could not create file')
	perm_msg={"ENC_USER":client.encUser, "OP":"addPermissions", "USERS_AND_PERMS":[my_new_perm],
		"SECRET":file_secret,"LOG_DATA":enc_log[1], "PATH":enc_path}
	if send_to_server(perm_msg)==None:
		return (0,'my new permission')	
	
	client.keys[enc_path] = (new_read_key, new_write_key)
	client.path_key[path] = enc_path
	client.enc_path_key[enc_path] = path
	
	return api_fopen(path, "w")

if __name__ == "__main__":
	pass
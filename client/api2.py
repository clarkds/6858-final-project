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

WATERMARK = "I HOPE THE SEMESTER IS ENDING"

client_all_public_keys={} 	#key=det(user), val = public key of users
client_user = None
client_encUser = None
client_passw = None
client_working_dir = None
client_secrets = {}
client_loggedIn = False		#True or False. all functions throw an exception if not client_loggedIn
client_keys = {}			#key = path, val = (file_RK, file_WK)
client_permissions_handle = None
client_socket = None
client_open_files = {}		#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata

PATH = 0
ENC_PATH = 1
METADATA = 2
CONTENTS_PATH_ON_DISK = 3
LOG_PATH_ON_DISK = 4
MODE = 5

#~~~~~~~~~~~~~~~~~~~~~~~ helper functions ~~~~~~~~~~~~~~~~~~~~~~~

def send_to_server(msg_obj):
	"""
	try {
		resp = client_send()
	} catch Exception {
		resp = None
	}
	if resp == None:
		logout()
	return resp
	"""
	passw

def read_from_server():
	"""
	similar to above
	if STATUS != 0, also append ERRMSG to client_err_msgs
	"""

def sanitize_path(path):
	"""
	clean up the slashes
	add working directory if necessary
	"""

def encrypt_path(path):
	passw

# any_path can be non-encrypted or encrypted
def log_path(any_path):
	"""
	add a .log in front of the last part of path
	"""

def write_secrets():
	"""
	mkdir dataDir, dataDir/user0 dataDir/user0/data
	sym_enc(hash(passw), pickle(secrets)) > dataDir/user0/secrets
	"""

def update_keys():
	"""
	client_keys = {}
	{OP: "getPermissions", ENC_USER: client_encUser}
	{OP: "ack", STATUS: 0 on success, permissions: [jenc_perm1, enc_perm2, enc_perm3]}
	if status != 0:
		return False
	for each perm in permissions:
		(enc_pathname, read_key, write_key) = un-json(asm_dec(client_user_sk, perm))
		client_keys[enc_pathname] = (read_key, write_key)
	return True
	"""

def get_metadata(handle):
	"""
	return client_open_files[handle][METADATA]
	"""

def get_log_path_on_disk(handle):
	"""
	return client_open_files[handle][LOG_PATH_ON_DISK]
	"""

# data is decrypted
def parse_metadata_and_contents_for_file(data):
	"""
	metadata_map = {}
	//insert checksum, CPK, edit_number
	return (metadata_map, contents), None on failure
	"""

def parse_log_for_file(data):
	"""
	return (secret_number, CSK, edit_list),  None on failure
	"""

def parse_metadata_for_dir(data):
	"""
	metadata_map = {}
	//insert checksum, CPK, edit_number
	return metadata_map,  None on failure
	"""

def parse_log_for_dir(data):
	"""
	return (secret_number, edit_CSK, edit_list),  None on failure
	"""

def save_file(data, path_on_disk):
	"""
	create all parent directories
	write file
	close file
	return True or False
	"""

# contents is a string
def verify_checksum(metadata_map, contents):
	"""
	return asym_dec(metadata_map["cpk"], metadatamap["checksum"]) == hash(contents|metadata_map["cpk"]|metadata_map[""]|metadata_map["edit_number"])
	"""

def create_checksum(metadata_map, contents):
	"""
	return enc(metadata_map["csk"], hash(contents|metadata_map["cpk"]|metadata_map[""]|metadata_map["edit_number"]))
	"""

# permissions_map: key=enc_path, val=[enc_reader_names_list, enc_writer_names_list]
def read_permissions_map():
	"""
	permissions_file_contents = read(client_permissions_handle)
	if permissions_file_contents == "":
		return {}
	else:
		return unpickle(permissions_file_contents )
	"""

def write_permissions_map(permissions_map):
	"""
	truncate(handle)
	fwrite(permissions_map, client_permissions_handle)
	"""

#~~~~~~~~~~~~~~~~~~~~~~~ API functions ~~~~~~~~~~~~~~~~~~~~~~~~~~~

def api_get_err_log():
	"""
	return client_err_msgs
	"""

def api_create_user(user, passw):
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

def api_login(user, passw, secretsFile=None):
	"""
	if api_login_helper(user, passw, secretsFile):
		passw
	else:
		api_logout()
	"""

def api_login_helper(user, passw, secretsFile):
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

def api_logout(keepfiles=False):
	"""
	clear all global variables, set client_loggedIn = false	
	close all open files
	if !keepfiles:
		remove dataDir/user/data
	"""

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

def api_fseek(handle, offset, whence):
	#return fseek(handle, offset, whence)
	pass

def api_ftell(handle):
	#return ftell(handle)
	pass

def api_fwrite(data, handle):
	#return handle.write(data, handle)
	pass

def api_fread(n, handle):
	#return fread(n, handle)
	pass

def api_fflush(handle):
	#return api_fflush_helper(handler, 0)
	pass

def api_fflush_helper(handle, attempt_num):
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

def api_fclose(handle):
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
def api_set_permissions(path, new_readers_list, new_writers_list,delete_my_permission=False):
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

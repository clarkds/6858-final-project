#client_working_dir=None
import string
import os
import pickle
import crypt
import json
client_working_dir='bobby/w'
client_secrets={'time':'boby'}
client_user='bbbb'
client_passw='Johnsefealsinf ioeasnf kaesf iew'
WATERMARK='HI there'
def sanitize_path(path):
	global client_working_dir
	# returns clean string of path. If path doesn't start with a /, prefixes global path to beginning of string or eror
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
	
print sanitize_path('../a/../b/c')
print sanitize_path('/a/b/c')

#check if response is None

### change both secrets
#### 
def test_sanitize_path():
	client_working_dir='bobby/w'
	print sanitize_path('a/b/c')
	print sanitize_path('/a/b/c')


def log_path(path):
	# appens .log_ to begining of last part of the path
	newpath=sanitize_path(path).split('/')
	newpath[-1]='.log_'+newpath[-1]
	return string.join(newpath,'/')
	
print log_path('/a/b/c')


def write_secrets():
	global client_user
	global client_secrets
	global client_passw
	if client_passw==None:
		return False
	#creates paths for separate users, returns True or False
	if True:
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
	else:
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
	client_passw=None
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

#print test_write_secrets()
	
	

def parse_metadata_and_contents_for_file(data):
	#returns tuple of (checkSum,CPK,edit_number,contents) or None
	try:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
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
		return (checkSum,CPK,edit_number,contents)
	except:
		return None
	
def test_parse_metadata_and_contents_for_file():
	data='HI there0x00000002210x0000000120x0000000130x000000014'
	print parse_metadata_and_contents_for_file(data)
	
def parse_log(data):
	try:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
		bp+=len(watermark)
		contents_Hex=data[bp:bp+10]
		contents_len=int(file_secret_Hex,16)
		bp+=10
		contents=data[bp:bp+file_secret_len]
		diffObj=pickle.loads(contents)
		###need to figure out how this works
		return None
	except:
		return None
	"""
	return (secret_number, CSK, edit_list),  None on failure
	"""
	
def test_parse_log():
	data='HI there0x00000002210x0000000120x000000013'
	print parse_log(data)

test_parse_log()








def parse_metadata_for_dir(data):
	#returns (checkSum,CPK,edit_number,contents) or None
	try:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
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
		return (checkSum,CPK,edit_number,contents)
	except:
		return None
	
def test_parse_metadata_for_dir():
	data='HI there0x00000002210x0000000120x0000000130x000000014'
	print parse_metadata_and_contents_for_file(data)
	"""
	metadata_map = {}
	//insert checksum, CPK, edit_number, password
	return metadata_map,  None on failure
	"""
test_parse_metadata_for_dir()




client_open_files = {}		#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)



### file must be open in r+
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
	newfile=open('testingfile','r+')
	client_open_files[newfile]={'boby':'test'}
	print client_open_files[newfile]
	print api_fwrite(newfile,'this is a test of the fwrite function')
	print data
	print api_fflush(newfile)
	print api_fseek(newfile,0,0)
	print api_fread(newfile,10)
	print data
	print api_ftell(newfile)
	newfile.close()
	print client_open_files[newfile]
	
#test_fseek_ftell_fwrite_fread_fflush()	



def read_permissions_list(handle): ### for testing
	m=[[('sally',crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa'))],[('tommy',crypt.create_sym_key('asdfjklasdfjkl', 'tommy', 'bbbbbbb'))]]
	print m
	return m
	
def encrypt_path(path):
	return '/user1/a/b/boby'
	
def write_permissions_list(handle,new_permissions):
	return True

def api_client_send(msg):
	print msg
	return True

def api_fflush(handle):
	return True
	
def cryptdet(s):
	return 'sek.fnaseoifbn'

def api_set_permissions(path, log_handle, new_readers_list, new_writers_list,delete_my_permission=False):
	global client_user
	global client_passw
	global client_loggedIn
	global client_public_keys
	global client_keys
	global client_encUser
	
	if client_loggedIn==False:
		return None
	permissions_list = read_permissions_list(log_handle)
	enc_path = encrypt_path(path)
	[old_readers_list, old_writers_list] = permissions_list
	new_permissions = [new_readers_list, new_writers_list]
	write_permissions_list(log_handle,new_permissions)
	(old_read_key,old_write_key)=client_keys[path]
	(new_rk, new_wk) = crypt.create_sym_key(crypt.hash(client_passw), enc_path, client_user), crypt.create_sym_key(crypt.hash(client_passw), enc_path, client_user)
	old_permissions=[]
	for readers in old_readers_list:
		reader=readers[0]
		if readers not in old_writers_list:
			store=pickle.dumps((enc_path,old_read_key,None))
			old_permissions.append((reader, crypt.sym_enc(client_public_keys[reader][1], store)))
	
			
	for writers in old_writers_list:
		writer=writers[0]
		store=pickle.dumps((enc_path,old_read_key,old_write_key))
		old_permissions.append((writer,crypt.sym_enc(client_public_keys[writer][1], store)))
	###old_permissions=json.dumps(old_permissions)
	client_keys[path]=(new_rk, new_wk)
	store = pickle.dumps((enc_path, new_rk, new_wk))
	my_new_perm  = (client_encUser, crypt.sym_enc(client_public_keys[client_encUser][1],store))
	###my_new_perm=json.dumps(my_new_perm)
	store = pickle.dumps((enc_path,old_read_key,old_write_key))
	my_old_perm  = (client_encUser, crypt.sym_enc(client_public_keys[client_encUser][1],store))
	old_permissions.append(my_old_perm)
	
	new_permissions=[]
	for readers in new_readers_list:
		reader=readers
		if readers not in new_writers_list:
			store=pickle.dumps((enc_path,old_read_key,None))
			new_permissions.append((reader, crypt.sym_enc(client_public_keys[readers][1], store)))
	
	for writers in new_writers_list:
		store=pickle.dumps((enc_path,old_read_key,old_write_key))
		writer=writers
		new_permissions.append((writer,crypt.sym_enc(client_public_keys[writer][1], store)))


	if delete_my_permission==False:
		new_message={"ENC_USER":client_encUser, "OP":"addPermissions", "USERS_AND_PERMS":my_new_perm}
		if api_client_send(new_message)==None:
			return (0,'my new permission')
			
			
	##change the key
	if api_fflush(log_handle)==None:
		return (0,'flushing log')
		
	removed_perm={"ENC_USER":client_encUser, "OP":"deletePermissions", "USERS_AND_PERMS":old_permissions}
	if api_client_send(removed_perm)==None:
		return (0,'revoking permissions')

	added_perm={"ENC_USER":client_encUser, "OP":"addPermissions", "USERS_AND_PERMS":new_permissions}
	if api_client_send(added_perm)==None:
		return (0,'adding new permissions')

	return 1

def test_set_perms():
	global client_user
	client_user='bob'
	global client_passw
	client_passw='bob'
	global client_loggedIn
	client_loggedIn=True
	global client_public_keys
	client_public_keys={'bob':crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa'),'sally':crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa'),'tommy':crypt.create_sym_key('asdfjklasdfjkl', 'tommy', 'bbbbbbbb')}
	global client_keys
	client_keys={'/a/b/c':((3,'one'),(3,'two'))}
	global client_encUser
	client_encUser=client_user
	print api_set_permissions('/a/b/c', 'log_handle', ['sally'], ['tommy'], delete_my_permission=False)
test_set_perms()

#"""
#	mkdir dataDir, dataDir/user0 dataDir/user0/data
#	sym_enc(hash(passw), pickle(secrets)) > dataDir/user0/secrets
#	"""
#client_working_dir=None
import string
import os
import pickle
import crypt
import json
import difflog
import sys


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


#check if response is None

### change both secrets
#### 
def test_sanitize_path():
	global client_working_dir
	client_working_dir='bobby/w'
	if sanitize_path('a/b/c')!='bobby/w/a/b/c':
		return False
	if sanitize_path('/a/b/..//c')!='/a/b/c':
		return False
	return True
print 'testinsgsanitization'
print test_sanitize_path()



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
print 'testinglog'
print test_log_path()

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

print test_write_secrets()
	
	

def parse_metadata_and_contents_for_file(data):
	#returns tuple of (checkSum,CPK,edit_number,contents) or None
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

	
print 'testing2'
print test_parse_metadata_and_contents_for_file()

def hex_string(data):
	data_len= sys.getsizeof(data)
	m=str(hex(data_len))
	if len(m)<10:
		newm=m.split('x')
		newm[0]='0x'
		while len(newm[1])<8:
			newm[1]='0'+newm[1]
	return string.join(newm,'')

print 'hex_string'
def test_hex_string():
	w='what in the world is going on?'
	if hex_string(w)!='0x00000043':
		return False
	return True
print test_hex_string()
			

def parse_log(data):
	#returns datalog object
	if True:
		global WATERMARK
		bp=0
		watermark=data[0:len(WATERMARK)]
		if watermark!=WATERMARK:
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
	"""
	return (secret_number, CSK, edit_list),  None on failure
	"""
	
def test_parse_log():
	datapickle=pickle.dumps({'hi':'by'})
	size=hex_string(datapickle)
	data='HI there'+size+datapickle
	if parse_log(data)!={'hi':'by'}:
		return False
	else:
		return True

print 'testlog'
print test_parse_log()



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

print 'testingdir'
print test_parse_metadata_for_dir()




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

print 'testingfiles'	
print test_fseek_ftell_fwrite_fread_fflush()	



def read_permissions_list(handle): ### returns permissons of a file by reading the log of the file

	LOG_PATH_ON_DISK=4
	ENC_PATH=1
	global client_open_files
	global client_keys
	diff=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=crypt.sym_dec(client_keys[client_open_files[handle][ENC_PATH]],diff.read())
	diff.close()
	diff_obj=parse_log(dec_diff)
	if diff_obj==False:
		return False
	return diff_obj.perm
	
def encrypt_path(path):
	return '/user1/a/b/boby'
	
def write_permissions_and_secrets(handle,new_permissions,new_filepassw,new_csk,old_write_key):
	#takes handle of file, as well as new permissions, new filepassw, and new csk and overwrites log file with new things
	LOG_PATH_ON_DISK=4
	ENC_PATH=1
	global client_open_files
	global WATERMARK
	global client_keys
	diff=open(client_open_files[handle][LOG_PATH_ON_DISK],'r')
	dec_diff=crypt.sym_dec(old_write_key,diff.read())
	diff.close()
	diff_obj=parse_log(dec_diff)
	diff_obj.update_perms(new_permissions[0],new_permissions[1])
	diff_obj.update_secrets(new_csk,new_filepassw)
	pickled_diff=pickle.dumps(diff_obj)
	
	new_log=WATERMARK+hex_string(pickled_diff)+pickled_diff
	new_log_file=crypt.sym_enc(client_keys[client_open_files[handle][ENC_PATH]],new_log)
	
	newdiff=open(client_open_files[handle][LOG_PATH_ON_DISK],'w')
	newdiff.write(new_log_file)
	newdiff.close()
	return True


def test_read_and_write_to_log():
	global client_user
	global client_passw
	global client_loggedIn
	global client_public_keys
	global client_keys
	client_keys={}
	global client_encUser
	global client_open_files

	disk_place='testdifflog'
	otherfile='testfile'
	m=open(otherfile,'w+')
	secrets=crypt.create_asym_key_pair()
	writesecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')
	readsecret=crypt.create_sym_key('asdfjklasdfjkl', 'sally', 'aaaaaaaa')
	client_keys[encrypt_path(otherfile)]=[readsecret,writesecret]
	filepassw=crypt.hash('abcdefghijklmnop')
	client_open_files[m]=[otherfile,encrypt_path(otherfile),{'checksum':secrets[-1],'edit_number':'hithere','cpk':secrets[1]},otherfile,disk_place,'boby','w+']
	
	#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata
	testdif=difflog.diff_log(secrets[-1],filepassw)
	pickledtestdif=crypt.sym_enc(writesecret[-1],pickle.dumps(testdif))
	testing=open(disk_place,'w')
	testing.write(pickledtestdif)
	testing.close()
	print read_permissions_list(m)

print 'logreadtest'
test_read_and_write_to_log()
	
	
	






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
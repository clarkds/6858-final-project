#client_working_dir=None
import string
import os
import pickle
import crypt
import json
import difflog
import sys
import random


client_working_dir='bobby/w'
client_secrets={'time':'boby'}
client_user='bbbb'
client_passw='Johnsefealsinf ioeasnf kaesf iew'
WATERMARK='HI there'
PATH = 0
ENC_PATH = 1
METADATA = 2
CONTENTS_PATH_ON_DISK = 3
LOG_PATH_ON_DISK = 4
PATH_TO_OLD_FILE=5
MODE = 6
def randomword(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))

def hex_string(data):
	data_len= sys.getsizeof(data)
	m=str(hex(data_len))
	if len(m)<10:
		newm=m.split('x')
		newm[0]='0x'
		while len(newm[1])<8:
			newm[1]='0'+newm[1]
	return string.join(newm,'')

def verify_checksum(metadata_map, contents):
	return crypt.asym_dec(metadata_map["cpk"], metadata_map["checksum"]) == crypt.hash(contents + metadata_map["cpk"] + metadata_map["edit_number"])

def create_checksum(metadata_map, contents, csk):
	hashed = crypt.hash(contents + metadata_map["cpk"] + metadata_map["edit_number"])
	return crypt.asym_enc(csk, hashed)[1]


	
		
		

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

print 'secretestest'
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

def api_fread(handle,n=None):
	if n==None:
		return handle.read()
	else:
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
	dec_diff=diff.read()#crypt.sym_dec(client_keys[client_open_files[handle][ENC_PATH]][1],diff.read())
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

print 'logreadtest'
print test_read_and_write_to_log()
	
def send_to_server(a):
	print a
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
	
print 'testing fflush_helper'
test_api_fflush_helper()
	
		




def send_to_server(msg):
	print msg
	return True

def api_fflush(handle):
	return True
	
def cryptdet(s):
	return 'sek.fnaseoifbn'
def randomword(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))
   





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
	
print 'testing_update_checksum'
test_update_checksum()

def api_set_permissions(path, handle, new_readers_list, new_writers_list,delete_my_permission=False):
	global client_user
	global client_passw
	global client_loggedIn
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
	
	change=write_permissions_and_secrets(handle,new_permissions,new_filepassw,new_csk,old_write_key)
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
test_set_perms()
	
#"""
#	mkdir dataDir, dataDir/user0 dataDir/user0/data
#	sym_enc(hash(passw), pickle(secrets)) > dataDir/user0/secrets
#	"""
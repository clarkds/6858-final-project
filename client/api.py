import crypt
import string #used to deal with pathnames
import os #used to create files
import pickle #used to easily store and load the lastInput dictionary
import comm
import json

################### global variables #######################################
################################################################################################
keyChain={} ## -> keyChain = dictionary with path:[symkey,asymkeys] for file
activeHandlers={} ## -> activeHandlers= dictionary with path:[handle,offset,read/write]
privateKey='' ##secretKey ->secretKey of user
publicKey='' ##publicKey -> publicKey of user
user='' ##user -> user who is using the client
encUser = ''	## encUser -> encrypted user name
lastInput={} ## ->the last change for each file ->dictionary with path:last update you gave the file, this must be updated everytime you write to a file
currentPath='' #the current (un-encrypted) path varaiable the user is on

##################################################################################################
##################################################################################################



################### helper functions created #######################################
################################################################################################

# sanitizes the path (removes duplicate slashes, trailing slashes)
# ex: sanitize_path('//a/b/c//d//') => ('/a/b/c/d', ['', 'a', 'b', 'c', 'd'])
# For an absolute path, the path_parts[0]='' and path_parts[1]=user
def sanitize_path(path):
	path_parts = path.split('/')
	path_parts = [path_parts[0]] + filter(None, path_parts[1:])	# remove empty strings from list
	clean_path = string.join(path_parts,'/')
	return (clean_path, path_parts)

# returns encrypted path of the path
# path must be absolute
def encrypted_path(path):
	assert(path.startswith('/'))
	(path,oldpath) = sanitize_path(path)	
	newpath = oldpath[:]
	newpath[1]=crypt.det(newpath[1])
	for part in range(2,len(newpath)):
		previousPath=string.join(oldpath[0:part+1],'/')
		(cipher_len, ciphertext) =crypt.sym_enc(keyChain[previousPath][0],newpath[part])
		newpath[part] = ciphertext
	return string.join(newpath,'/')

# finds the path for the logfile of the file
def logfile_path(path):
	(clean_path, newpath)=sanitize_path(path)
	newpath[-1]='.log_'+newpath[-1]
	return string.join(newpath,'/')
	
#gets the path to the log file of the lowest directory path is in (if path is a directory, returns logfile of directory above path)
def dir_log_path(path):
	(clean_path, newpath)=sanitize_path(path)
	newpath[-1]='.log_'+newpath[-2]
	return string.join(newpath,'/')

def dir_checkSum_path(path): #includes checksum, edit number, and watermark, and public key for checksum ((if path is a directory, returns checkSum of directory above path)
	(clean_path, newpath)=sanitize_path(path)
	newpath[-1]='.checkSum_'+newpath[-2]
	return string.join(newpath,'/')

#gets path to directory (if path is a directory, returns path of directory above path)
def dir_path(path):
	(clean_path, newpath)=sanitize_path(path)
	return string.join(newpath[:-1],'/')

##################################################################################################
##################################################################################################



################### functions needed but not created yet #######################################
################################################################################################


#checks watermark, and if you have write acces can check last update, returns True if it checks out
def check_received_file(filename,logfilename=None):
	pass

# get all our file keys from the server
def update_keyChain():
	reply = client_send({
		"ENC_USER": encUser,
		"OP": "getPermissions"})
	permissions = reply["permissions"]
	
	newKeyChain = {}
	newKeyChain[user] = keyChain[user]
	for perm in permissions:
		permJson = asym_dec(privateKey, perm)
		(filepath, file_rk, file_wk) = json.loads(permJson)
		newKeyChain[filepath] = (file_rk, file_wk)
	keyChain = newKeyChain
	
#returns temporary filename of downloaded ftp file
def receive_file(encryptedpath):
	pass

#tells server to create a directory for detuser, returns True if succeeds
def server_create_user(detUser):
	pass

#clears global variables and logs user out
def logout():
	pass
	
#init(username)
#destroy()

#fseek(handle, offset, whence)
#ftell(handle)
#fwrite(binary, numbytes, handle)
#binary fread(n, handle)
#fclose(handle)

#mkdir(path)
#chdir(path)

#struct fstat(path) - search for key in our table
#list of users & permisions list_permissions(path)
# grant(path, user, R/W):
	
#revoke(path, user)
#mv(oldpath, newpath)
#rm(path)
#iterator opendir(path)
#readdir(iterator)
#closedir(iterator)

#possible -> save permissions to file in client so root can't render file system inert by destroying permissions table

##################################################################################################
##################################################################################################

	
################### functions created #######################################
################################################################################################


### logs in the user and updates the global variables
def login(username,password):
	encryptUserName=crypt.det(username)
	if os.path.exists('users/'+encUserName)==False:
		success = False
	else:
		secrets=open('users/'+encUserName+'/secret','r')
		cipher=secrets.read()
		secrets.close()
		waterMark=crypt.watermark()
		plaintext=crypt.clientDecrypt(password,cipher)
		if waterMark==plaintext.split('\n')[0]:
			privateKey=plaintext.split('\n')[2]
			publicKey=plaintext.split('\n')[1]
			user=username
			encUser = encUserName
			keyChain[user]=crypt.det(user)
			update_keyChain()
			savedLogs=open('users/'+encUserName+'/savedLogs','w')
			lastInput=pickle.load(savedLogs)
			savedLogs.close()
			currentPath="/" + user
			success=True
		else:
			success = False
	return success



### creates a user of the system for the client, logins them in, then 
def create_user(username,password):
	encUserName=crypt.det(username)
	(len_pk, pk, len_sk, sk) = crypt.create_asym_key_pair()
	privKey=sk
	pubKey=pk
	check = server_create_user(encUserName)
	if os.path.exists('users/'+encUserName)==False and check==True:
		os.mkdir('users/'+encUserName)
		secret=open('users/'+encUserName+'/secret','w')
		waterMark=crypt.watermark()
		secret.write(crypt.clientEncrypt(password,waterMark+'\n'+pubKey+'\n'+privKey))
		secret.close()
		savedLogs=open('users/'+encUserName+'/savedLogs','w')
		lastInput['None']="none"
		pickle.dump(lastInput,savedLogs)
		savedLogs.close()
		success=login(username,password)
	else:
		success=False
	return success
	

# python automatically handles memory, so we only need strings to hold the contents of the file we want to create or read
#creates new file if not on the keychain, way == r ->read permissions, w ->write permissions, success allows us to write error messages for why open does not succeed
def fopen(path, way):
	if way=='w':
		#make sure users have permission to write in directory
		if dir_log_path(path) not in keyChain:
			update_keyChain()# make sure we don't have permission
		#if user is creating a new file
		if dir_log_path(path) in keyChain and path not in keyChain:
			fileAsymKeys=crytpto.create_asym_key_pair()
			fileSymKey=crypt.create_sym_key()
			difFileSymKey=crypt.create_sym_key()
			keyChain[path]=[fileSymKey,fileAsymKeys]
			keyChain[logfile_path(path)]=[difFileSymKey,fielAsymKeys]
			activeHandlers[path]=['',0,'w']
			activeHandlers[logfile_path(path)]=['',0,'w']
			success=[True,'w']
		#if the file exits and have both permission for log file and file in keyChain
		elif logfile_path(path) in keyChain and path in keyChain:
			encPath=encrypted_path(path)
			encLogPath=encrypted_path(logfile_path(path))
			tmpFile=receive_file(encPath)
			tmpLogFile=receive_file(encLogPath)
			success=[check_received_file(tmpFile,tmpLogFile), 'w']
			if success[0]==True:
				receivedFile=open(tmpFile,'r')
				receivedLogFile=open(tmpLogFile,'r')
				activeHandlers[path]=[receivedFile.read(),0,'w']
				activeHandlers[logfile_path(path)]=[receivedLogFile.read(),0,'w']
				receivedFile.close()
				receivedLogFile.close()
			else:
				success[1]='Problem with file'
		else:
			success=[False,'Incorrect permissions']
	#if we only want to read the file		
	else:
		if path not in keyChain:
			update_keyChain()#####  -> make sure we don't have permission
		if path not in keyChain: # this means file doesn't exist or don't have correct permissions
			success=fopen(path,'w')
			if success[0]==False:
				success[1]='Incorrect permissions'
		else:
			encPath=encrypted_path(path)
			tmpFile=receive_file(encPath)
			success=[check_received_file(tmpFile,tmpLogFile), 'w']
			if success[0]==True:
				receivedFile=open(tmpFile,'r')
				activeHandlers[path]=[receivedFile.read(),0,'w']
				receivedFile.close()
				receivedLogFile.close()
			else:
				success[1]='Problem with file'
	return success		
		
##################################################################################################
##################################################################################################

		



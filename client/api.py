import crypto
import string #used to deal with pathnames
import os #used to create files
import pickle #used to easily store and load the lastInput dictionary

################### global variables #######################################
################################################################################################
keyChain={} ## -> keyChain = dictionary with path:[symkey,asymkeys] for file
activeHandlers={} ## -> activeHandlers= dictionary with path:[handle,offset,read/write]
privateKey='' ##secretKey ->secretKey of user
publicKey='' ##publicKey -> publicKey of user
user='' ##user -> user who is using the client
lastInput={} ## ->the last change for each file ->dictionary with path:last update you gave the file, this must be updated everytime you write to a file
currentPath='' #the current path varaiable the user is on

##################################################################################################
##################################################################################################



################### helper functions created #######################################
################################################################################################


## returns encrypted path of the path 
def encrypted_path(path):
	oldpath=path.split('/')
	newpath = path.split('/')
	newpath[0]=crypto.det(newpath[0])
	for part in range(1,len(newpath)):
		previousPath=string.join(oldpath[0:part+1],'/')
		newpath[part]=crypto.sym_enc(keyChain[previousPath][0],newpath[part])
	return string.join(newpath,'/')


# finds the path for the logfile of the file
def logfile_path(path):
	newpath=path.split('/')
	newpath[-1]='.log'+newpath[-1]
	return string.join(newpath,'/')
	
#gets the path to the log file of the lowest directory path is in (if path is a directory, returns logfile of directory above path)
def dir_log_path(path):
	newpath = path.split('/')
	newpath[-1]='.log'+newpath[-2]
	return string.join(newpath,'/')

def dir_checkSum_path(path): #includes checksum, edit number, and watermark, and public key for checksum ((if path is a directory, returns checkSum of directory above path)
	newpath = path.split('/')
	newpath[-1]='.checkSum'+newpath[-2]
	return string.join(newpath,'/')

#gets path to directory (if path is a directory, returns path of directory above path)
def dir_path(path):
	newpath = path.split('/')
	return string.join(newpath[:-1],'/')

##################################################################################################
##################################################################################################



################### functions needed but not created yet #######################################
################################################################################################


#checks watermark, and if you have write acces can check last update, returns True if it checks out
def check_received_file(filename,logfilename=None):
	pass
	
def update_keyChain():
	pass
	
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
	encryptUserName=det(username)
	if os.path.exists('users/'+encUserName)==False:
		success = False
	else:
		secrets=open('users/'+encUserName+'/secret','r')
		cipher=secrets.read()
		secrets.close()
		waterMark=crypto.watermark()
		plaintext=clientDecrypt(password,cipher)
		if waterMark==plaintext.split('\n')[0]:
			privateKey=plaintext.split('\n')[2]
			publicKey=plaintext.split('\n')[1]
			user=username
			keyChain[user]=crypto.det(user)
			update_keyChain()
			savedLogs=open('users/'+encUserName+'/savedLogs','w')
			lastInput=pickle.load(savedLogs)
			savedLogs.close()
			currentPath=crypto.det(user)
			success=True
		else:
			success = False
	return success



### creates a user of the system for the client, logins them in, then 
def create_user(username,password):
	encUserName=crypto.det(username)
	asymKeys=crypto.create_asym_key_pair()
	privKey=asymKeys[1]
	pubKey=asymKeys[0]
	check = server_create_user(encUserName)
	if os.path.exists('users/'+encUserName)==False and check==True:
		os.mkdir('users/'+encUserName)
		secret=open('users/'+encUserName+'/secret','w')
		waterMark=crypto.watermark()
		secret.write(crypt.clientEncrypt(password,waterMark+'\n'+pubKey+'\n'+privKey))
		secret.close()
		savedLogs=open('users/'+encUserName+'/savedLogs','w')
		lastInput['None']="none"
		pickle.dump(lastInput,savedLogs)
		savedLogs.close()
		login(username,password)
		success=True
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
			fileSymKey=crypto.create_sym_key()
			difFileSymKey=crypto.create_sym_key()
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

		



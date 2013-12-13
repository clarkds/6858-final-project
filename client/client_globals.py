"""
Global variables for the client.
These are shared between functions and hold the state of the fnction
"""

err_msgs = "" 		#list of all error messages for logging

open_export_files = {}

public_keys = {} 	#key=det(user), val = public key of users

user = None 			#the user who is logged in 

encUser = None		#encrypted name of the logged in user

passw = None			#user's password

working_dir = None   #current working directory

secrets = {}			#stored information

loggedIn = True		#True or False. all functions throw an exception if not loggedIn

keys = {}			#key = enc_path, val = (file_RK, file_WK)

path_key = {}      	#mapping from path to encrypted path

enc_path_key = {}   #mapping from encrypted path to path

socket = None

open_files = {}		#key = handle of contents file, val = (path, enc_path, metadata_map, contents_path_on_disk, log_path_on_disk, path_to_old_file,mode)
	# metadata_map is for accessing each part of metadata

import string

class DirKey(dict):
	def __init__(self, *args):
		dict.__init__(self,args)

	def __getitem__(self,key):
		key_list = key.split('/')
		if key_list[-1].startswith('.meta_'):
			key_list[-1] = key_list[-1][len('.meta_'):]
		key = string.join(key_list, '/')
		val = dict.__getitem__(self,key)
		return val

	def __setitem__(self,key,val):
		key_list = key.split('/')
		if key_list[-1].startswith('.meta_'):
			key_list[-1] = key_list[-1][len('.meta_'):]
		key = string.join(key_list, '/')
		return dict.__setitem__(self,key,val)

import os

parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parentdir = parentdir + '/common'
os.sys.path.insert(0,parentdir) 

from sqlalchemy import *
from sqlalchemy.orm import *
from sqlalchemy.ext.declarative import *
import pbkdf2
import base64
import random
import string
import json

PublicKeyBase = declarative_base()
PermissionBase = declarative_base()
PasswordBase = declarative_base()
WriteKeyBase = declarative_base() 

def dbsetup(name, base):
	thisdir = os.path.dirname(os.path.abspath(__file__))
	dbdir   = os.path.join(thisdir, "db", name)
	if not os.path.exists(dbdir):
		os.makedirs(dbdir)

	dbfile  = os.path.join(dbdir, "%s.db" % name)
	engine  = create_engine('sqlite:///%s' % dbfile)
	base.metadata.create_all(engine)
	session = sessionmaker(bind=engine)
	return session()

class PublicKey(PublicKeyBase):
	__tablename__ = "publickey"
	username = Column(String(128), primary_key=True)
	key = Column(String(128))

class Permission(PermissionBase):
	__tablename__ = "permission"
	username = Column(String(128), primary_key=True)
	target = Column(String(128), primary_key=True)
	permission = Column(String(128), primary_key=True)

class Password(PasswordBase):
	__tablename__ = "password"
	username = Column(String(128), primary_key=True)
	password = Column(String(128))
	salt = Column(String(128))

class WriteKey(WriteKeyBase):
	__tablename__ = "WriteKeys"
	path = Column(String(128), primary_key = True)
	key = Column(String(128))

def publickey_setup():
	return dbsetup("publickey", PublicKeyBase)

def permission_setup():
	return dbsetup("permission", PermissionBase)

def password_setup():
	return dbsetup("password", PasswordBase)

def writekey_setup():
	return dbsetup("writekey", WriteKeyBase)

def add_write_key(path, key):
	wkey = WriteKey()
	wkey.path = path
	wkey.key = key
	db = writekey_setup()
	db.add(wkey)
	db.commit()

def update_write_key(path, key, new_key):
	if check_write_key(path, key):
		db = writekey_setup()
		existing_key = db.query(WriteKey).get(path)
		existing_key.key = key
		db.add(key)
		db.commit()
		return True
	else:
		return False

def check_write_key(path, key):
	db = writekey_setup()
	existing_key = db.query(WriteKey).get(path)
	if existing_key.key == key:
		return True
	else:
		return False	

def add_permission(username, target, permission):
	user = Permission()
	user.username = username
	user.permission = permission
	user.target = target
	db = permission_setup()
	db.add(user)
	db.commit()
	print "add_permission:", username, target, permission

def remove_permission(username, target, permission):
	db = permission_setup()
	permissions = db.query(Permission).filter(Permission.username == username, Permission.target == target, Permission.permission == permission).delete()
	db.commit()

def get_permissions_shared_by(username):
	db = permission_setup()
	permissions = db.query(Permission).filter(Permission.username == username).all()
	for i in range(len(permissions)):
		permissions[i] = (permissions[i].username, permissions[i].target, permissions[i].permission)
	return permissions

def get_permissions_shared_with(username):
	print "get_permissions_shared_with", username
	db = permission_setup()
	permissions = db.query(Permission).filter(Permission.target == username).all()
	print "get_permissions_shared_with : len permissions", len(permissions)
	for i in range(len(permissions)):
		permissions[i] = (permissions[i].username, permissions[i].target, permissions[i].permission)
	return permissions

def get_public_key(username):
	db = publickey_setup()
	user = db.query(PublicKey).get(username)
	return user.key

def get_all_public_keys():
	db = publickey_setup()
	table_contents = db.query(PublicKey).filter(PublicKey.username != None).all()
	users_and_perms = [(i.username, i.key) for i in table_contents]
	return users_and_perms 
		
def set_public_key(username, publickey):
	db = publickey_setup()
	user = db.query(PublicKey).get(username)
	user.key = publickey
	db.commit()

def check_password(username, password):
	db = password_setup()
	user = db.query(Password).get(username)
	if user:
		hash = json.loads(user.password)
		salt = json.loads(user.salt)
		if hash == pbkdf2.crypt(password, salt, 1000):
			return True
		else:
			return False
	return False

def generate_salt():
	_random_source = open("/dev/urandom", "rb")
	salt = _random_source.read(63)
	salt_ascii = base64.b64encode(salt)
	salt_ascii = salt_ascii.replace('+',random.choice(string.ascii_letters))
	salt_ascii = salt_ascii.encode('us-ascii')
	salt_ascii = salt_ascii.encode('utf-8')
	return salt_ascii

def add_user_to_databases(username, password, publickey):
	user = PublicKey()
	user.username = username
	user.key = publickey
	db = publickey_setup()
	db.add(user)
	db.commit()

	user = Password()
	salt = generate_salt()
	hash = pbkdf2.crypt(password,salt,1000)
	hash_json = json.dumps(hash)
	hash_uni = hash_json.decode('utf-8')
	salt_json = json.dumps(salt)
	user.username = username
	user.password = hash_uni
	user.salt = salt_json
	db = password_setup()
	db.add(user)
	db.commit()

def user_exists(username):
	db = password_setup()
	user = db.query(Password).get(username)
	if user:
		return True
	db = publickey_setup()
	user = db.query(PublicKey).get(username)
	if user:
		return True
	db = permission_setup()
	user = db.query(Permission).filter(Permission.username == username).first()
	if user:
		return True
	return False
		

import sys
if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "Usage: %s [init-person|init-transfer|init-cred]" % sys.argv[0]
		exit(1)

	cmd = sys.argv[1]
	if cmd == 'init-publickey':
		publickey_setup()
	elif cmd == 'init-permission':
		permission_setup()
	elif cmd == 'init-password':
		password_setup()
	elif cmd == 'init-writekey':
		writekey_setup()
	else:
		raise Exception("unknown command %s" % cmd)

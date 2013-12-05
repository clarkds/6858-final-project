from sqlalchemy import *
from sqlalchemy.orm import *
from sqlalchemy.ext.declarative import *
import os

PublicKeyBase = declarative_base()
PermissionsBase = declarative_base()
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

class Permissions(PermissionsBase):
	__tablename__ = "permissions"
	username = Column(String(128), primary_key=True)
	permissions = Column(String(128))

def publickey_setup():
	return dbsetup("publickey", PublicKeyBase)

def permissions_setup():
	return dbsetup("permissions", PermissionsBase)

def addPermission(username, permission):
	# TODO: Sanitize permission
	db = permissions_setup()
	user = db.query(Permissions).get(username)
	user.permissions = user.permissions + '/' + permission
	db.commit()

def getPermissions(username):
	db = permissions_setup()
	user = db.query(Permissions).get(username)
	return user.permissions

def getPublicKey(username):
	db = publickey_setup()
	user = db.query(PublicKey).get(username)
	return user.key

def setPublicKey(username, publickey):
	db = publickey_setup()
	user = db.query(PublicKey).get(username)
	user.publickey = publickey
	db.commit()

def addUserToDatabases(username):
	user = PublicKey()
	user.username = username
	user.publickey = ""
	db = publickey_setup()
	db.add(user)
	db.commit()

	user = Permissions()
	user.username = username
	user.permissions = ""
	db = permissions_setup()
	db.add(user)
	db.commit()

import sys
if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "Usage: %s [init-person|init-transfer|init-cred]" % sys.argv[0]
		exit(1)

	cmd = sys.argv[1]
	if cmd == 'init-publickey':
		publickey_setup()
	elif cmd == 'init-permissions':
		permissions_setup()
	else:
		raise Exception("unknown command %s" % cmd)

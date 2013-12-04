from sqlalchemy import *
from sqlalchemy.orm import *
from sqlalchemy.ext.declarative import *
import os

PublicKeyBase = declarative_base()
PermissionsBase = declarative_base()

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

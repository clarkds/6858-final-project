"""
Author: Clark Della Silva
Contact: clarkds@mit.edu

this module requires pyCrypto  -- apt-get install python-crypto

This module handles the encryption functions for the file system.
It implements the following:
Deterministic Encryption using AES in ECB mode
Symmetric Encyption using AES in CBC mode with a block size of 16, and a 16 byte random IV.  The key for AES-CBC is derived using PBKDF2.
Asymmetric Encrption using PKCS1_OAEP with 2048bit RSA keys.
Digital Signatures using  PKCS1_PSS using  2048bit RSA keys.
	The Digital signature is used in place of an HMAC as the checksum stored in the file.  
"""
import os
parentdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parendir = parentdir + '/common'
os.sys.path.insert(0,parentdir)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from common.pbkdf2 import PBKDF2
import base64, random, string
import binascii

AES_BS = AES.block_size
AES_IVS = AES.block_size
SYM_KEY_SIZE = 16 #bytes
RSA_KEY_SIZE = 2048 #bits

pad = lambda s: s + ((AES_BS - len(s) % AES_BS)) * chr(AES_BS - len(s) % AES_BS)
unpad = lambda s: s[0:-ord(s[-1])]

def bytesToStr(data):
	return binascii.hexlify(data)
	
def strToBytes(string):
	return binascii.unhexlify(string)

def hash(str):
	h = SHA512.new()
	h.update(str)
	ret = bytesToStr(h.hexdigest())
	#TODO: make this more secure by using a hash function that generates shorter hashes
	# instead of just substring-ing the hash
	if len(ret) > 64:
		return ret[0:64]
	else:
		return ret

def det(plaintext):
	pad_text = pad(plaintext)
	#TODO: used to be AES.new(key, AES.MOCDE_ECB) but key was undefined
	# is this correct?
	obj = AES.new('This is a key456', AES.MODE_ECB)
	ciphertext = obj.encrypt(pad_text)
	return bytesToStr(ciphertext)

def create_sym_key(master_Key, label, context, use_salt = True):
	#master_Key is derived from user password
	#label is filename or similar, context is username
	if use_salt:
		salt = '\00'.join([label, context, generate_salt()])
	else:
		salt = '\00'.join([label, context])
	sym_Key = PBKDF2(master_Key, salt).hexread(SYM_KEY_SIZE)
	sym_Key = bytesToStr(sym_Key)
	return (len(sym_Key), sym_Key)

def create_asym_key_pair():
	#return (900, '2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145417631444475696d465276637350766c4a446879570a3036336958764157364e714c7a554b46467759424f617668354a55566b56516c584a4e36584242536e6a6950395142506d707a736f74585878483472497337510a762b446d55715041325642525769774f7043536f547642566c4e5767366476714452666b467632315a3174366a773467596d45684e332b6c76503369625348520a4945724a75574748744e6e4564766b3348366c5771644a707a3768642b426a70707650614e3059577656464c74547538746c6858363138774b7a6b487a5941630a49353974697767443563426c71476b5562613545513141337551634b76645a6d636f47416a475872794a767551575741595641594534452b42634a6631476f6b0a4236456863326971784648784139617068753652546e504b396b3037497168546b7464394e7542494348507a707436756654635756484b417051504c2f612b510a41514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d', 3348, '2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949456f77494241414b43415145417631444475696d465276637350766c4a446879573036336958764157364e714c7a554b46467759424f617668354a55560a6b56516c584a4e36584242536e6a6950395142506d707a736f7458587848347249733751762b446d55715041325642525769774f7043536f547642566c4e57670a366476714452666b467632315a3174366a773467596d45684e332b6c76503369625348524945724a75574748744e6e4564766b3348366c5771644a707a3768640a2b426a70707650614e3059577656464c74547538746c6858363138774b7a6b487a59416349353974697767443563426c71476b5562613545513141337551634b0a76645a6d636f47416a475872794a767551575741595641594534452b42634a6631476f6b4236456863326971784648784139617068753652546e504b396b30370a497168546b7464394e7542494348507a707436756654635756484b417051504c2f612b514151494441514142416f49424151435251434e714371344b68417a4f0a76767374514a31756c7a30663855366a655a48637842314272716874666363696765482f465a444d4b5a676a6e367a715057316d694e626e507938574c6838450a4b767062456752424f65494561686b33704a67765376584f76356f64584c444e4d43686368542b3873782f554b4d6c3663475372696745695544596b3663414f0a7266386a3969484e543571364b596362307034723665686c48473855764d426f7a6d616a41674672692f6a396e6d43644c486577682f463569597035465855470a61632b4a38724c737331697a714f367a317831353436556a36786e70433433766f6278687931565a6b382f6c4d62616a554968774a3132344732553348304b720a55426e686e4d51506f4a68434d6142332b71717442684e2b6c7a58332b6a50315a325630436b52584a776233346239796230736d3943533243356830575655430a3357484f55626278416f4742414e4a67456f666d4d576f4c4d63553854534555696143706e676244776f48466b726b493957374642456f4a394c433168466b730a6e4753482f6867414a334879696d3441425a507a4c562f684c3372587274336a413554466c33326c6a4a2f4a31544873726e6f6e4d36764768463870334249370a387370525553346a484d70456e2b4c3648426c78394f6846584e522f6d4b47524f654658695a654f347677486765474d47356479534d3164416f4742414f6a4f0a674968626b54476e553855786d466e456d547730344442326a307242687936693454584a6949654f734531743457424b70622f66585356564e787351724872550a42686c2f3635536f583951386c687447457367476b5163514b41376d5a5a45684943316a6f435a61714c67562b65783857333674733671424978394f48494e490a736b4772576674496b464c30546d59596536424c6d636d544b61444f6730683636596436654c3731416f474141334b546d7971496b4d5a534d487447674535480a32787773664d766b65682f30775a65462f6953345a305932666c62624c6d4c757853373957514e586f6952705a4667587630377935576c5a5439674e413548650a307964527a6a7453544b5151484674576d4b5866304f62563849464e472f646a6954452f39564f5a2b793659754332464846326a74394b374c4c68536c674d390a515a59667152347356686b425a654c58364f6c30692f6b436759427967533843346c61316e324536656a772b327332727153346a61417a7562655635634b396f0a62796c7830794b7630723270534d3368593546437a586a2f484f4a59763351496b7278694c37614367784970632f7645326b583276574757676f65754c4362520a624644577a48787a6e6f75415832483547714a6c32494a5834576c7777513637386657642f494450374532724e5a754971656149474a4f2b2f685067554751510a4f4a4b7643514b426742485a4a4b3630687171656f54727a64494751727355752f734742786a6a4355325462356f685a744a72564f46676d707242306d4551450a454e564b556554795237622b3276676f57664d41646b3565736e7a6d2f6348524f5a734a7653546a574b6236636e71557541672f51394d4b6846634a76304a2b0a7a626f76312b577a7669576135746f3869504578454650516f6b6e6e614d70396a7848694b7a7078346263643576753653434a390a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d')
	
	key = RSA.generate(RSA_KEY_SIZE)
	priv_key = key.exportKey()
	pub_key = key.publickey().exportKey()
	pub_key = bytesToStr(pub_key)
	priv_key = bytesToStr(priv_key)
	return (len(pub_key), pub_key, len(priv_key), priv_key)
	
def sym_enc(key, plaintext):
	key = strToBytes(key)
	plaintext = pad(plaintext)
	iv = generate_iv()
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = (iv  + cipher.encrypt(plaintext))
	ciphertext = bytesToStr(ciphertext)
	return (len(ciphertext), ciphertext)

def sym_dec(key, ciphertext):
	key = strToBytes(key)
	ciphertext = strToBytes(ciphertext)
	iv = ciphertext[:AES_IVS]
	ciphertext = ciphertext[AES_IVS:]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(ciphertext))

def asym_enc_long(key, plaintext):
	len_pt = len(plaintext)/2
	plain_start = plaintext[:len_pt]
	plain_end = plaintext[len_pt:]
	(len_cs, cs) = asym_enc(key, plain_start)
	(len_ce, ce) = asym_enc(key, plain_end)
	return (len_cs + len_ce, cs + "What are the odds?" + ce)

def asym_enc(key, plaintext):
	key = strToBytes(key)
	pub_key = RSA.importKey(key)
	cipher = PKCS1_OAEP.new(pub_key)
	ciphertext = cipher.encrypt(plaintext)
	ciphertext = bytesToStr(ciphertext)
	return (len(ciphertext), ciphertext)

def asym_dec_long(key, ciphertext):
	cs = ciphertext.split("What are the odds?")[0]
	ce = ciphertext.split("What are the odds?")[1]
	plaintext =  asym_dec(key, cs) + asym_dec(key, ce)
	return plaintext
	

def asym_dec(key, ciphertext):
	key = strToBytes(key)
	ciphertext = strToBytes(ciphertext)
	priv_key = RSA.importKey(key)
	cipher = PKCS1_OAEP.new(priv_key)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext

def generate_dig_sig(priv_key, plaintext):
	priv_key = strToBytes(priv_key)
	#generates the digital signature for the contents of the encrypted file
	key = RSA.importKey(priv_key)
	h = SHA512.new()
	h.update(plaintext)
	signer = PKCS1_PSS.new(key)
	signature = signer.sign(h)
	signature = bytesToStr(signature)
	return (len(signature), signature)

def verify_dig_sig(pub_key, plaintext, signature):
	pub_key = strToBytes(pub_key)
	signature = strToBytes(signature)
	#verifies that the contents of the encrypted file match the digital signature
	key = RSA.importKey(pub_key)
	h = SHA512.new()
	h.update(plaintext)
	verifier = PKCS1_PSS.new(key)
	return verifier.verify(h,signature)

def generate_salt():
	_random_source = open("/dev/urandom", "rb")
	salt = _random_source.read(63)
	salt_ascii = base64.b64encode(salt)
	salt_ascii = salt_ascii.replace('+',random.choice(string.ascii_letters))
	return salt_ascii

def generate_iv():
	#generates a random 8 byte IV for each file.  need to store list of all iv's.
	_random_source = open("/dev/urandom", "rb")
	iv = _random_source.read(AES_IVS)
	return iv

	
def clientEncrypt(password,plaintext):
	pass #return cipher text, used to encrypt keys of user who logs into client
	
def clientDecrypt(password,ciphertext):
	pass #return plain text, used to decrypt keys of user who logs into client

def watermark():
	return "DEADBEEF" #generate watermark

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

def create_sym_key(master_Key, label, context):
    #master_Key is derived from user password
    #label is filename or similar, context is username
    salt = '\00'.join([label, context, generate_salt()])
    sym_Key = PBKDF2(master_Key, salt).hexread(SYM_KEY_SIZE)
    sym_Key = bytesToStr(sym_Key)
    return (len(sym_Key), sym_Key)

def create_asym_key_pair():
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

def asym_enc(key, plaintext):
    key = strToBytes(key)
    pub_key = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(pub_key)
    ciphertext = cipher.encrypt(plaintext)
    ciphertext = bytesToStr(ciphertext)
    return (len(ciphertext), ciphertext)


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
    return (len(signature), signature)

def verify_dig_sig(pub_key, plaintext, signature):
    pub_key = strToBytes(pub_key)
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

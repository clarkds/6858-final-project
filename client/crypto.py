def hash(str):
    pass

def det(plaintext):
    pass

def create_sym_key():
    pass # return tuple (size of key, key)

def create_asym_key_pair():
    pass # return tuple (size of pk, pk, size of sk, sk)

def sym_enc(key, plaintext):
    pass # return tuple (size of cipher, cipher)

def sym_dec(key, ciphertext):
    pass

def asym_enc(key, plaintext):
    pass # return tuple (size of cipher, cipher)

def asym_dec(key, ciphertext):
    pass
    
def clientEncrypt(password,plaintext):
	pass #return cipher text, used to encrypt keys of user who logs into client
	
def clientDecrypt(password,ciphertext):
	pass #return plain text, used to decrypt keys of user who logs into client

def watermark():
	pass #generate watermark

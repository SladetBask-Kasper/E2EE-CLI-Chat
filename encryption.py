# https://pypi.org/project/pycryptodome/
import string, random, base64, hashlib, os, gzip
from Crypto import Random
from Crypto.Cipher import AES
from settings import *

def printKey(key, title = ""):
	putTitle = ""
	if len(title) > 0:
		putTitle = f" ({title})"
	print(f"{putTitle} [{len(key)}] {key}.\r")

#
# Class originally taken from : https://stackoverflow.com/a/21928790
#
class AESCipher(object):

	# gets Random Alphanumeric String
	@staticmethod
	def genKey(length = 1024):
		if length <= 32:
			return ''.join(random.sample(string.ascii_letters + string.digits, length))
		else:
			rv = ""
			for i in range(int(length/32)):
				rv += ''.join(random.sample(string.ascii_letters + string.digits, 32))
			return rv

	def __init__(self, key = "None"):
		key = str(key)
		if (key == "None"):
			#key = self.genKey(32768) # 2048*16
			key = self.genKey(2048)
			#print("key: ", key)
		self.bs = AES.block_size
		self.key = hashlib.sha256(key.encode()).digest()
		self.hexkey = hashlib.sha256(key.encode()).hexdigest()
		self.keylen = len(key)

	def encrypt(self, raw):
		raw = self._pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw.encode()))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]
	def getKey(self):
		return "("+ str(self.keylen)+") " + self.hexkey

alwayCryptor = AESCipher(ALWAYS_USE_KEY)
def pack(msg):
	global alwayCryptor
	rv = alwayCryptor.encrypt(msg).decode()
	return rv
def unpack(double_enc_data):
	global alwayCryptor
	rv = alwayCryptor.decrypt(double_enc_data)#.encode()
	return rv
def cls():
	os.system('cls' if os.name=='nt' else 'clear')
# secure send
def ssend(socket, message, aes):
	data = gzip.compress(aes.encrypt(pack(message)))
	"""if len(str(data.decode())) >= 32:
		print("Compressing message")
		data = b'@gzip' + gzip.compress(data)"""
	socket.sendall(data)

def receivedata(socket, aes):
	data = None
	try:
		data = socket.recv(MAX_PACK_LEN)
	except ConnectionAbortedError:
		socket.close()
		exit()
	if not data:
		return None
	"""if data[:5] == b"@gzip":
		print("Decompressing message")
		data =  gzip.decompress(data[5:])"""
	return str(unpack(aes.decrypt(gzip.decompress(data))))

"""if __name__ == "__main__":
	data = "This is very secret."
	printKey(data, "Original msg")
	aes = AESCipher()
	printKey(aes.getKey(), "Key")
	enc_data = aes.encrypt(data)
	printKey(str(enc_data), "Encrypted data")
	#print (enc_data == enc_data.decode().encode())
	#printKey(str(base64.b64decode(enc_data)), "Decoded encrypted data")
	dec_data = aes.decrypt(enc_data)
	printKey('"'+str(dec_data)+'"', "Decrypted data")"""
if __name__ == "__main__":
	data = "This is very secret."
	#data = "a"*530 # double encrypted data is 1024 chars long
	#data = "a"*1110 # double encrypted data is 2048 chars long
	#printKey(data, "Original msg")
	aes = AESCipher()
	enc_data = aes.encrypt(data)
	printKey(str(enc_data.decode()), "Encrypted data")
	a2 = AESCipher()
	double_enc_data = a2.encrypt(enc_data.decode())
	printKey(str(double_enc_data.decode()), "Double Encrypted Data")

	dec1 = a2.decrypt(double_enc_data).encode()
	dec2 = aes.decrypt(dec1)


	#dec_data = aes.decrypt(enc_data)
	#printKey('"'+str(dec2)+'"', "Decrypted data")

"""
data = "This is very secret."

aes = AESCipher()
enc_data = aes.encrypt(data)

a2 = AESCipher()
double_enc_data = a2.encrypt(enc_data.decode())

dec1 = a2.decrypt(double_enc_data).encode()
dec2 = aes.decrypt(dec1) # done
"""

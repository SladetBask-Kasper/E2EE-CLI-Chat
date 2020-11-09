import string, random, base64, hashlib, os, gzip, socket, threading, pyDH
from Crypto import Random
from Crypto.Cipher import AES
from settings import *
from sys import argv
from urllib.parse import quote, unquote

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

	def encrypt(self, raw, urlQuote = False):
		if urlQuote:
			raw = quote(raw).replace("%20", " ")
		raw = self._pad(raw) # the replace is there to save a few bites.
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw.encode()))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return unquote(self._unpad(cipher.decrypt(enc[AES.block_size:])).decode())

	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]
	def getKey(self):
		return "("+ str(self.keylen)+") " + self.hexkey

#
# =========================================================================
#

alwayCryptor = AESCipher(ALWAYS_USE_KEY)
diffieAES = AESCipher(ALWAYS_SAME_KEY)
del ALWAYS_SAME_KEY
del ALWAYS_USE_KEY
def pack(msg):
	global alwayCryptor
	rv = alwayCryptor.encrypt(msg, urlQuote=True).decode()
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
	socket.sendall(data)

def receivedata(socket, aes):
	data = None
	try:
		data = socket.recv(MAX_PACK_LEN)
	except ConnectionAbortedError:
		#print("ConnectionAbortedError when receiving data")
		socket.close()
		exit()
	if not data:
		return None
	return str(unpack(aes.decrypt(gzip.decompress(data))))

# Diffie-Hellaman Key exchange
def difhel(sock):

	global diffieAES

	dh = pyDH.DiffieHellman() # Exchanger for Diffie-Hellman key exchange
	pubkey = str(dh.gen_public_key()) # Our public key for this conversation
	failLimit = 2
	sharedKey = ""
	data = ""

	print(" [*] Setting up keys...", end=" ")

	#sock.sendall(gzip.compress(diffieAES.encrypt(pack(pubkey))))
	ssend(sock, pubkey, diffieAES)
	fails = 0
	while True:
		try:
			data = receivedata(sock, diffieAES)
			if not data:
				sock.close()
				print("Failed key exchange")
				exit()
			# generate shared key with "data"
			sharedKey = dh.gen_shared_key(int(data))
			break
		except ValueError:
			if fails >= failLimit:
				print("Failed key exchange, unknown message: ", str(data))
				sock.close()
				exit()
			fails+=1
			continue

	print("Done!")
	return AESCipher(sharedKey)

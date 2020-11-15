import string, random, base64, hashlib, os, gzip, socket, threading, pyDH, rsa
from Crypto import Random
from Crypto.Cipher import AES
from settings import *
from sys import argv
from urllib.parse import quote, unquote


def generateRSAKeys():
	(pubkey, privkey) = rsa.newkeys(1024)
	f = open('keys/serv_priv.pem', 'wb')
	f.write(privkey.save_pkcs1())
	f.close()
	f = open('keys/serv_pub.pem', 'wb')
	f.write(pubkey.save_pkcs1())
	f.close()
	(pubkey, privkey) = rsa.newkeys(1024)
	f = open('keys/cli_priv.pem', 'wb')
	f.write(privkey.save_pkcs1())
	f.close()
	f = open('keys/cli_pub.pem', 'wb')
	f.write(pubkey.save_pkcs1())
	f.close()
def genkeys(): generateRSAKeys()
def readPriv(filename):
	with open(filename, mode='rb') as privatefile:
		keydata = privatefile.read()
		return rsa.PrivateKey.load_pkcs1(keydata)
def readPub(filename):
	with open(filename, mode='rb') as privatefile:
		keydata = privatefile.read()
		return rsa.PublicKey.load_pkcs1(keydata)
#print(readPub("keys/cli_pub.pem"))
#cli_pub = readPub("keys/cli_pub.pem")
#serv_pub = readPub("keys/serv_pub.pem")
use_priv = None
use_pub = None

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
		raw = self._pad(raw) # the replace is there to save a few bites.
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(raw.encode()))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode()

	def _pad(self, s: str):
		s = str(s)
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]
	def getKey(self):
		return "("+ str(self.keylen)+") " + self.hexkey

#
# =========================================================================
#

def useAsServer():
	global use_pub
	global use_priv

	use_priv = readPriv("keys/serv_priv.pem")
	use_pub = readPub("keys/cli_pub.pem")
def useAsClient():
	global use_pub
	global use_priv

	use_priv = readPriv("keys/cli_priv.pem")
	use_pub = readPub("keys/serv_pub.pem")

alwayCryptor = AESCipher(ALWAYS_USE_KEY)
diffieAES = AESCipher(ALWAYS_SAME_KEY)
del ALWAYS_SAME_KEY
del ALWAYS_USE_KEY
def pack(msg):
	global alwayCryptor

	# What to use for signiture?
	#>>> len(hashlib.md5(b'GeeksforGeeks').hexdigest())
	#32
	#>>> len(hashlib.sha1(b'GeeksforGeeks').hexdigest())
	#40
	#>>> len(hashlib.sha256(b'GeeksforGeeks').hexdigest())
	#64
	#>>> len(hashlib.sha512(b'GeeksforGeeks').hexdigest())
	#128
	# I don't want to use md5 or sha1 since i believe you can forge sig:s
	# with them but i also want the sig to be as small as possible and take
	# as little bandwidth as possible. It also has to be less than 117 bites
	# well since we're just using it to verify that the message hasn't gone
	# currupt i'll use md5 for bandwidth
	#sig = str(rsa.encrypt(hashlib.md5(rv).digest(), use_pub))[:-1][2:]# diry way to decode.
	msg = quote(msg).replace("%20", " ")
	sig = quote(str(rsa.encrypt(hashlib.md5(msg.encode()).digest(), use_pub))[:-1][2:])#.decode('latin-1')
	bruh = str(sig+'ENDSIG'+msg)
	print(bruh)
	rv = alwayCryptor.encrypt(bruh)
	return rv
def unpack(double_enc_data):
	global alwayCryptor
	data = alwayCryptor.decrypt(double_enc_data)
	sig, msg = data.split('ENDSIG')
	sig = unquote(sig).encode()
	msg = msg.encode()
	try:
		sig = rsa.decrypt(sig, use_priv)
	except:
		print(" [!] Invalid RSA Key. Connection compromised.")
		#exit() # the program should crash so idk why i'm not calling this exit.
	if not sig == hashlib.md5(msg).digest():
		print(" [!] Message might have been corrupted!")

	return unquote(msg)
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

	print(" [*] Setting up keys...", end=" ")

	dh = pyDH.DiffieHellman(16) # Exchanger for Diffie-Hellman key exchange
	pubkey = str(dh.gen_public_key()) # Our public key for this conversation
	failLimit = 2
	sharedKey = ""
	data = ""

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

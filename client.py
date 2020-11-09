# source : https://realpython.com/python-sockets/
import socket, threading, pyDH
from encryption import *
from sys import argv

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
sharedKey = ""
diffieAES = AESCipher(ALWAYS_SAME_KEY)
del ALWAYS_SAME_KEY

if len(argv) > 1:
	# This means arg was passed. Assuming its IP
	HOST = str(argv[1])

if len(argv) > 2:
	# this meanse two args was passed. Assuming it's port.
	try:
		PORT = int(argv[2])
	except:
		print("Invalid port as argv. " + str(PORT) + " is port.")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
connected = True
print(f"Connected to {HOST}:{PORT}!")
aes = None
# Diffie-Hellaman Key exchange
def difhel():
	global aes
	global diffieAES
	global s
	global sharedKey

	dh = pyDH.DiffieHellman() # Exchanger for Diffie-Hellman key exchange
	pubkey = str(dh.gen_public_key()) # Our public key for this conversation

	print(" [*] Setting up keys...")

	s.sendall(gzip.compress(diffieAES.encrypt(pack(pubkey))))
	while True:
		data = s.recv(MAX_PACK_LEN)
		if not data:
			s.close()
			print("Failed key exchange")
			exit()
		# generate shared key with "data"
		try:
			sharedKey = dh.gen_shared_key(int(unpack(diffieAES.decrypt(gzip.decompress(data)))))
			break
		except gzip.BadGzipFile:
			got = ""
			try:
				got = str(unpack(aes.decrypt(data)))
			except:
				got = str(data)
			if not got == "changekey":
				print("Failed key exchange, unknown message: ", got)
				s.close()
				exit()
			continue
	aes = AESCipher(sharedKey)
	#del diffieAES
	#print(" [*] Shared key", sharedKey)
difhel()

def listen():
	global s
	global connected

	inDiffie = False
	while connected:
		data = receivedata(s, aes)

		if not data:
			connected = False
			break
		if data == 'disconnect':
			safeExit()
		elif data == "changekey":
			print(" [*] Changing keys")
			ssend(s, data, aes)
			difhel()
		else:
			print("Server:", data)
def sender():
	global s
	global connected

	while connected:
		try :
			msg = str(input()).strip()
		except EOFError:
			safeExit()

		if msg == "":
			continue
		elif len(msg) > 530:
			print("ERROR: Your message was too big to send.")
			continue
		elif msg == "disconnect":
			safeExit()
		elif msg=="clear" or msg=="cls":
			cls()
		else:
			#s.sendall(aes.encrypt(pack(msg)))
			ssend(s, msg, aes)
t = threading.Thread(target=sender)
t.daemon = True

def safeExit():
	global s
	global connected
	#global t

	#t.kill() # thread will be closed upon exit
	connected = False
	try:
		#s.sendall(b'disconnect')
		ssend(ssend(s, "disconnect", aes))
	except:
		pass
	s.close()
	exit()

try:
	t.start()
	listen()
except:
	safeExit()
s.close()

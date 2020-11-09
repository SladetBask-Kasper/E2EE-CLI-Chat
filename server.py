# source : https://realpython.com/python-sockets/
import socket, threading, pyDH
from encryption import *
from sys import argv

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
sharedKey = ""
diffieAES = AESCipher(ALWAYS_SAME_KEY)
del ALWAYS_SAME_KEY

if len(argv) > 1:
	# this meanse arg was passed. Assuming it's port.
	try:
		PORT = int(argv[1])
	except:
		print("Invalid port as argv. " + str(PORT) + " is port.")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
conn, addr = s.accept()

connected = True
print(f'Connected by {addr[0]}:{addr[1]}!')

# Diffie-Hellaman Key exchange
def difhel():
	global aes
	global diffieAES
	global conn
	global sharedKey

	dh = pyDH.DiffieHellman() # Exchanger for Diffie-Hellman key exchange
	pubkey = str(dh.gen_public_key()) # Our public key for this conversation

	print(" [*] Setting up keys...")

	conn.sendall(gzip.compress(diffieAES.encrypt(pack(pubkey))))
	while True:
		data = conn.recv(MAX_PACK_LEN)
		if not data:
			conn.close()
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
				got = str(data.decode())
			if not got == "changekey":
				print("failed key exchange, unknown message: ", got)
				conn.close()
				s.close()
				exit()
			continue
	aes = AESCipher(sharedKey)
	#print(" [*] Shared key", sharedKey)# It's probably a bad idea to echo out the key used for encryption.
	#del diffieAES
difhel()

def sender():
	global conn
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
			ssend(conn, msg, aes)

t = threading.Thread(target=sender)
t.daemon = True

def safeExit():
	global conn
	global connected
	#global t

	#t.kill() # thread will be closed upon exit
	connected = False
	try:
		#conn.sendall(b'disconnect')
		ssend(conn, "disconnect", aes)
	except:
		pass
	conn.close()
	s.close()
	exit()

inDiffie = False
# listener
try:
	t.start()
	while connected:

		data = receivedata(conn, aes)

		if not data:
			connected = False
			break
		if data == 'disconnect':
			safeExit()
		elif data == "changekey":
			print(" [*] Changing keys")
			ssend(conn, data, aes)
			difhel()
		else:
			print("Client:", data)
except KeyboardInterrupt:
	safeExit()

conn.close()
s.close()

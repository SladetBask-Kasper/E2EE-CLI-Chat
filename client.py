# source : https://realpython.com/python-sockets/
from encryption import *

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

if len(argv) > 1:
	# This means arg was passed. Assuming its IP
	HOST = str(argv[1])

if len(argv) > 2:
	# this meanse two args was passed. Assuming it's port.
	try:
		PORT = int(argv[2])
	except:
		print("Invalid port as argv. " + str(PORT) + " is now the port.")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
connected = True
print(f"Connected to {HOST}:{PORT}!")

aes = difhel(s)

def listen():
	global s
	global connected
	global aes

	inDiffie = False
	while connected:
		data = receivedata(s, aes)

		if not data:
			connected = False
			break
		if data == 'disconnect':
			safeExit()
		elif data == "changekey":
			ssend(s, data, aes)
			aes = difhel(s)
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

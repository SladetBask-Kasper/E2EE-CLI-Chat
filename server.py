# source : https://realpython.com/python-sockets/
from encryption import *

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

if len(argv) > 1:
	# this meanse arg was passed. Assuming it's port.
	try:
		PORT = int(argv[1])
	except:
		print("Invalid port as argv. " + str(PORT) + " is now the port.")

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((HOST, PORT))
	s.listen()
	conn, addr = s.accept()
except:
	print("Failed to bind and listen to port.")
	exit()

connected = True
print(f'Connected by {addr[0]}:{addr[1]}!')

aes = difhel(conn)

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
	global s

	connected = False
	try:
		ssend(conn, "disconnect", aes)
	except:
		pass
	conn.close()
	s.close()
	exit()

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
			ssend(conn, data, aes)
			aes = difhel(conn)
		else:
			print("Client:", data)
except KeyboardInterrupt:
	safeExit()

conn.close()
s.close()

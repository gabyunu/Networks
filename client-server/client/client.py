import socket

HOST = '18.221.174.49'
PORT = 12345

s = socket.socket()
s.connect((HOST, PORT))

data = s.recv(1024)
print("Received:", data.decode())

s.close()

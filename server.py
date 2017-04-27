### __author__ == Shubham Bhardwaj

# libraries
import socket
import sys
from thread import *
import dicom
import pylab
import array
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pyblake2 import blake2b
import random


# init cipher and random number
backend = default_backend()
key = 'JA\xd6\xbbR\xc3Ur1\x00X\xf3\xfd\xbb\x9b\xaei;\x0f\xdbhsh\x0f\xb7\xb4\xfd\x1cI\xc9\xb2\xae'
iv = '\xb7*i\xbd\xc3\xd5f\x18\x81\xa9\xf8\x1ev\x9a\xa1M'
secret_key = 'secret key'
'''
key = os.urandom(32)
iv = os.urandom(16)
'''
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
decryptor = cipher.decryptor()

host = ''
port = 5555

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.bind((host, port))
except socket.error as e:
	print(str(e))
print('waiting for a connection...')
s.listen(5)

def check_hash_msg(msg):
	# returns a hash for the message
	h = blake2b(key=secret_key)
	h.update(msg)
	auth_code = h.hexdigest()
	return auth_code


def threaded_client(conn):
	conn.send(str.encode("Welcome, send your info"))
	
	while True:
		data = conn.recv(131072+128)
		if not data:
			break
		#data = str.decode(data)
		print '\nRecieved message ... OK'
		print 'len of data recieved is',len(data)
		hash_value_recv = data[-128:]
		print 'hash_value recieved is',hash_value_recv,'\n' 
		image_data = data[:-128]
		if hash_value_recv!=check_hash_msg(image_data):
			raise Exception("Bad hash value - discarding data")
		conn.sendall(str.encode('data recieved from server'))
	decryptor = cipher.decryptor()
	new_byte_array = decryptor.update(image_data) + decryptor.finalize()	
	#print new_byte_array
	ds = dicom.read_file("brain_016.dcm")	
	ds.PixelData = new_byte_array
	ds.save_as("new_file_final.dcm")
	conn.close()

while True:
	conn, addr = s.accept()
	print ("connected to "+addr[0]+":"+str(addr[1]))
	start_new_thread(threaded_client,(conn,))

#318
# client will send hash you have to take the message again and generate the hash
# and equate both of them to check their integrity

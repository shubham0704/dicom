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
'''
key = os.urandom(32)
iv = os.urandom(16)
'''
key = 'JA\xd6\xbbR\xc3Ur1\x00X\xf3\xfd\xbb\x9b\xaei;\x0f\xdbhsh\x0f\xb7\xb4\xfd\x1cI\xc9\xb2\xae'
iv = '\xb7*i\xbd\xc3\xd5f\x18\x81\xa9\xf8\x1ev\x9a\xa1M'
secret_key = 'secret key'
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()
random.seed(7)
rng = random.Random(42)


def generate_hash(msg):
	# returns a hash for the message
	h = blake2b(key=secret_key)
	h.update(msg)
	auth_code = h.hexdigest()
	print 'generated hash is',auth_code
	return auth_code



def encrypt(ds):
	# encrypt using AES cipher
	hex_vals = ds.PixelData
	byte_array = array.array('B',hex_vals)
	byte_array = "".join(map(chr,byte_array))
	enc_img = encryptor.update(byte_array) + encryptor.finalize()
	return enc_img

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = "localhost"
port = 5555
server_ip = "127.0.0.1:5555"

s.connect((server,port))
result = s.recv(4096)

while len(result)>0:
	ds = dicom.read_file("images/brain_001.dcm")
	enc_img = encrypt(ds)
	hash_val = generate_hash(enc_img)
	print len(hash_val), 'len of image data is',len(enc_img)
	
	s.sendall((enc_img+hash_val))
	result = s.recv(1024)
	print result
	break

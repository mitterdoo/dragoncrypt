'''
Python wrapper module for Dragoncrypt C library
'''

from ctypes import CDLL, c_int, c_char_p, c_ulonglong, byref
from secrets import token_bytes
import time, os, os.path

class ValidityException(Exception): pass

if os.name == 'nt':
	drgc = CDLL("dragoncrypt.dll")
else:
	drgc = CDLL(os.path.join(os.getcwd(), 'dragoncrypt.so'))
KEY_SIZE = c_int.in_dll(drgc, 'dragoncryptKeySize').value
def encrypt(input: bytes, key: int, iv_size: int) -> bytes:
	'''
	Encrypts the byte array `input` with the provided `key`, prepending the message with an initialization vector with `iv_size` random bytes.
	`iv_size` must be the same when decrypting, to read back the data properly.
	'''
	size = len(input)
	input_p = c_char_p(input)

	iv = token_bytes(iv_size)
	iv_ptr = c_char_p(iv)

	output = bytes(size + KEY_SIZE + iv_size)
	output_p = c_char_p(output)

	drgc.sencrypt(input_p, output_p, c_ulonglong(key), size, iv_ptr, iv_size)
	return output
	
def decrypt(input: bytes, key: int, iv_size: int):
	'''
	Decrypts the byte array `input` with the provided `key`, returning the decrypted byte array without the IV of `iv_size` bytes at the beginning.
	`iv_size` must be the same as when the message was encrypted, to read back the data properly.

	If validity check fails, an ValidityException is raised.
	'''
	size = len(input)
	input_p = c_char_p(input)

	output = bytes(max(0,size - KEY_SIZE - iv_size))
	output_p = c_char_p(output)

	ret = drgc.sdecrypt(input_p, output_p, c_ulonglong(key), size, iv_size)
	if ret == 0:
		raise ValidityException()
	return output

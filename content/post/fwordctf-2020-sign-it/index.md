---
title: FwordCTF 2020 | Sign it!
subtitle: ECDSA nonce bias exploitation
date: 2020-09-10T16:32:40.283Z
draft: false
featured: false
tags:
  - Cryptography
  - ECDSA
  - Signatures
  - Private Key Recovery
  - Nonce
  - Biais
image:
  filename: signit-1.png
  focal_point: Smart
  preview_only: false
---
# Description
## 500 points (6 solves)
## nc signit.fword.wtf 1337
**Author:** `KOOLI`

# Overview

 ![](signit-1.png)
 
 Connecting to the provided nc service we can see we have two possibilities:
 1. See available commands:
  - ls
  - cat run.py
2. Execute command:
   - ls :
      - `flag.txt`
      - `run.py`
   - cat run.py
   
```python 
#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long
from binascii import hexlify, unhexlify
from random import randrange
from hashlib import sha1
import os
import ecdsa


class Ellip(object):
	def __init__(self):
		# NIST Curve P-192 for da speed:
		_p = 6277101735386680763835789423207666416083908700390324961279
		_r = 6277101735386680763835789423176059013767194773182842284081
		_b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
		_Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
		_Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
		curve_192 = ecdsa.ellipticcurve.CurveFp(_p, -3, _b, 1)
		generator_192 = ecdsa.ellipticcurve.PointJacobi(
		    curve_192, _Gx, _Gy, 1, _r, generator=True
		)
		g = generator_192
		n = g.order()
		secret = randrange(1, n)
		self.pubkey = ecdsa.ecdsa.Public_key(g, g * secret)
		self.privkey = ecdsa.ecdsa.Private_key(self.pubkey, secret)
		self.nonce = randrange(1, n)

	def ephemere_key(self):
		return self.nonce ^ randrange(1, 2**150)

	def sign(self, command):
		_k = self.ephemere_key()
		c_int = bytes_to_long(sha1(command.encode()).digest())
		signature = self.privkey.sign(c_int, _k)
		return hexlify(ecdsa.util.sigencode_der(signature.r, signature.s, self.pubkey.generator.order()))

	def valid_sig(self, command , signature):
		signature = unhexlify(signature)
		r , s = ecdsa.util.sigdecode_der(signature, self.pubkey.generator.order())
		signature = ecdsa.ecdsa.Signature(r, s)
		c_int = bytes_to_long(sha1(command.encode()).digest())
		if self.pubkey.verifies(c_int, signature):
			return True
		return False

	def execute_command(self, command, signature):
		if self.valid_sig(command, signature):
			print("\nOutput: ")
			print(os.system(command))
		else:
			print("\nIncorrect signature.")

	def available_commands(self):
		available = ['ls','cat run.py']
		print("   Command   |    Signature")
		for cmd in available:
			signature = self.sign(cmd)
			print (f'{cmd:12} | {signature.decode()}')


def menu():
	print ("\nMenu:")
	print ("\t[1-] See available commands.")
	print ("\t[2-] Execute command.")
	print ("\t[3-] Exit.\n")

def main():
	try:
		E = Ellip()
		while True:		
			menu()
			choice = int(input(">>> ").strip())
			if choice == 1:
				E.available_commands()
			elif choice == 2:
				cmd = input("Command: ").strip()
				signature = input("Signature: ").strip()
				E.execute_command(cmd , signature)
			else:
				exit()
	except Exception:
		print("\nAn Exception occured. What are you trying to do?")
		exit()
if __name__ == '__main__':
	main()
```

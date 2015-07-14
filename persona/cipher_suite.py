#!/usr/bin/env python
""" cipher_suite.py
        
    Paul A. Lambert 2015
"""
from hashlib import sha256
from cryptopy.ecc.curves import NIST_P256

class CipherSuite( object ):
    """ """
    def __init__(self): pass
    def hash(self): pass
    def aead_encrypt(self): pass
    def aead_decrypt(self): pass
    

class Suite_01( CipherSuite ):
    cipherSuiteId = 'S01'
    Group = NIST_P256
    hash = sha256
    encrypt = 
    
    

           
cs = Suite_01()
print cs.Group









#!/usr/bin/env python
""" cipher_suite.py
        
    Paul A. Lambert 2015
"""
from hashlib import sha256 as SHA256
from cryptopy.ecc.curves import NIST_P256
from cryptopy.cipher.aes_siv import AES_SIV

class CipherSuite( object ):
    """ """
    def __init__(self):
        # use class name as suite text name for any display
        self.cipher_suite_name = self.__class__.__name__
    
    def HashUaid( self, pubKeyValue ):
        """ Default calculation of a UAID using hash defined by Cipher Suite """
        hash = self.Hash.new()
        
        return uaidString
    

class Suite_01( CipherSuite ):
    """ A SuiteB compatible Cipher Suite using NIST P256 curve """
    cipher_suite_id   = 0x0101
    Group = NIST_P256
    Hash  = SHA256
    AeadCipher = AES_SIV
    
class Bitcoin_Suite( CipherSuite ):
    """ A CipherSUite compatible with Bitcoin """
    cipher_suite_id   = 0x0102
    Group = SECP_256k1
    Hash  = SHA256
    AeadCipher = AES_SIV
    
    








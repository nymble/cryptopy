#!/usr/bin/env python
""" test_aes_cmac.py

    Tests for AES CMAC from NIST 800-38B
    
    References:
        RFC 4493 - http://www.rfc-editor.org/rfc/rfc4493.txt
        NIST - http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
        
        
    test_aes_cmac.py(c) 2015 by Paul A. Lambert
        
    test_aes_cmac.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/cipher/test/test_aes_cmac.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.cipher.aes_cmac import aes_cmac, subkey

class TestVectorsNIST_SP_800_38B(unittest.TestCase):
    """ Test Vectors from NIST Special Publication 800-38B """
    
    def test_AES128_CMAC(self):
        """ FIPS 800-38B D.1 AES-128 """

        # For Examples 1 to 4 below, the block cipher is the
        # AES algorithm with the following 128 bit key: 
        key = '2b7e1516 28aed2a6 abf71588 09cf4f3c' 

        cmac_gen_test(
            test = 'NIST SP_800-38B D.1 AES-128 - Subkey Generation',
            key  = key,
            k1   = 'fbeed618 35713366 7c85e08f 7236a8de',
            k2   = 'f7ddac30 6ae266cc f90bc11e e46d513b')
                       
        cmac_mac_test(
            test = 'NIST SP_800-38B D.1 AES-128 - Example 1 MLen = 0',
            key  = key,
            m    = '',
            t    = 'bb1d6929 e9593728 7fa37d12 9b756746' )
    
        cmac_mac_test(
            test = 'NIST SP_800-38B D.1 AES-128 - Example 2 MLen = 128',
            key  = key,
            m    = '6bc1bee2 2e409f96 e93d7e11 7393172a',  
            t    = '070a16b4 6b4d4144 f79bdd9d d04a287c' )
        
        cmac_mac_test(
            test = 'NIST SP_800-38B D.1 AES-128 - Example 3 MLen = 320',
            key  = key,
            m  = '''6bc1bee2 2e409f96 e93d7e11 7393172a
                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                    30c81c46 a35ce411''',
            t    = 'dfa66747 de9ae630 30ca3261 1497c827' )
        
        cmac_mac_test(
            test = 'NIST SP_800-38B D.1 AES-128 - Example 4 MLen = 512',
            key  = key,
            m  = '''6bc1bee2 2e409f96 e93d7e11 7393172a
                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                    30c81c46 a35ce411 e5fbc119 1a0a52ef
                    f69f2445 df4f9b17 ad2b417b e66c3710''',
            t    = '51f0bebf 7e3b9d92 fc497417 79363cfe' )
           

    def test_AES192_CMAC(self):
        """ FIPS 800-38B D.2 AES-192 """
        
        key = '8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b'
        
        cmac_gen_test(
            test = 'NIST SP_800-38B D.2 AES-192 - Subkey Generation',
            key  = key,
            k1   = '448a5b1c 93514b27 3ee6439d d4daa296',
            k2   = '8914b639 26a2964e 7dcc873b a9b5452c')
        
        cmac_mac_test(
            test = 'NIST SP_800-38B D.2 AES-192 - Example 5 MLen = 0',
            key  = key,
            m    = '',
            t    = 'd17ddf46 adaacde5 31cac483 de7a9367' )
    
        cmac_mac_test(
            test = 'NIST SP_800-38B D.2 AES-192 - Example 6 MLen = 128',
            key  = key,
            m    = '6bc1bee2 2e409f96 e93d7e11 7393172a',
            t    = '9e99a7bf 31e71090 0662f65e 617c5184' )
    
        cmac_mac_test(
            test = 'NIST SP_800-38B D.2 AES-192 - Example 7 MLen = 320',
            key  = key,
            m  = '''6bc1bee2 2e409f96 e93d7e11 7393172a
                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                    30c81c46 a35ce411''',
            t    = '8a1de5be 2eb31aad 089a82e6 ee908b0e' )
        
        cmac_mac_test(
            test = 'NIST SP_800-38B D.2 AES-192 - Example 8 MLen = 512',
            key = key,
            m  = '''6bc1bee2 2e409f96 e93d7e11 7393172a
                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                    30c81c46 a35ce411 e5fbc119 1a0a52ef
                    f69f2445 df4f9b17 ad2b417b e66c3710''',
            t    = 'a1d5df0e ed790f79 4d775896 59f39a11' )
    
    def test_AES256_CMAC(self):
        """ FIPS 800-38B D.3 AES-256 """
        
        key = '''603deb10 15ca71be 2b73aef0 857d7781
                 1f352c07 3b6108d7 2d9810a3 0914dff4''' # for examples 9 to 12
        
        cmac_gen_test(
            test = 'NIST SP_800-38B D.3 AES-256 - Subkey Generation',
            key  = key,
            k1   = 'cad1ed03 299eedac 2e9a9980 8621502f',
            k2   = '95a3da06 533ddb58 5d353301 0c42a0d9')
                       
        cmac_mac_test(
            test = 'NIST SP_800-38B D.3 AES-256 - Example 9 MLen = 0',
            key  = key,
            m    = '',
            t    = '028962f6 1b7bf89e fc6b551f 4667d983' )
    
        cmac_mac_test(
            test = 'NIST SP_800-38B D.3 AES-256 - Example 10 MLen = 128',
            key  = key,
            m    = '6bc1bee2 2e409f96 e93d7e11 7393172a',
            t    = '28a7023f 452e8f82 bd4bf28d 8c37c35c' )
    
        cmac_mac_test(
            test = 'NIST SP_800-38B D.3 AES-256 - Example 11 MLen = 320',
            key  = key,
            m  = '''6bc1bee2 2e409f96 e93d7e11 7393172a
                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                    30c81c46 a35ce411 ''',
            t    = 'aaf3d8f1 de5640c2 32f5b169 b9c911e6' )
        
        cmac_mac_test(
            test = 'NIST SP_800-38B D.3 AES-256 - Example 12 MLen = 512',
            key  = key,
            m  = '''6bc1bee2 2e409f96 e93d7e11 7393172a
                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                    30c81c46 a35ce411 e5fbc119 1a0a52ef
                    f69f2445 df4f9b17 ad2b417b e66c3710''',
            t    = 'e1992190 549f6ed5 696a2c05 6c315410' )

    
def cmac_gen_test(test, key, k1='', k2=''):
    """ NIST test of subkey generation of k1 and k2 from key """
    key = decode_vector( key )  # key in string of hex
    k1_known  = decode_vector( k1 )
    k2_known  = decode_vector( k2 )    
    k1, k2 = subkey( key)   # test this fucntion
                            # against known results       
    assert k1 == k1_known 
    assert k2 == k2_known 
        
def cmac_mac_test(test='',key='', m='', t=''):
    """ NIST test vector validation of CMAC output """
    key = decode_vector( key )
    m = decode_vector( m )
    t = decode_vector( t )
    cm = aes_cmac(key, m)
    assert t == cm

def decode_vector(string):
    """ Covert readable test vector string to an octet string """
    return ''.join( string.split() ).decode('hex')
    
if __name__ == '__main__':
    unittest.main()

    


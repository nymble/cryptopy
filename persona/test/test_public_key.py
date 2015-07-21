#!/usr/bin/env python
""" test_public_key.py

    Copyright (c) 2015 by Paul A. Lambert   
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.persona.public_key import PublicKey, PublicKeyPair
from cryptopy.persona.cipher_suite import Suite_01

    
class TestPublicKey(unittest.TestCase):
    """  """
    def test_basic_pk(self):
        """ Basic unit test of a PublicKey Pair """
        cipherSuite = Suite_01()
        curve = cipherSuite.Group()
        G = curve.generator()
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        point = d * G # example point from NSA tests
        self.assertTrue ( curve.on_curve(point) )
      
        pubKey = PublicKey( cipherSuite, point )
        
        self.assertTrue( len(pubKey.uaid)==16 )
        

   
        
class TestPublicKeyPair(unittest.TestCase):
    """  """
    def test_basic(self):
        """ Basic unit test of a PublicKey Pair """
        cipherSuite = Suite_01()
        keyPair1 = PublicKeyPair( cipherSuite )
        keyPair2 = PublicKeyPair( cipherSuite )



if __name__ == '__main__':
    unittest.main()

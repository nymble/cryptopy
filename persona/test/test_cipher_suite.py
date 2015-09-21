#!/usr/bin/env python
""" test_cipher_suite.py

    Copyright (c) 2015 by Paul A. Lambert   
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.persona.cipher_suite import Suite_01
from cryptopy.persona.public_key import PublicKeyPair
    

class TestSuite01(unittest.TestCase):
    """  """
    def test_basic(self):
        """ """
        cipherSuite = Suite_01()
        keyPair1 = PublicKeyPair( cipherSuite )
        keyPair2 = PublicKeyPair( cipherSuite )

        
    def test_02(self):
        """ """
        assert True


class Test_CipherSuite(unittest.TestCase):
    """ Test cipher suite object class """
    def test_CipherSuite_object(self):
        """  """
        # base class
        c = CipherSuite()
        print c.name
        c = PMP01() # sub class of CipherSuite
        print 'name:', c.name
        print 'id:', c.id
    
    def test_CipherSuite_sign(self):
        cipherSuite = PMP01()
        text = 'test of the cipher suite signature abstraction'
        print ' --- {0} ---'.format(text)
        signatureOctets = cipherSuite.sign(text)
        print 'cipher suite:', cipherSuite.name
        print 'signature:',signatureOctets
    
    def test_CipherSuite_public_key(self):
        pass



if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python
""" test_encoding.py

    
    test_encoding.py (c) 2013 by Paul A. Lambert

    test_encoding.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.cipher.encoding import b27encode, b27decode
from cryptopy.cipher.encoding import b85encode, b85decode
from cryptopy.cipher.encoding import b94encode, b94decode 
from cryptopy.cipher.encoding import int_to_string, string_to_int


class TestBase85(unittest.TestCase):
    """ """
    def test_RFC1924_Example(self):
        """ Test conformance of to RFC1924 definition of base85
             RFC1924 example of a IPv6 address ->  1080:0:0:0:8:800:200C:417A
        """
        rfc1924_example_number = 0x108000000000000000080800200c417a 
        rfc1924_example = int_to_string( rfc1924_example_number )
        rfc1924_example_encoded = '4)+k&C#VzJ4br>0wv%Yp'
        base85_encoded = b85encode(rfc1924_example)
        self.assertEqual( base85_encoded , rfc1924_example_encoded )
        self.assertEqual( b85decode(base85_encoded), rfc1924_example )
        

class TestEncodeDecode(unittest.TestCase):
    """ Quick test of each encoding routine for 0 to 999 """
    def test_basic(self):
        """  """
        for i in range(0,1000):
            test_octets = int_to_string(i)
            self.assertEqual( string_to_int(test_octets), i )
            self.assertEqual( b27decode(b27encode(test_octets)) , test_octets ) 
            self.assertEqual( b85decode(b85encode(test_octets)) , test_octets ) 
            self.assertEqual( b94decode(b94encode(test_octets)) , test_octets ) 

if __name__ == '__main__':
    unittest.main()


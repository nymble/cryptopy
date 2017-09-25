#!/usr/bin/env python
""" test_XXXXXXXXXXXXXXXXXXXXX.py
    Unit tests for ECC routines.
    
    Currently only testing SmallWeierstrassCurveFp
"""
import unittest

# cruft required to import correctly without full install
if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.ecc.ecc import SmallWeierstrassCurveFp
from cryptopy.ecc.curves import NIST_P192, NIST_P521, BrainPoolP256r1, smallWeierstrassCurves

     
 # was in test_ecc ....       
class TestPointUncompression(unittest.TestCase):
    """ Basic point decomprssion not using y-coord hint """
    def test_ned_point(self):
        x = 0x29d54ba5bd599041326f84ab894bc1c0a4d9a8474b4b9cf64640c71f8e3bbb34
        curve = BrainPoolP256r1()
        #Q = curve.uncompress(x) ##<-------------------------------------------------------------------------------
        self.assertEqual( c.n * G, IDENTITY )

if __name__ == '__main__':
    unittest.main()

    

    
 
#!/usr/bin/env python
""" test_curve25519.p7
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.ecc.curves import Curve25519


class TestCurve25519(unittest.TestCase):
    """ Curve25519 - a Edwards Curve """
    
    def test_C25519_DH(self):
        """ Test vectors taken from the NaCl distribution
            https://github.com/cryptosphere/rbnacl/blob/master/lib/rbnacl/test_vectors.rb
        """
        c = Curve25519()
        d_a = 0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
        Q_a = 0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
        d_b = 0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
        Q_b = 0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
        Sab = 0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
        
    def test_C25519_DH(self):
        """ draft-josefsson-tls-curve25519-02 """
        c = Curve25519()
        g = c.generator()
        d_A = 0x5AC99F33632E5A768DE7E81BF854C27C46E3FBF2ABBACD29EC4AFF517369C660
        d_B = 0x47DC3D214174820E1154B49BC6CDB2ABD45EE95817055D255AA35831B70D3260
        Qa = d_A*g
        x_A = 0x057E23EA9F1CBE8A27168F6E696A791DE61DD3AF7ACD4EEACC6E7BA514FDA863
        x_B = 0x6EB89DA91989AE37C7EAC7618D9E5C4951DBA1D73C285AE1CD26A855020EEF04
        x_S = 0x61450CD98E36016B58776A897A9F0AEF738B99F09468B8D6B8511184D53494AB
        assert 0==1 # this routine is not complete


if __name__ == '__main__':
    unittest.main()

    

    
 
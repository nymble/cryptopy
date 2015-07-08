#!/usr/bin/env python
""" test_curve_generation.py

    Paul A. Lambert 2015
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    from curve_generation import MontgomeryFromEdwards, MontgomeryFromTwistedEdwards
    from curves import Ed25519, MS384e1
else:
    
    from ..curve_generation import MontgomeryFromEdwards, MontgomeryFromTwistedEdwards
    from ..curves import Ed25519, MS384e1


class TestMontgomeryFromEdwards(unittest.TestCase):

    def test_Ed25519_to_Montgomery(self):
        curve = MontgomeryFromEdwards( Ed25519() )
        
        # test generator point and order
        G = curve.generator()    # generator point on curve
        n = curve.n              # order of curve
        self.assertTrue(   n*G == IDENTITY   )
        
    def test_MS384e1_to_Montgomery(self):
        curve = MontgomeryFromTwistedEdwards( MS384e1() )
        
        # test generator point and order
        G = curve.generator()    # generator point on curve
        n = curve.n              # order of curve
        self.assertTrue(   n*G == IDENTITY   )   


if __name__ == '__main__':
    unittest.main()


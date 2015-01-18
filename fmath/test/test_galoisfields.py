#!/usr/bin/env python
""" test_galoisfields.py
    Unit tests for overloading of: +, -, /, ^ for modular math on GF(p)
    
    Copyright Paul A. Lambert 2015
"""
import unittest
from galoisfield import GF
from random import randrange

class TestGaloisFIeld(unittest.TestCase):
    def test_add_sub_neg(self):       
        gfp = GF(11)
        x = gfp(1)
        y = gfp(8)
        self.assertTrue( y-x == -(x-y) )
        self.assertTrue( y+3 == gfp(0) )
        self.assertTrue( 3+y == gfp(0) )
        self.assertTrue( y-3 == -(3-y) )
    
    def test_mult(self):
        gfp = GF(11)
        x = gfp(7)
        y = gfp(8)
        self.assertTrue( x*y == x*8 )
        self.assertTrue( x*y == 7*y )
        
    def test_inversion(self):
        gfp = GF(11)
        for i in range(1, gfp.p):
            self.assertTrue( int(gfp(i) * gfp.inverse(i)) == 1)
            a = gfp(7)/gfp(i)
            b = 7/gfp(i)
            c = gfp(7)/i
            self.assertTrue( a == b)
            self.assertTrue( a == c)

    def test_exp(self):
        """ the '^' is overloaded to support x^2 as exponentiation """
        gfp = GF(11)
        x = gfp(4)
        z = 2^x
        y = gfp(2**4)
        self.assertTrue( x^2 == gfp(int(x)**2) )
        self.assertTrue( 2^x == gfp(int(2)**int(x)) )

    def test_misc(self):
        gfp = GF(2**255 - 19)
        x = gfp(0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)
        a24 = gfp(486662-2) / gfp(4)
        self.assertTrue( int(a24) == 121665)
        p = 2**255 - 19
        gfp = GF(p)
        for i in range(100):
            x = randrange(p)
            invx = 1/gfp(x)
            self.assertTrue( x*invx == gfp(1) )
        
if __name__ == '__main__':
    unittest.main()


    

    
 
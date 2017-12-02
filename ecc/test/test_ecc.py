#!/usr/bin/env python
""" test_ecc.py
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

class SimpleCurve( SmallWeierstrassCurveFp ):
    """ Simple test curve y**2 == x**2+x**2+1 mod 23"""
    p = 23
    a = 1
    b = 1
    n = 7
    

class TestEllipticCurveFp(unittest.TestCase):
    """ Extended from Peter Pearson's ecc package
        Test basic SmallWeierstrassCurveFp math from X9.62 tests
    """
    def test_simple(self):       
        c = SimpleCurve()
        IDENTITY = c.IDENTITY
        # basic operations
        g = c.point(3,10)  # make a point
        l = c.point(9,7)
        m = c.point(17,20)
        self.assertEqual( m, g + l) # addition m = g + l
        
        g_inv = -g  # point inversion
        # self.assertEqual( g + g_inv, IDENTITY ) #  inversion
        self.assertEqual( g - g , IDENTITY )    # subraction of inverse
        self.assertEqual( l, m - g)             # l = m - g
        self.assertEqual( g, m - l)             # g = m - l
        d = c.point(7,12)
        self.assertEqual( g.double(), d )
        self.assertEqual( g + g, d )
        self.assertEqual( 2*g, d)
        self.assertEqual( g*2, d)
        
    def test_x962_1(self):
        c = SimpleCurve()
        IDENTITY = c.identity()
        g = c.point(13, 7)
        check = IDENTITY
        for i in range( 7 + 1 ):
            p = ( i % 7 ) * g
            self.assertEqual( p, check)
            check = check + g

    def test_x962_2(self):
        """ Samples from X9.62 using NIST Curve P-192 """
        c = NIST_P192()
        p192 = c.point(c.xG, c.yG)
        d = 651056770906015076056810763456358567190100156695615665659L
        Q = d * p192
        self.assertEqual( Q.x, 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5L )
        #
        k = 6140507067065001063065065565667405560006161556565665656654L
        R = k * p192
        self.assertEqual( R.x, 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEADL )
        self.assertEqual( R.y, 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835L )
        #
        u1 = 2563697409189434185194736134579731015366492496392189760599L
        u2 = 6266643813348617967186477710235785849136406323338782220568L
        temp = u1 * p192 + u2 * Q
        self.assertEqual( temp.x, 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEADL )
        self.assertEqual( temp.y, 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835L )
        
    
class TestAllCurves(unittest.TestCase):
    """ Basic validation of Curve generators """
    def test_G_times_n(self):
        for Curve in smallWeierstrassCurves: # now may work for Edwards 
            c = Curve()
            IDENTITY = c.identity()
            print c.curveId, c.oid
            G = c.generator()
            self.assertEqual( c.n * G, IDENTITY )

if __name__ == '__main__':
    unittest.main()

    

    
 
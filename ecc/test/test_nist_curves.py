#!/usr/bin/env python
""" test_nist_curves.py

    
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/<this file>
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    

from cryptopy.ecc.curves import NIST_P192, NIST_P256, NIST_P521
       
class TestNistCurves(unittest.TestCase):
    """ Examples from
       'Mathematical routines for the NIST prime elliptic curves'
        April 05, 2010        
    """
    def test_NIST_P192(self):
        """ 4.1 Curve P-192
            4.1.2 Example calculations
        """
        c = NIST_P192()
        # S
        xS = 0xd458e7d127ae671b0c330266d246769353a012073e97acf8
        yS = 0x325930500d851f336bddc050cf7fb11b5673a1645086df3b
        S = c.point(xS,yS)
        # T
        xT = 0xf22c4395213e9ebe67ddecdd87fdbd01be16fb059b9753a4
        yT = 0x264424096af2b3597796db48f8dfb41fa9cecc97691a9c79
        T = c.point(xT,yT)
        
        # Full add R = S + T:
        xR = 0x48e1e4096b9b8e5ca9d0f1f077b8abf58e843894de4d0290
        yR = 0x408fa77c797cd7dbfb16aa48a3648d3d63c94117d7b6aa4b
        R = c.point(xR,yR)
        self.assertEqual( R, S + T )
        
        # Full subtract R = S - T:
        xR = 0xfc9683cc5abfb4fe0cc8cc3bc9f61eabc4688f11e9f64a2e
        yR = 0x093e31d00fb78269732b1bd2a73c23cdd31745d0523d816b
        R = c.point(xR,yR)
        self.assertEqual( R, S - T )
        
        # Double R = 2*S:        
        xR = 0x30c5bc6b8c7da25354b373dc14dd8a0eba42d25a3f6e6962
        yR = 0x0dde14bc4249a721c407aedbf011e2ddbbcb2968c9d889cf
        R = c.point(xR,yR)
        self.assertEqual( R, 2*S )
        self.assertEqual( R, S*2 )
        
        # Scalar multiply R = dS:
        d = 0xa78a236d60baec0c5dd41b33a542463a8255391af64c74ee
        xR = 0x1faee4205a4f669d2d0a8f25e3bcec9a62a6952965bf6d31
        yR = 0x5ff2cdfa508a2581892367087c696f179e7a4d7e8260fb06
        R = c.point(xR,yR)
        self.assertEqual( R, d*S )
        
        # Joint scalar multiply R = dS + eT (d as above):
        e = 0xc4be3d53ec3089e71e4de8ceab7cce889bc393cd85b972bc
        xR = 0x019f64eed8fa9b72b7dfea82c17c9bfa60ecb9e1778b5bde
        yR = 0x16590c5fcd8655fa4ced33fb800e2a7e3c61f35d83503644
        R = c.point(xR,yR)
        self.assertEqual( R, d*S  + e*T )

    def test_NIST_P256(self):
        """ 4.3 Curve P-256
            4.3.2 Example calculations
            We give the results of basic calculations on a pair of
            points S and T using affine coordinates. S has coordinates:
        """       
        curve = NIST_P256()
        xS = 0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9
        yS = 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256
        s = curve.point(xS,yS)
        # and T has coordinates:
        xT = 0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b
        yT = 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316
        t = curve.point(xT,yT)

    def test_NIST_P521(self):
        """ 4.5 Curve P-521
            4.5.2 Example calculations
        """
        p521 = NIST_P521()
        xS = 0x000001d5c693f66c08ed03ad0f031f937443458f601fd098d3d0227b4bf62873af50740b0bb84aa157fc847bcf8dc16a8b2b8bfd8e2d0a7d39af04b089930ef6dad5c1b4
        yS = 0x00000144b7770963c63a39248865ff36b074151eac33549b224af5c8664c54012b818ed037b2b7c1a63ac89ebaa11e07db89fcee5b556e49764ee3fa66ea7ae61ac01823
        s = p521.point(xS,yS)
        xT = 0x000000f411f2ac2eb971a267b80297ba67c322dba4bb21cec8b70073bf88fc1ca5fde3ba09e5df6d39acb2c0762c03d7bc224a3e197feaf760d6324006fe3be9a548c7d5
        yT = 0x000001fdf842769c707c93c630df6d02eff399a06f1b36fb9684f0b373ed064889629abb92b1ae328fdb45534268384943f0e9222afe03259b32274d35d1b9584c65e305
        t = p521.point(xT,yT)
        
        # Full add R = S + T :
        xR = 0x000001264ae115ba9cbc2ee56e6f0059e24b52c8046321602c59a339cfb757c89a59c358a9a8e1f86d384b3f3b255ea3f73670c6dc9f45d46b6a196dc37bbe0f6b2dd9e9
        yR = 0x00000062a9c72b8f9f88a271690bfa017a6466c31b9cadc2fc544744aeb817072349cfddc5ad0e81b03f1897bd9c8c6efbdf68237dc3bb00445979fb373b20c9a967ac55
        r = p521.point(xR,yR)
        self.assertEqual( r, s+t )
        
        # Full subtract R = S - T :
        xR = 0x000001292cb58b1795ba477063fef7cd22e42c20f57ae94ceaad86e0d21ff22918b0dd3b076d63be253de24bc20c6da290fa54d83771a225deecf9149f79a8e614c3c4cd
        yR = 0x000001695e3821e72c7cacaadcf62909cd83463a21c6d03393c527c643b36239c46af117ab7c7ad19a4c8cf0ae95ed51729885461aa2ce2700a6365bca3733d2920b2267
        r = p521.point(xR,yR)
        self.assertEqual( r, s - t )
        
        # Double R = 2*S:
        xR = 0x0000012879442f2450c119e7119a5f738be1f1eba9e9d7c6cf41b325d9ce6d643106e9d61124a91a96bcf201305a9dee55fa79136dc700831e54c3ca4ff2646bd3c36bc6
        yR = 0x0000019864a8b8855c2479cbefe375ae553e2393271ed36fadfc4494fc0583f6bd03598896f39854abeae5f9a6515a021e2c0eef139e71de610143f53382f4104dccb543
        r = p521.point(xR,yR)
        self.assertEqual( r, 2*s )
        
        # Scalar multiply R = dS:
        d =  0x000001eb7f81785c9629f136a7e8f8c674957109735554111a2a866fa5a166699419bfa9936c78b62653964df0d6da940a695c7294d41b2d6600de6dfcf0edcfc89fdcb1
        xR = 0x00000091b15d09d0ca0353f8f96b93cdb13497b0a4bb582ae9ebefa35eee61bf7b7d041b8ec34c6c00c0c0671c4ae063318fb75be87af4fe859608c95f0ab4774f8c95bb
        yR = 0x00000130f8f8b5e1abb4dd94f6baaf654a2d5810411e77b7423965e0c7fd79ec1ae563c207bd255ee9828eb7a03fed565240d2cc80ddd2cecbb2eb50f0951f75ad87977f
        r = p521.point(xR,yR)
        self.assertEqual( r, d*s )
        
        # Joint scalar multiply R = dS + eT (d as above):
        e =  0x00000137e6b73d38f153c3a7575615812608f2bab3229c92e21c0d1c83cfad9261dbb17bb77a63682000031b9122c2f0cdab2af72314be95254de4291a8f85f7c70412e3
        xR = 0x0000009d3802642b3bea152beb9e05fba247790f7fc168072d363340133402f2585588dc1385d40ebcb8552f8db02b23d687cae46185b27528adb1bf9729716e4eba653d
        yR = 0x0000000fe44344e79da6f49d87c1063744e5957d9ac0a505bafa8281c9ce9ff25ad53f8da084a2deb0923e46501de5797850c61b229023dd9cf7fc7f04cd35ebb026d89d
        r = p521.point(xR,yR)
        self.assertEqual( r, d*s + e*t )

if __name__ == '__main__':
    unittest.main()

    

    
 

#!/usr/bin/env python
"""
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/cipher/test/test_aes_cmac.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.ecc.ecc import SmallWeierstrassCurveFp
from cryptopy.ecc.curves import NIST_P192, NIST_P224, NIST_P256, NIST_P384, NIST_P521
from cryptopy.ecc.curves import BrainPoolP256r1, smallWeierstrassCurves
from cryptopy.ecc.curves import Curve3617, Curve25519


class SimpleCurve( SmallWeierstrassCurveFp ):
    """ Simple test curve y**2 == x**2+x**2+1 mod 23"""
    p = 23
    a = 1
    b = 1
    n = 7
    

class TestEllipticCurveFp(unittest.TestCase):
    """ Extended from Peter Pearson's ecc package
        Test basic SmallWeierstrassCurveFp math
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
 
       
class TestNistCurves(unittest.TestCase):
    """ Example calculations from:
           'Mathematical routines for the NIST prime elliptic curves'
            April 05, 2010
            https://www.nsa.gov/ia/_files/nist-routines.pdf
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

    def test_NIST_P224(self):
        """ 4.2 Curve P-224
            4.2.2 Example calculations
        """
        c = NIST_P224()
        #S
        xS = 0x6eca814ba59a930843dc814edd6c97da95518df3c6fdf16e9a10bb5b
        yS = 0xef4b497f0963bc8b6aec0ca0f259b89cd80994147e05dc6b64d7bf22
        S = c.point(xS,yS)
        # T
        xT = 0xb72b25aea5cb03fb88d7e842002969648e6ef23c5d39ac903826bd6d
        yT = 0xc42a8a4d34984f0b71b5b4091af7dceb33ea729c1a2dc8b434f10c34
        T = c.point(xT,yT)
        
        # Full add R = S + T:
        xR = 0x236f26d9e84c2f7d776b107bd478ee0a6d2bcfcaa2162afae8d2fd15
        yR = 0xe53cc0a7904ce6c3746f6a97471297a0b7d5cdf8d536ae25bb0fda70
        R = c.point(xR,yR)
        self.assertEqual( R, S + T )
        
        # Full subtract R = S - T:
        xR = 0xdb4112bcc8f34d4f0b36047bca1054f3615413852a7931335210b332
        yR = 0x90c6e8304da4813878c1540b2396f411facf787a520a0ffb55a8d961
        R = c.point(xR,yR)
        self.assertEqual( R, S - T )
        
        # Double R = 2*S:        
        xR = 0xa9c96f2117dee0f27ca56850ebb46efad8ee26852f165e29cb5cdfc7
        yR = 0xadf18c84cf77ced4d76d4930417d9579207840bf49bfbf5837dfdd7d
        R = c.point(xR,yR)
        self.assertEqual( R, 2*S )
        self.assertEqual( R, S*2 )
        
        # Scalar multiply R = dS:
        d = 0xa78ccc30eaca0fcc8e36b2dd6fbb03df06d37f52711e6363aaf1d73b
        xR = 0x96a7625e92a8d72bff1113abdb95777e736a14c6fdaacc392702bca4
        yR = 0x0f8e5702942a3c5e13cd2fd5801915258b43dfadc70d15dbada3ed10
        R = c.point(xR,yR)
        self.assertEqual( R, d*S )
        
        # Joint scalar multiply R = dS + eT (d as above):
        e = 0x54d549ffc08c96592519d73e71e8e0703fc8177fa88aa77a6ed35736
        xR = 0xdbfe2958c7b2cda1302a67ea3ffd94c918c5b350ab838d52e288c83e
        yR = 0x2f521b83ac3b0549ff4895abcc7f0c5a861aacb87acbc5b8147bb18b
        R = c.point(xR,yR)
        self.assertEqual( R, d*S  + e*T )
        
    def test_NIST_P256(self):
        """ 4.3 Curve P-256
            4.3.2 Example calculations
        """
        c = NIST_P256()
        #S
        xS = 0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9
        yS = 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256
        S = c.point(xS,yS)
        # T
        xT = 0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b
        yT = 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316
        T = c.point(xT,yT)
        
        # Full add R = S + T:
        xR = 0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e
        yR = 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264
        R = c.point(xR,yR)
        self.assertEqual( R, S + T )
        
        # Full subtract R = S - T:
        xR = 0xc09ce680b251bb1d2aad1dbf6129deab837419f8f1c73ea13e7dc64ad6be6021
        yR = 0x1a815bf700bd88336b2f9bad4edab1723414a022fdf6c3f4ce30675fb1975ef3
        R = c.point(xR,yR)
        self.assertEqual( R, S - T )
        
        # Double R = 2*S:        
        xR = 0x7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0
        yR = 0xfa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7
        R = c.point(xR,yR)
        self.assertEqual( R, 2*S )
        self.assertEqual( R, S*2 )
        
        # Scalar multiply R = dS:
        d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
        xR = 0x51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f
        yR = 0x75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5
        R = c.point(xR,yR)
        self.assertEqual( R, d*S )
        
        # Joint scalar multiply R = dS + eT (d as above):
        e = 0xd37f628ece72a462f0145cbefe3f0b355ee8332d37acdd83a358016aea029db7
        xR = 0xd867b4679221009234939221b8046245efcf58413daacbeff857b8588341f6b8
        yR = 0xf2504055c03cede12d22720dad69c745106b6607ec7e50dd35d54bd80f615275
        R = c.point(xR,yR)
        self.assertEqual( R, d*S  + e*T )
    
    def test_NIST_P384(self):
        """ 4.4 Curve P-384
            4.4.2 Example calculations
        """
        c = NIST_P384()
        # S
        xS = 0xfba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f92385dda82768ada415ebab4167459da98e62b1332d1e73cb0e
        yS = 0x5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45
        S = c.point(xS,yS)
        # T
        xT = 0xaacc05202e7fda6fc73d82f0a66220527da8117ee8f8330ead7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051
        yT = 0x84009a263fefba7c2c57cffa5db3634d286131afc0fca8d25afa22a7b5dce0d9470da89233cee178592f49b6fecb5092
        T = c.point(xT,yT)
        
        # Full add R = S + T:
        xR = 0x12dc5ce7acdfc5844d939f40b4df012e68f865b89c3213ba97090a247a2fc009075cf471cd2e85c489979b65ee0b5eed
        yR = 0x167312e58fe0c0afa248f2854e3cddcb557f983b3189b67f21eee01341e7e9fe67f6ee81b36988efa406945c8804a4b0
        R = c.point(xR,yR)
        self.assertEqual( R, S + T )
        
        # Full subtract R = S - T:
        xR = 0x6afdaf8da8b11c984cf177e551cee542cda4ac2f25cd522d0cd710f88059c6565aef78f6b5ed6cc05a6666def2a2fb59
        yR = 0x7bed0e158ae8cc70e847a60347ca1548c348decc6309f48b59bd5afc9a9b804e7f7876178cb5a7eb4f6940a9c73e8e5e
        R = c.point(xR,yR)
        self.assertEqual( R, S - T )
        
        # Double R = 2*S:        
        xR = 0x2a2111b1e0aa8b2fc5a1975516bc4d58017ff96b25e1bdff3c229d5fac3bacc319dcbec29f9478f42dee597b4641504c
        yR = 0xfa2e3d9dc84db8954ce8085ef28d7184fddfd1344b4d4797343af9b5f9d837520b450f726443e4114bd4e5bdb2f65ddd
        R = c.point(xR,yR)
        self.assertEqual( R, 2*S )
        self.assertEqual( R, S*2 )
        
        # Scalar multiply R = dS:
        d = 0xa4ebcae5a665983493ab3e626085a24c104311a761b5a8fdac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480
        xR = 0xe4f77e7ffeb7f0958910e3a680d677a477191df166160ff7ef6bb5261f791aa7b45e3e653d151b95dad3d93ca0290ef2
        yR = 0xac7dee41d8c5f4a7d5836960a773cfc1376289d3373f8cf7417b0c6207ac32e913856612fc9ff2e357eb2ee05cf9667f
        R = c.point(xR,yR)
        self.assertEqual( R, d*S )
        
        # Joint scalar multiply R = dS + eT (d as above):
        e = 0xafcf88119a3a76c87acbd6008e1349b29f4ba9aa0e12ce89bcfcae2180b38d81ab8cf15095301a182afbc6893e75385d
        xR = 0x917ea28bcd641741ae5d18c2f1bd917ba68d34f0f0577387dc81260462aea60e2417b8bdc5d954fc729d211db23a02dc
        yR = 0x1a29f7ce6d074654d77b40888c73e92546c8f16a5ff6bcbd307f758d4aee684beff26f6742f597e2585c86da908f7186
        R = c.point(xR,yR)
        self.assertEqual( R, d*S  + e*T )
        
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
        
        
class TestPointUncompression(unittest.TestCase):
    """ Basic point decomprssion not using y-coord hint """
    def test_ned_point(self):
        x = 0x29d54ba5bd599041326f84ab894bc1c0a4d9a8474b4b9cf64640c71f8e3bbb34
        curve = BrainPoolP256r1()
        Q = curve.uncompress(x)
           
    
class TestAllCurves(unittest.TestCase):
    """ Basic validation of Curve generators """
    def test_G_times_n(self):
        for Curve in smallWeierstrassCurves: # now may work for Edwards 
            c = Curve()
            IDENTITY = c.identity()
            print c.curveId, c.oid
            G = c.generator()
            self.assertEqual( c.n * G, IDENTITY )

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


if __name__ == '__main__':
    unittest.main()

    

    
 
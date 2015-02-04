""" curve25519.py
    
    SmallWeierstrassCurveFp               y**2 == x**3 + a*x + b
    KoblitzCurveFp                        y**2 == x**3       + b
    TwistedEdwardsCurveFp        a*x**2 + y**2 ==    1 + d*x**2*y**2 
    EdwardsCurveFp                 x**2 + y**2 == c*(1 + d*x**2*y**2) 
    MontgomeryCurveFp                     y**2 == x**3 + a*x**2 + x 
       
"""
from ellipticcurve import EllipticCurveFp

class MontgomeryCurveFp( EllipticCurveFp ):
    def contains_point(curve, point):
        x = point.x; y = point.y; a = curve.a; p = curve.p; x_sqrd = x*x
        
        return    (y*y) % p == (x*x_sqrd + a*x_sqrd + x) % p

    def add_points(curve, p1, p2):
        """ Montgomery elliptic curve point addition"""
        IDENTITY = curve.identity()
        if p2 == IDENTITY:
            return p1
        if p1 == IDENTITY:
            return p2
       
        x1 = p1.x; x2 = p2.x; y1 = p1.y; y2 = p2.y
        a = curve.a; p = curve.p; inv = curve.inverse

        if x1 == x2:
            if y1 == y2:
                return p1.double()
            else:
                assert y1 + y2 == 0
                return p1

        l = (y2-y1)*inv(x2-x1)        
        x3 = l**2 - a - x1 - x2
        y3 = l*(x1 - x3) - y1
        return curve.point(x3 % p, y3 % p)

    def negate(curve, p1):
        """ Negate a point """
        return curve.point(-p1.x % p, p1.y)

    def double_point(curve, point):
        """ Return a new point that is twice the old
        """
        x1 = point.x; y1 = point.y; a = curve.a; inv = curve.inverse
        p = curve.p
        
        l = (3*x1*x1 + 2*a*x1 + 1)*inv(2*y1)
        x3 = l*l - a - 2*x1
        y3 = l*(x1 - x3) - y1
        return curve.point(x3 % p, y3 % p)

    def scalar_multiple(curve, point, scalar):
        if scalar == 0:
            return curve.identity()
        q = curve.scalar_multiple(point, scalar/2)
        q = q + q
        if scalar & 1:
            q = q + point
        return q
   
    def identity(curve):
        """ The additive identity """
        return curve.point(0,-1)

    def montgomery_ladder(curve, scalar, point):
        """ Scalar multiplication on a Montgomery curve
        """
        x1 = point.x; a = curve.a; p = curve.p
        
        x2,z2,x3,z3 = 1, 0, point.x, 1
        for i in reversed(range(255)):
            bit = 1 & (scalar >> i)
            x2, x3 = cswap(x2, x3, bit)
            z2, z3 = cswap(z2, z3, bit)
            x3, z3 = ((x2*x3 - z2*z3)**2,  x1*(x2*z3 - z2*x3)**2)
            x2, z2 = ((x2**2 - z2**2)**2,  4*x2*z2*(x2**2 + a*x2*z2+z2**2))
            x2, x3 = cswap(x2, x3, bit)
            z2, z3 = cswap(z2, z3, bit)
        return ( x2*z2**(p-2) ) % p
        
    def montgomery_ladder2(curve, scalar, point):
        """
            1987 Montgomery "Speeding the Pollard and elliptic curve
            methods of factorization", page 261, fifth and sixth displays,
            plus common-subexpression elimination, plus assumption Z1=1.
        """
        x1 = point.x; a = curve.a; p = curve.p
        a24 = (a - 2) / 4   
        x_2, z_2, x_3, z_3 = 0, 1, x_1, 1
        for t in reversed(range(255)):
            s_t = 1 & (scalar >> t)
            (x_2, x_3) = cswap(x_2, x_3, s_t)
            (z_2, z_3) = cswap(z_2, z_3, s_t)
            A = x_2 + z_2
            AA = A**2
            B = x_2 - z_2
            BB = B**2
            E = AA - BB
            C = x_3 + z_3
            D = x_3 - z_3
            DA = D * A
            CB = C * B    
            x_3 = (DA + CB)**2   
            z_3 = x_1 * (DA - CB)**2  
            x_2 = AA * BB
            z_2 = E * (AA + a24 * E)   #BB?
            (x_2, x_3) = cswap (x_2, x_3, s_t)
            (z_2, z_3) = cswap (z_2, z_3, s_t)
        return (x_2 * (z_2**(p - 1))) % p


""" Edwards and Montgomery curves """
""" draft-irtf-cfrg-curves-01 """
   For the ~128-bit security level, the prime 2^255-19 is recommended
   for performance on a wide-range of architectures.  This prime is
   congruent to
    assert p % 4 == 1

    curveId = 'intermediate25519'
    strength = 126
    oid = None
    p = 2**255-19
    d = 121665
    n = 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
    h = 8

   In order to be compatible with widespread existing practice, the
   recommended curve is an isogeny of this curve.  An isogeny is a
   "renaming" of the points on the curve and thus cannot affect the
   security of the curve:

   p  2^255-19
   d  370957059346694393431380835087545651895421138798432190163887855330
      85940283555

   order  2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed

   cofactor  8



Langley, et al.          Expires August 1, 2015                 [Page 6]

 
Internet-Draft                  cfrgcurve                   January 2015


   X(P)  151122213495354007725011514095885315114540126930418572060461132
      83949847762202

   Y(P)  463168356949264781694283940034751631413079938662562256157830336
      03165251855960
      """

class Curve25519( MontgomeryCurveFp ):
    """ y**2 == x**3 + 486662*x**2 + x  mod 2**255-19 """
    curveId = 'curve25519'
    strength = 126
    oid = None
    p  = 2**255-19
    a = -1
    c  = 486662
    xG = 9
    yG = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
    r  = 2**252 + 27742317777372353535851937790883648493
    h  = 8
    n  = h * r 
    
    
class Ed25519( TwistedEdwardsCurveFp ):
    """ (x**2 + y**2) % p == (1 + 121665/121666)*x**2 * y**2) % p """
    curveId = 'Ed25519'
    strength = 126
    oid = None
    p  = 2**255 - 19
    d =  1      #  d = (121665/121666) % p
    xG = 9
    #yG = 14781619447589544791020593568409986887264606134616475288964881837755586237401
    yG = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
    r  = 2**252 + 27742317777372353535851937790883648493 
    h  = 8
    n = h * r
 
class MS255t1( TwistedEdwardsCurveFp ):
    """ MS https://datatracker.ietf.org/doc/draft-black-rpgecc/
        The isogenous Montgomery curve is given by A = 0x76D06 = 486662
    """
    curveId = 'ms255t1'
    strength = 126
    oid = None
    # p = 255** - 19
    p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    a = -1
    d = 121665  # 0x1DB41 
    xG = 0x5C88197130371C6958E48E7C57393BDEDBA29F9231D24B3D4DA2242EC821CDF1
    yG = 0x6FEC03B956EC4A0E51A838029242F8B107C27399CC7840C34B955E478A8FB7A5
    r = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    h = 8    
       
class MS384e1( EdwardsCurveFp ):
    """ draft-black-rpgecc-01 
        The isogenous Montgomery curve is given by A = 0xB492 = 46226
    """
    curveId = 'ms255t1'
    strength = 198
    oid = None
    p = 2**384 - 317
    c = 1
    d = -11556
    d = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD19F
    xG = 0x61B111FB45A9266CC0B6A2129AE55DB5B30BF446E5BE4C005763FFA8F33163406FF292B16545941350D540E46C206BDE
    yG = 0x82983E67B9A6EEB08738B1A423B10DD716AD8274F1425F56830F98F7F645964B0072B0F946EC48DC9D8D03E1F0729392
    r  = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE2471A1CB46BE1CF61E4555AAB35C87920B9DCC4E6A3897D
    h = 4

      
class E382( EdwardsCurveFp ):
    """ x**2+y**2 == (1-67254*x**2*y**2) mod 2**382-105 """
    curveId = 'e382'
    strength = 190
    oid = None
    p  = 2**382-105
    d  = -67254
    xG = 3914921414754292646847594472454013487047137431784830634731377862923477302047857640522480241298429278603678181725699
    yG = 17
    n  = 2**380 - 1030303207694556153926491950732314247062623204330168346855
    h  = 4


class M383( MontgomeryCurveFp ):
    """ y**2 == x**3+2065150*x**2+x mod 2**383-187 """
    curveId = 'm383'
    strength = 190
    p = 2**383-187
    a = 2065150
    xG = 0xc  #  12
    yG = 0x1ec7ed04aaf834af310e304b2da0f328e7c165f0e8988abd3992861290f617aa1f1b2e7d0b6e332e969991b62555e77e
    n  = 2**380 + 166236275931373516105219794935542153308039234455761613271
    h  = 8


class Curve3617( EdwardsCurveFp ):
    curveId = 'curve3617'
    strength = 205
    oid = None
    p  = 2**414 - 17  
    d  = 3617
    xG = 0x1a334905141443300218c0631c326e5fcd46369f44c03ec7f57ff35498a4ab4d6d6ba111301a73faa8537c64c4fd3812f3cbc595
    yG = 0x22   # 34
    n  = 2**411 - 33364140863755142520810177694098385178984727200411208589594759
    h  = 8


class M511( MontgomeryCurveFp ):
    """ 
        https://eprint.iacr.org/2013/647.pdf
    """
    curveId = 'm511'
    strength = 253.8
    oid = None
    p  = 2**511-187
    a  = 530438
    xG = 5
    yG = 2500410645565072423368981149139213252211568685173608590070979264248275228603899706950518127817176591878667784247582124505430745177116625808811349787373477
    n  = 2**508 + 10724754759635747624044531514068121842070756627434833028965540808827675062043
    h  = 8


class E521( EdwardsCurveFp ):
    """ x**2+y**2 = 1-376014*x**2*y**2  mod 2**521-1"""
    curveId = "e521"
    strength = 259
    oid = None
    p  = 2**521-1
    d  = -376014
    xG = 1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324
    yG = 12
    n  = 2**519 - 337554763258501705789107630418782636071904961214051226618635150085779108655765
    h  = 4


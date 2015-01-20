#!/usr/bin/env python
""" ecc.py

Elliptic Curve

Refs: http://safecurves.cr.yp.to/index.html
      http://ed25519.cr.yp.to/python/ed25519.py
      https://github.com/warner/python-ed25519/blob/master/kat.py
      Extension and repackaging of Peter Pearson's open source ECC

20131201 refactored
2015  projections and new curve type changes, midway in refactor .... 

Paul A. Lambert 2015
"""
from numbertheory import inverse_mod, square_root_mod_prime

class EllipticCurveError(Exception): pass

class EllipticCurveFp(object):
    """ A Elliptic Curve over the field of integers modulo a prime.
        Overloaded by specific curve types to support:
            SmallWeierstrassCurveFp
            TwistedEdwardsCurveFp
            EdwardsCurveFp
            MontgomeryCurveFp

       A collection of curves using this class are in:  curves.py
    """
    def __init__(self):
        self.coord_size = len( int_to_string(self.p) )
        self.IDENTITY = self.identity()  # aka INFINITY for Weierstrass curves
    
    def point(self, x, y):
        """ Factory method to make points on a curve """
        return Point(self, x, y)
        
    def generator(self):
        """ Return the ECC generator point G """
        return self.point(self.xG, self.yG)
    
    def uncompress(self, xR):
        """ Return a new point R from just x-coordinate xR
            Note - this is not ANSI or SEC format 'x' with
                   leading 2 bits holding (2 + yR mod 2)
            yR will be incorrect for 50% of runs,
            but ECDH will still have correct answer
        """
        a = self.a
        b = self.b
        p = self.p
        #t0 = ( xR*xR*xR + a*xR + b ) % p
        t0 = ((xR*xR + a)*xR + b ) % p
        t1 = square_root_mod_prime( t0, p )
        yR = t1   # it might also be yR = p - t1
        R = self.point( xR, yR )
        if self.contains_point(R):
            return R
        yR = p - t1
        R = self.point( xR, yR )
        if self.contains_point(R):
            return R
        else:
            EllipticCurveError( "uncompress failed")
        
    def inverse(self, a):
        """ scalar inversion in Fp - overload for 'p' specific optimizations """
        return inverse_mod(a, self.p)  # this is a generic inverse_mod
                                  # 7 times faster than pow(a, self.p-2, self.p)
                     

class Point(object):
    """ An Afine point on an elliptic curve """
    def __init__(self, curve, x, y):
        """Create point on identified 'curve' having points x and y"""
        self.curve = curve
        self.x = x
        self.y = y     

    def __add__(self, other):
        return self.curve.add_points(self, other)
        
    def __neg__(self):
        return self.curve.negate(self)

    def __sub__(self, other):
        return self + -other
    
    def __cmp__(self, other):
        """Return 0 if the points are identical, 1 otherwise."""
        if self.curve == other.curve and self.x == other.x and self.y == other.y:
            return 0
        else:
            return 1       
    
    def __mul__(self,other):
        return self.curve.scalar_multiple(self,other)
        
    def __rmul__(self, other):
        """Multiply a integer by a point."""     
        return self * other

    def __str__(self):
        if self == self.curve.identity(): return "Identity"
        return "(%d,%d)" % ( self.x, self.y )

    def double(self):
        """Return a new point that is twice the old """   
        return self.curve.double_point(self)

    def encode(self, encode='raw'):
        """ Encode a point (usually for public keys) """
        if encode == 'raw':   # encode both x and y sequentially
            return int_to_string(self.x, padto=self.curve.coord_size) + int_to_string(self.y, padto=self.curve.coord_size)
        else:
            raise Exception('undefined encode')
                
    def to_octetstring(self):
        """ Encode point as x and y octetstring """
        octetstring = int_to_string(self.x) + int_to_string(self.y)
        return octetstring
    
    def from_octetstring(self,octetstring):
        """
        http://tools.ietf.org/html/draft-jivsov-ecc-compact-00 """
        raise "to do"
    
    def __str__(self):
        if self == self.curve.identity():
            return "IDENTITY"
        return "(%d,%d)" % ( self.x, self.y )    

class SmallWeierstrassCurveFp( EllipticCurveFp ):
    """ A Small Wierstrass curve has points on:
            y^2 == x^3 + a*x^2+b  over  GF(p)
    """
    def contains_point(curve, g):
        """Is the point 'g' on the Small Weierstrass curve"""
        p = curve.p;  a = curve.a;  b = curve.b;  x = g.x;  y = g.y

        return  (y**2) % p == (x**3 + a*x**2 + b) % p
          
    def add_points(curve, p1, p2):
        """ Add one point to another point (from X9.62 B.3). """
        assert p1.curve == p2.curve    # points must be on the same curve
        INFINITY = curve.identity()
        if p2 == INFINITY:
            return p1
        if p1 == INFINITY:
            return p2
        
        x1 = p1.x; y1 = p1.y; x2 = p2.x; y2 = p2.y; p = curve.p #for readability
        inv = curve.inverse
        if x1 == x2:
            if ( y1 + y2 ) % p == 0:
                return INFINITY
            else:
                return p1.double()      
        l = ( (y2-y1) * inv( x2-x1) ) % p    
        x3 = (l * l - x1 - x2) % p
        y3 = (l * ( x1 - x3 ) - y1) % p       
        return curve.point(x3, y3)
        
    def negate(curve, point):
        """ Negate a point """
        return curve.point( point.x, -point.y )

    def double_point(curve, point):
        """Return a new point that is twice the old (X9.62 B.3)."""   
        p = curve.p; a = curve.a; inv = curve.inverse
        x = point.x; y = point.y
        
        l = ( (3*x*x + a) * inv(2*y) ) % p    
        x3 = (l*l - 2*x) % p
        y3 = (l * (x - x3) - y) % p       
        return curve.point(x3, y3)
    
    def scalar_multiple(curve, point, scalar):
        """Multiply a point by an integer (From X9.62 D.3.2). """ 
        INFINITY = curve.identity()
        def leftmost_bit( x ):
            assert x > 0
            result = 1L
            while result <= x: result = 2 * result
            return result / 2
    
        e = scalar
        # if point.n: e = e % point.n #?? if n=None??
        e = e % point.curve.n
        if e == 0: return INFINITY
        if point == INFINITY: return INFINITY
        assert e > 0
    
        e3 = 3 * e
        negative_self = curve.point( point.x, -point.y )
        i = leftmost_bit( e3 ) / 2
        result = point
        while i > 1:
            result = result.double()
            if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + point
            if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
            # print ". . . i = %d, result = %s" % ( i, result )
            i = i / 2   
        return result

    def identity(curve):
        """ The additive identity """
        return curve.point(None, None) # Special point at infinity


class KoblitzCurveFp( SmallWeierstrassCurveFp ):
    """ A Koblitz curve is a SMall Weierstrass curve with a=0 :
            y**2 == x**3 + b  over  GF(p)
    """
    a = 0
    
    
class TwistedEdwardsCurveFp( EllipticCurveFp ):
    """ A Twisted Edwards curve has points on:
            (a*x**2 + y**2) % p == (1 + d*x**2*y**2) % p
    """       
    def contains_point(curve, g):
        """ Returns true if the point 'g' is on the curve """
        x = g.x; y = g.y; d = curve.d;  a = curve.a;  p = curve.p
        
        return  (a*x**2 + y**2) % p == (1 + d*x**2*y**2) % p
            
    def add_points(curve, p1, p2):
        """ Add two points on the curve """
        x1 = p1.x;  x2 = p2.x;  y1 = p1.y;  y2 = p2.y
        d = curve.d; a = curve.a; p = curve.p; inv = curve.inverse
        
        # Edwards curve addition 
        x3 = ( (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2) ) % p
        y3 = ( (y1*y2-a*x1*x2) * inv(1-d*x1*x2*y1*y2) ) % p       
        return curve.point(x3, y3)
        
    def negate(curve, p):
        """ Negate a point """
        return curve.point(-p.x, p.y)

    def double_point(curve, point):
        """ Return a new point that is twice the old """
        
        # Edwards curve point doubling
        return point+point
            
        x = point.x; y = point.y; inv = curve.inverse
        # following hangs for n*G ???????
        x_sqrd = x*x;   y_sqrd = y*y
        x2 = (2*x*y)*inv(x_sqrd + y_sqrd)
        y2 = (y_sqrd - x_sqrd)*inv(2 - x_sqrd - y_sqrd)
        return curve.point(x2, y2)
        
    def scalar_multiple(curve, point, scalar):
        if scalar == 0:
            return curve.identity()
        q = curve.scalarmult(point, scalar/2)
        q = q + q
        if scalar & 1:
            q = q + point
        return q
        
    def identity(curve):
        """ The additive identity """
        return curve.point(0,-1)
        
class EdwardsCurveFp( TwistedEdwardsCurveFp ):
    """ An Edwards curve is a Twisted Edwards curve with a = 1
            (a*x**2+y**2)%p == (1+d*x**2*y**2)%p
            or 
            (x**2+y**2)%p == (1+d*x**2*y**2)%p
    """
    a = 1
     
class MontgomeryCurveFp( EllipticCurveFp ):
    """ A Montogomery curve has points on:
            y^2 == x^3 + a*x^2 + x  modulo the prime p
    """
    def contains_point(curve, g):
        """ Is the point 'g' on the curve? """
        x = g.x; y = g.y; a = curve.a; p = curve.p; x_sqrd = x*x
        
        return (y*y) % p == (x*x_sqrd + a*x_sqrd + x) % p

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

def cswap(x2, x3, bit):
    dummy = bit * (x2 - x3)
    x2 = x2 - dummy
    x3 = x3 + dummy
    return (x2, x3)
    
def int_to_string( x, padto=None ):
    """ Convert integer x into a string of bytes, as per X9.62.
        If 'padto' defined, result is zero padded to this length.
    """
    assert x >= 0
    if x == 0: return chr(0)
    result = ""
    while x > 0:
        q, r = divmod( x, 256 )
        result = chr( r ) + result
        x = q
    if padto:
        padlen = padto - len(result)
        assert padlen >= 0
        result = padlen*chr(0) + result
    return result

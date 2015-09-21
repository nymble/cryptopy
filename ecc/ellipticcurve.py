#!/usr/bin/env python
""" ellipticcurve.py

    Contains base classes:
     - EllipticCurveError
     - EllipticCurve
     - EllipticCurveFp
     - Point

    Overloaded by specific curve types in ecc.py to support:
        SmallWeierstrassCurveFp
        TwistedEdwardsCurveFp
        EdwardsCurveFp
        MontgomeryCurveFp

    A collection of curves using this class are in:  curves.py
       
20131201 refactored

Paul A. Lambert 2015
"""
from numbertheory import inverse_mod, square_root_mod_prime
from cryptopy.cipher.common import string_to_int, int_to_string
from Crypto import Random

class EllipticCurveError(Exception): pass

class EllipticCurveFp(object):
    """ A Elliptic Curve over the field of integers modulo a prime.
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
    
    def xxuncompress(self, xR):
        """ Return a new point R from just x-coordinate xR
            Note - this is not ANSI or SEC format 'x' with
                   leading 2 bits holding (2 + yR mod 2)
            yR will be incorrect for 50% of runs,
            but ECDH will still have correct answer
        """
        a = self.a; b = self.b; p = self.p
        t0 = ((xR*xR + a)*xR + b ) % p
        t1 = square_root_mod_prime( t0, p )
        yR = t1   # it might also be yR = p - t1
        R = self.point( xR, yR )
        if self.on_curve(R):
            return R
        yR = p - t1
        R = self.point( xR, yR )
        if self.on_curve(R):
            return R
        else:
            EllipticCurveError( "uncompress failed")
        
    def inverse(self, a):
        """ scalar inversion in Fp - overload for 'p' specific optimizations """
        return inverse_mod(a, self.p)  # this is a generic inverse_mod
                           # 7 times faster than pow(a, self.p-2, self.p)
                                  
    def randomScalar(self):
        """ Random scalar in range """
        rndfile = Random.new()
        scalar = string_to_int( rndfile.read(self.coord_size) ) % self.p
        return scalar
    
    def newAsymSecret(self):
        """ Creation of a asymetric secret for a public key pair
            For ECC it's usally a random scalar, curve25519 must overload
        """
        return self.randomScalar()
    
    def make_PublicKey(self, secretScalar):
        """ Create a public key from a secret key """
        return secretScalar * self.generator()
    
    def is_valid( self, point ):
        return self.contains_point( point )
    
    def __contains__( self, point ):
        """ support syntax using 'in', e.g.
                if point in curve:
        """
        return self.contains_point( point )

class Point(object):
    """ An Afine point on an elliptic curve """
    def __init__(self, curve, x, y):
        """Create point on identified 'curve' having coordinates x and y"""
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

    # xx - remove encoding from point since ther are several ways ...
    def xxencode(self, encode='raw'):
        """ Encode a point (usually for public keys) """
        if encode == 'raw':   # encode both x and y sequentially
            return int_to_string(self.x, padto=self.curve.coord_size) + int_to_string(self.y, padto=self.curve.coord_size)
        else:
            raise Exception('undefined encode')
                
    def xxto_octetstring(self):
        """ Encode point as x and y octetstring """
        octetstring = int_to_string(self.x) + int_to_string(self.y)
        return octetstring
    
    def xxfrom_octetstring(self,octetstring):
        """ """
        raise "to do"
        point = self.curve.point
        return point
    
    def __str__(self):
        if self == self.curve.identity():
            return "IDENTITY"
        return "(%d,%d)" % ( self.x, self.y )    


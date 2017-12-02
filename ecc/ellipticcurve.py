#!/usr/bin/env python
""" ellipticcurve.py

    Contains base classes:
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

    Copyright Paul A. Lambert 2017
"""

from numbertheory import inverse_mod, square_root_mod_prime

class EllipticCurveError(Exception): pass

class EllipticCurve(object):
    """ Base class for elliptic curves. """
    def point(self, x, y, validate=True):
        """ Factory method to make points on the curve """
        return Point(self, x, y, validate=validate)

    def generator(self):
        """ Return the predefined generator point G """
        return self.point(self.xG, self.yG)


class EllipticCurveFp(EllipticCurve):
    """ Elliptic Curve over the field of integers modulo a prime p. """
    def __init__(self):
        # calculate the coord_size
        p = self.p
        assert p >= 0
        size = 0
        while p > 0:
            q, r = divmod( p, 256 )
            size += 1
            p = q
        self.coord_size = size # in bytes
        self.IDENTITY = self.identity() # defined in subclass

    def inverse(self, a):
        """ scalar inversion in Fp, overload for 'p' specific optimizations """
        # this is a generic inverse_mod 7 times faster
        # than pow(a, self.p-2, self.p)
        return inverse_mod(a, self.p)


class Point(object):
    """ An Afine point on an elliptic curve """
    def __init__(self, curve, x, y, validate=True):
        """Create point on identified 'curve' having coordinates x and y"""
        self.curve = curve
        self.x = x
        self.y = y
        if validate: assert curve.on_curve(self)

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

    # === below should be refactored ===
    def encode(self, encode='raw'):
        """ Encode a point (usually for public keys) """
        if encode == 'raw':   # encode both x and y sequentially
            return int_to_string(self.x, padto=self.curve.coord_size) + int_to_string(self.y, padto=self.curve.coord_size)
        else:
            raise Exception('undefined encode')

    def toOctets(self):
        """ Encode point as x coordinate """
        return int_to_string(self.x)

    def to_octetstring(self): # Used???
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



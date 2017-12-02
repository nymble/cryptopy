#!/usr/bin/env python
""" ecc.py

    Elliptic Curve Cryptograpy

    This module contains the base mathmatical operations for
    the supported elliptic curves.

    Specific elliptic curves are defined using these classes
    in curves.py

    Refs:
        Peter Pearson's open source ECC
        http://safecurves.cr.yp.to/index.html
        http://ed25519.cr.yp.to/python/ed25519.py
        https://github.com/warner/python-ed25519/blob/master/kat.py


    20131201 refactored
    2015  projections and new curve type changes

    Copyright Paul A. Lambert 2017
"""
from ellipticcurve import EllipticCurveFp
from numbertheory import square_root_mod_prime
from os import urandom


class SmallWeierstrassCurveFp( EllipticCurveFp ):
    """ A Small Wierstrass curve has points on:
            y^2 == x^3 + a*x^2+b  over  GF(p)
    """
    def on_curve(curve, point):
        p = curve.p;  a = curve.a; b = curve.b;
        x = point.x;  y = point.y; INFINITY = curve.IDENTITY

        if point == INFINITY: # point at infinity
            return True
        else:
            return  (y**2) % p == (x**3 + a*x + b) % p

    def add_points(curve, p1, p2):
        """ Add one point to another point (from X9.62 B.3). """
        assert p1.curve == p2.curve    # points must be on the same curve
        INFINITY = curve.IDENTITY
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
        INFINITY = curve.IDENTITY
        def leftmost_bit( x ):
            assert x > 0
            result = 1L
            while result <= x: result = 2 * result
            return result / 2

        e = scalar
        e = e % point.curve.n
        if e == 0:
            return INFINITY
        if point == INFINITY:
            return INFINITY
        assert e > 0

        e3 = 3 * e
        negative_self = curve.point( point.x, -point.y )
        i = leftmost_bit( e3 ) / 2
        result = point
        while i > 1:
            result = result.double()
            if ( e3 & i ) != 0 and ( e & i ) == 0:
                result = result + point
            if ( e3 & i ) == 0 and ( e & i ) != 0:
                result = result + negative_self
            i = i / 2
        return result

    def identity(curve):
        """ The additive identity. Special values for 'infinity'
            Note - idenity is required by 'on_curve' check so
            validate is disabled for this special point.
        """
        return curve.point(None, None, validate=False)

    @classmethod
    def y_from_x(cls, x):
        """ Returns one of the two possible values for y from x.
            Used for point decompression.
        """
        a = cls.a; b = cls.b; p = cls.p
        y_squared = ((x*x+ a)*x + b ) % p
        # it might be y or p - y
        y = square_root_mod_prime( y_squared, p )
        return y

    def new_private_key(self):
        return string_to_int( urandom(self.coord_size) )


class KoblitzCurveFp( SmallWeierstrassCurveFp ):
    """ A Koblitz curve is a Small Weierstrass curve with a=0 :
            y**2 == x**3 + b  over  GF(p)
    """
    a = 0


class TwistedEdwardsCurveFp( EllipticCurveFp ):
    """ A Twisted Edwards curve has points on:
            (a*x**2 + y**2) % p == (1 + d*x**2*y**2) % p
    """
    def on_curve(curve, g):
        """ Returns true if the point 'g' is on the curve """
        x = g.x; y = g.y; d = curve.d;  a = curve.a;  p = curve.p

        #return  (a*x**2 + y*y - 1 - d*x*x*y*y)  % p == 0
        xx = x*x
        return  (a*xx - 1 + y*(1 - d*xx*y))  % p == 0

    def add_points(curve, p1, p2):
        """ Add two points on the curve """
        x1 = p1.x;  x2 = p2.x;  y1 = p1.y;  y2 = p2.y
        d = curve.d; a = curve.a; p = curve.p; inv = curve.inverse

        # Edwards curve addition
        x3 = ( (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2) ) % p
        y3 = ( (y1*y2-a*x1*x2) * inv(1-d*x1*x2*y1*y2) ) % p    # ??? a=1 or a=-1 for Edwards?
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
            return curve.IDENTITY
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
            y**2 == x**3 + a*x**2 + x  modulo the prime p
    """
    def on_curve(curve, g):
        """ Is the point 'g' on the curve? """
        x = g.x; y = g.y; a = curve.a; p = curve.p; x_sqrd = x*x

        return (y*y) % p == (x*x_sqrd + a*x_sqrd + x) % p

    def add_points(curve, p1, p2):
        """ Montgomery elliptic curve point addition"""
        if p2 == curve.IDENTITY:
            return p1
        if p1 == curve.IDENTITY:
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
            return curve.IDENTITY
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
    """ Swap routine used by Montgomery Ladder """
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

def string_to_int( octet_string ):
    """ Convert a string of bytes into an integer, as per X9.62. """
    long_int = 0L
    for c in octet_string:
        long_int = 256 * long_int + ord( c )
    return long_int


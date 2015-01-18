#!/usr/bin/env python
""" 
"""
   
class SmallWeierstrassCurveFp( EllipticCurveFp ):
    """ A Small Wierstrass curve has points on:
            y^2 == x^3 + a*x^2+b  over  GF(p)
    """
    def contains_point(curve, x, y):
        """Is the point (x,y) on the Small Weierstrass curve"""
        
        return  (y**2) % p == (x**3 + a*x**2 + b) % p
          
    def add_points(curve, p1, p2):
        """ Add one point to another point (from X9.62 B.3). """
        assert p1.curve == p2.curve    # points must be on the same curve

        if (x1, y1) == INFINITY: return (x1, y1)
        if (x2, y2) == INFINITY: return (x2, y2)
        
        if x1 == x2:
            if ( y1 + y2 ) % p == 0:
                return INFINITY
            else:
                return double_point(x, y)      
        l = ( (y2-y1) / ( x2-x1) ) % p    
        x3 = (l * l - x1 - x2) % p
        y3 = (l * ( x1 - x3 ) - y1) % p       
        return (x3, y3)
        
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
        if point.n: e = e % point.n
        if e == 0: return INFINITY
        if point == INFINITY: return INFINITY
        assert e > 0
    
        e3 = 3 * e
        negative_self = curve.point( point.x, -point.y, point.n )
        i = leftmost_bit( e3 ) / 2
        result = point
        while i > 1:
            result = result.double()
            if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + point
            if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
            i = i / 2   
        return result

    def identity(curve):
        return curve.point(None, None) # Special point at infinity
             

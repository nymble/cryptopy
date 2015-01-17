#!/usr/bin/env python
""" 
"""

class MontgomeryCurveFp( EllipticCurveFp ):
    """ A Montogomery curve has points on:
            y^2 == x^3 + a*x^2 + x  modulo the prime p
    """
    def scalar_multiple(curve, scalar, point):
        return curve.montgomery_ladder(scalar, point)
        
    def montgomery_ladder(curve, scalar, point):
        """ Scalar multiplication on a Montgomery curve """
        x1 = point.x; a = curve.a; p = curve.p
        
        x2,z2,x3,z3 = 1, 0, x1, 1
        
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
            AA = A*A        
            B = x_2 - z_2
            BB = B*B       
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
    

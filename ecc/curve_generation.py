#!/usr/bin/env python
""" curve_generation.py

    Algorithms to generate new curves and to validate rigid curve definitions
"""
from ecc import EdwardsCurveFp, MontgomeryCurveFp

class Edwards_draft_black_rpgecc_01( EdwardsCurveFp ):
    """  from draft-black-rpgecc-01
    """

    def new_curve_d(self, p):
        """ Output a 'd' parameter for an Edwards Curve
            from draft-black-rpgecc-01
        """
        # assert is_prime(p)
        assert      p % 4 == 3
        d = 0
        while True:
            while True:
                if (d > 0) :
                    d = -d
                else:
                    d = -d + 1
                
                # until d is not a square in GF(p)
                if pow(d, (p-1)/2, p) == p - 1 :
                    break
                
            # Compute rd, rd', hd, hd' where #Ed(GF(p)) = hd * rd,
            #Ed'(GF(p)) = hd' * rd', hd and hd' are powers of 2 and rd, rd'are odd
       
            # until ((hd = hd' = 4) and rd is prime and rd' is prime)
            # if .... etc
        return d
"""

6.  Generators

   The generator points P = (X(P),Y(P)) for all curves are selected by
   taking the smallest positive value x in GF(p) (when represented as an
   integer) such that (x, y) is on the curve and such that (X(P),Y(P)) =
   8 * (x, y) has large prime order rd.

   Input: a prime p and curve parameters non-square d and
          a = -1 for twisted Edwards (p = 1 mod 4) or
          a = 1 for Edwards (p = 3 mod 4)
   Output: a generator point P = (X(P), Y(P)) of order rd
   1. Set x = 0 and found_gen = false
   2. while (not found_gen) do
       x = x + 1
       while ((1 - a * x^2) * (1 - d * x^2) is not a quadratic
              residue mod p) do
         x = x + 1
       end while
       Compute an integer s, 0 < s < p, such that
              s^2 * (1 - d * x^2) = 1 - a * x^2 mod p
       Set y = min(s, p - s)

       (X(P), Y(P)) = 8 * (x, y)

       if ((X(P), Y(P)) has order rd on Ed or tEd, respectively) then
         found_gen = true
       end if
     end while
   3. Output (X(P),Y(P))
"""

class MontgomeryFromEdwards( MontgomeryCurveFp ):
    """ Convert 
            Ed: x^2 + y^2 =- 1 + d x^2 y^2 over GF(p)
        to 4-isogenous curve
            EM: v^2 = u^3 + Au^2 + u
            
        from draft-black-rpgecc-01
    """
    
    def __init__(self, edwards_curve):
        p = edwards_curve.p
        assert (p % 4) == 3
        assert pow(d, (p-1)/2, p) == p - 1   # d must be non-square
        
        A = -(4*d - 2) % p  
        
        # set all parameters
        self.curveId = 'MtoE_' + edwards_curve.curveId
        self.strength = edwards_curve.strength  # 4-isogenous
        self.oid = None
        self.p = p
        self.a = A
        self.n = edwards_curve.n
        self.h = edwards_curve.h
        
        # Map the generator point from Edwards to Montgomery
        x = edwards_curve.xG; y = edwards_curve.yG
        
        # The neutral element (0,1) and the point of order two (0,-1) on Ed are
        # mapped to the point at infinity on EM.      
        if (x,y) == (0,1) or (x,y) == (0,-1) :
            self.value( self.identity() )
        else:
            self.x =  y**2 * inv( x**2 )                 # aka u
            self.y = -y*(x**2 + y**2 - 2) * inv( x**3 )  # aka v

class MontgomeryFromTwistedEdwards( MontgomeryCurveFp ):
    """ Convert 
            Ed: x^2 + y^2 =- 1 + d x^2 y^2 over GF(p)
        to 4-isogenous curve
            EM: v^2 = u^3 + Au^2 + u
            
            math from wikipedia
    """
    
    def __init__(self, twisted_edwards_curve):
        p = edwards_curve.p
        #assert (p % 4) == 3
        #assert pow(d, (p-1)/2, p) == p - 1   # d must be non-square
        
        assert c == 1 # assumed 1 for most embodiments of Twisted Edwards Curves
        a = twisted_edwards_curve.a; d = twisted_edwards_curve.d
        

        
        A = (2*(a+d)*inv(a-d)) % p
        # for a =-1
        # A = 2*(d-1) / (d+1)
        
        # set all parameters
        self.curveId = 'MtoE_' + edwards_curve.curveId
        self.strength = edwards_curve.strength  # 4-isogenous
        self.oid = None
        self.p = p
        self.a = A
        self.n = edwards_curve.n
        self.h = edwards_curve.h
        
        # Map the generator point from Edwards to Montgomery
        x = edwards_curve.xG; y = edwards_curve.yG
        
        # The neutral element (0,1) and the point of order two (0,-1) on Ed are
        # mapped to the point at infinity on EM.      
        if (x,y) == (0,1) or (x,y) == (0,-1) :
            self.value( self.identity() )
        else:
            self.x = (1+y) * inv(1-y)               # aka u
            self.y = (1+y) * inv((1-y)*x)           # aka v


"""       
        # Then for the Montgomery curve EM: v^2 = u^3 + Au^2 + u
        x = edwards_curve.x; y = edwards_curve.y

        # The neutral element (0,1) and the point of order two (0,-1) on Ed are
        # mapped to the point at infinity on EM.      
        if (x,y) == (0,1) :
            
        u =  y**2 * inv ( x**2 )
        v =  -y*(x**2 + y**2 - 2) * inv( x**3 )


       
       The dual isogeny is given by

    phi_d: EM -> Ed, (u,v) -> (x,y), where
        x = 4v(u - 1)(u + 1) / (u^4 - 2u^2 + 4v^2 + 1),
        y = (u^2 + 2v - 1)(u^2 - 2v - 1) / (-u^4 + 2uv^2 + 2Au + 4u^2 + 1).

   It holds phi_d(phi((x,y))) = [4](x,y) on Ed and phi(phi_d((u,v))) =
   [4](u,v) on EM.
"""
   
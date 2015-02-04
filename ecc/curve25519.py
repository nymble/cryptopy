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

    def negate(curve, p1):
        return curve.point(-p1.x % p, p1.y)
   
    def identity(curve):
        return curve.point(0,-1)

    def montgomery_ladder(curve, scalar, point):
        """ 1987 Montgomery "Speeding the Pollard and elliptic curve
            methods of factorization", page 261, fifth and sixth displays,
            plus common-subexpression elimination, plus assumption Z1=1.
        """
        u = point.x;  a = curve.a;  p = curve.p; k = scalar
        
        a24 = (a - 2) * curve.inverse(4)   # (a-2)/4     
        x_1 = u
        x_2 = 1
        z_2 = 0
        x_3 = u
        z_3 = 1
        swap = 0        
        for t in reversed(range(255)):
            k_t = (k >> t) & 1
            swap ^= k_t
            (x_2, x_3) = cswap(swap, x_2, x_3) # conditional swap
            (z_2, z_3) = cswap(swap, z_2, z_3)
            swap = k_t            
            A = x_2 + z_2
            AA = A**2  % p
            B = x_2 - z_2
            BB = B**2  % p
            E = AA - BB % p
            C = x_3 + z_3 % p
            D = x_3 - z_3 % p
            DA = D * A  % p
            CB = C * B   % p
            x_3 = (DA + CB)**2  % p
            z_3 = x_1 * (DA - CB)**2  % p
            x_2 = AA * BB 
            z_2 = E * (AA + a24 * E) % p             #BB?
            (x_2, x_3) = cswap(swap, x_2, x_3)
            (z_2, z_3) = cswap(swap, z_2, z_3)

        return ( x_2 * (z_2**(p - 2)) ) % p

def cswap(swap, x_2, x_3):
    dummy = swap * (x_2 - x_3)
    x_2 = x_2 - dummy
    x_3 = x_3 + dummy
    return (x_2, x_3)
    
      
class Curve25519( MontgomeryCurveFp ):   
    """ y**2 == x**3 + 486662*x**2 + x  mod 2**255-19 """
    curveId = 'curve25519'
    strength = 126
    oid = None
    p  = 2**255-19
    a  = 486662
    xG = 9
    yG = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
    r  = 2**252 + 27742317777372353535851937790883648493
    h  = 8
    
    def __call__(self, scalar_octet_string, ): pass
        
        
    
def decodeLittleEndian(b):
    return sum([b[i] << 8*i for i in range(32)])
    
def decodeUCoordinate(u):
    u_list = [ord(b) for b in u]
    u_list[31] &= 0x7f
    return decodeLittleEndian(u_list)

def encodeUCoordinate(u):
    u = u % p
    return ''.join([chr((u >> 8*i) & 0xff) for i in range(32)])

def decodeScalar(k):
    k_list = [ord(b) for b in k]  
    k_list[0] &= 248                  # <- tweaking to make it special scalar
    k_list[31] &= 127
    k_list[31] |= 64 
    return decodeLittleEndian(k_list)    


""" 7.1. Test vectors """

# Input scalar (input as a octet string):
s_octets = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'.decode('hex')
# Input U-coordinate:
in_u = 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'.decode('hex')
# Output U-coordinate:
out_u_known = 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'.decode('hex')

# Validate little-endian conversion of s and in_u
s_num_k  = 31029842492115040904895560451863089656472772604678260265531221036453811406496
in_u_num_k = 34426434033919594451155107781188821651316167215306631574996226621102155684838
s = decodeScalar(s_octets)
in_u_num = decodeScalar(in_u)
assert s == s_num_k
assert in_u_num == in_u_num_k

# Test as a function on octet strings
curve25519 = Curve25519()
out_u = curve25519(s_octets, in_u)

assert out_u_octets == out_u_known 



"""
Input scalar:
  4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
Input scalar as a number (base 10):
  35156891815674817266734212754503633747128614016119564763269015315466259359304
Input U-coordinate:
  e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
Input U-coordinate as a number:
  8883857351183929894090759386610649319417338800022198945255395922347792736741
Output U-coordinate:
  95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
"""


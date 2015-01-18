""" curves.py
    
  Elliptic Curve Cryptography Parameter Definitions
  
  Definitions Include:
    - SECP Fp Curves from SEC 2: Recommended Elliptic Curve Domain Parameters
    - NIST Fp Curves from FIPS PUB 186-4 (same as selected SECP curves)
    - Brainpool Curves from RFC 5639, March 2010
    - Montogomery and Edwards curves from
      http://www.hyperelliptic.org/EFD/g1p/index.html
    - Chinese Commercial Cryptography Administration Office Fp-256
    - Russian Federal GOST R 34.10-2001
    - French National Agency for the Security of Information Systems FRP256v1
      http://www.legifrance.gouv.fr/affichTexte.do?cidTexte=JORFTEXT000024668816
    
  These ECC definitions include four classes of curves defined over the field
  of integers modulo a prime p.  Each class of curve has an equation and
  assoicated parameters unique to the class type.  Four classes of curves
  are described:
    
    SmallWeierstrassCurveFp               y**2 == x**3 + a*x + b
    KoblitzCurveFp                        y**2 == x**3       + b
    TwistedEdwardsCurveFp        a*x**2 + y**2 ==    1 + d*x**2*y**2 
    EdwardsCurveFp                 x**2 + y**2 == c*(1 + d*x**2*y**2) 
    MontgomeryCurveFp                     y**2 == x**3 + a*x**2 + x 
       
  The defintions include for each curve type:
    
    curveId - An ASCII string used to identify the curve parameters      
    strength - an integer providing the estimated cryptographic strength
               of the curve as a power of 2                 
    oid - a list of integers that correspond to the associated ASN.1 object
          identifier. The oid is listed as 'None' if the assigned oid is unknown        
    p - The prime modulus of the group GF(p). Often p is a Mersenne prime
        or psuedo-Mersenne prime to facilitate efficient modular operations
    xG - the x-coordinate of a generator point G for the curve        
    yG - the y-coordinate of a generator point G for the curve
    n  - the order of the generator point G
    h - the cofactor of the curve
    seed - used for some random curves to demonstrate the provenance of
           the curve parameters and included for reference when available

  Each curve type has the following equations and parameters
  
    Small Wierstrass     y**2 == x**3 + a*x + b  mod p     
      a - often set to p-3 for efficiency        
      b - selected for the security properties of the curve shape
      z - used by 'twisted' Brainpool curves for isogenous transform
          of untwisted curve to a curve with a = p-3
  
    Small Wierstrass      y**2 == x**3 + a*x + b  mod p     
      a - often set to p-3 for efficiency        
      b - selected for the security properties of the curve shape
      z - used by 'twisted' Brainpool curves for isogenous transform
          of untwisted curve to a curve with a = p-3

    Koblitz               y**2 == x**3 + b  mod p           
      b - selected for the security properties of the curve shape
          
    Edwards              x**2 + y**2 == c*(1 + d*x**2 * y**2) mod p    
      c - typically set to 1 so the equation is reduced to:
                         x**2 + y**2 == 1 + d*x**2 * y**2  mod p               
      d - selected for the security properties of the curve shape  
        
    Montgomery           y**2 == x**3 + c*x**2 + x  mod p     
      c - selected for the security properties of the curve shape
 
    
    Paul A. Lambert, December 2013
"""
from ecc import SmallWeierstrassCurveFp, EdwardsCurveFp, MontgomeryCurveFp 

class SECP_192r1( SmallWeierstrassCurveFp ):
    curveId = 'secp192r1'
    strength = 80
    #  {iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 1 }
    oid = (1,2,840,10045,3,1,1)
    # p = 2**192 - 2**64 - 1
    p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a = p-3  # all NIST mod p curves use a = -3 , note  -3 % p = (p-3)

    b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    # Generator point coordinate (x,y), order n and cofactor h
    # Any point G=(x,y) can serve as base point. User may generate their own
    # to ensure cryptographic separation of networks.

    xG = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
    yG = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
    n = 6277101735386680763835789423176059013767194773182842284081
    h = 1 # cofactor

    seed = 0x3045ae6fc8422f64ed579528d38120eae12196d5  # unknown provenance
    seed_c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65L
    # NIST validation of parameters
    # assert seed_c == SHA1(seed)
    # assert (seed_c*b**2 + 27) % p == 0

class NIST_P192(SECP_192r1):  # NIST renamed secp192r1
    curveId = 'nistP192'

class SECP_224r1( SmallWeierstrassCurveFp ):
    curveId = 'secp224r1'
    strength = 112
    # {iso(1) identified-organization(3) certicom(132) curve(0) 33}
    oid = (1, 3, 132, 0, 33) 
    # p = 2**224 - 2**96 + 1
    p = 0xffffffffffffffffffffffffffffffff000000000000000000000001L
    a = p - 3
    b = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4    
    xG = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21
    yG = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34
    n = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d
    h = 1
    
    seed = 0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5
    seed_c = 0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fb

class NIST_P224( SECP_224r1 ):  # NIST renamed Secp224r1
    curveId = 'nistP224'

class SECP_256k1( KoblitzCurveFp ):
    """ Certicom secp256-k1 curve - used in Bitcoin, not used by NIST
    """
    curveId = 'secp256k1'
    strength = 128
    # {iso(1) identified-organization(3) certicom(132) curve(0) 10}
    oid = (1,3,132,0,10) 
    # p = 2**256 - 2**32 - 2**29 - 2**28 - 2**7 - 2**26 - 2**24 - 1
    p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    b  = 7
    xG = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    yG = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    n  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    h  = 1
    
class SECP_256r1( SmallWeierstrassCurveFp ):
    """ Commonly used NIST/SECP curve """
    curveId ='secp256r1'
    strength = 128
    # {iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7}
    oid = (1,2,840,10045,3,1,7) 
    # p = 2**256 - 2**224 + 2**192 + 2**96 - 1
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = p - 3 
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    xG = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    yG = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    h = 1
       
    seed = 0xc49d360886e704936a6678e1139d26b7819f7e90
    seed_c = 0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d
    
class NIST_P256(SECP_256r1): # NIST renamed secp256r1
    curveId = 'nistP256'

class WAPI( SmallWeierstrassCurveFp ):
    """ Chinese Commercial Cryptography Administration Curve
        Documented in WAPI spec.  another may be in implementations
        oid = (1, 2, 156, 11235, 1, 1, 1, 2, 1)  # implementations?
    """
    curveId = 'wapi'
    strength = 96
    oid = (1,2,156,1001,5,40,1)
    p = 0xbdb6f4fe3e8b1d9e0da8c0d46f4c318cefe4afe3b6b8551f
    a = 0xbb8e5e8fbc115e139fe6a814fe48aaa6f0ada1aa5df91985
    b = 0x1854bebdc31b21b7aefc80ab0ecd10d5b1b3308e6dbf11c1
    xG = 0x4ad5f7048de709ad51236de65e4d4b482c836dc6e4106640
    yG = 0x02bb3a02d4aaadacae24817a4ca3a1b014b5270432db27d2
    n = 0xbdb6f4fe3e8b1d9e0da8c0d40fc962195dfae76f56564677 
    h = 1

class SWP256CCAO01( SmallWeierstrassCurveFp ):
    """ Chinese Commercial Cryptography Administration Office
        Fp-256 ECC curve used in SM2 from:
        https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
        http://www.oscca.gov.cn/UpFile/2010122214822692.pdf
    """
    curveId ='swp256cccao01'
    aka = ('Fp-256',)
    strength = 128
    oid = None
    p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
    a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
    b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    xG = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
    yG = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
    n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

class SWP256SM2( SmallWeierstrassCurveFp ):
    """ Chinese Commercial Cryptography Administration Office
        State Public Key Cryptographic Algorithm SM2
        http://www.oscca.gov.cn/UpFile/2010122214836668.pdf
        https://eprint.iacr.org/2013/816.pdf
    """
    curveid = 'swp256sm2'
    strength = 128
    oid = None
    # p = 2**256 - 2**225 + 2**224 - 2**96 + 2**64 - 1
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = p - 3
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    xG = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    yG = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    h = 1

class SWP256GOST01( SmallWeierstrassCurveFp ):
    """ Russian GOST curve GOST R 34.10-2012 
        https://tools.ietf.org/html/rfc7091
        http://standartgost.ru/en/180829
    """
    curveId ='swp256gost01'
    aka = ('Fp-256',)
    strength = 128
    oid = None 
    p = 0x8000000000000000000000000000000000000000000000000000000000000431
    a = 0x7
    b = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
    xG = 0x2
    yG = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8
    n = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
    h = 1
    
    
class FRP256v1( SmallWeierstrassCurveFp ):
    """ French National Agency for the Security of Information Systems 2009 
      http://www.legifrance.gouv.fr/affichTexte.do?cidTexte=JORFTEXT000024668816
    """
    curveId ='frp256v1'
    strength = 128
    oid = (1, 2, 250, 1, 223, 101, 256, 1)
    p = 0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03
    a = p-3
    b = 0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F
    xG = 0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF
    yG = 0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB
    n = 0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1
    h = 1


class SECP_384r1( SmallWeierstrassCurveFp ):
    curveId = 'secp384r1'
    strength = 192
    # { iso(1) identified-organization(3) certicom(132) curve(0) 34 }
    oid = (1,3,132,0,34) 
    # p = 2**384 - 2**128 - 2**96 + 2**32 - 1 
    p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
    a = p - 3  
    b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
    xG = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
    yG = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
    n = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
    h = 1
    
    seed = 0xa335926aa319a27a1d00896a6773a4827acdac73
    seed_c = 0x79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483
    
class NIST_P384(SECP_384r1): # NIST renamed secp384r1
    curveId = 'nistP384'
  
class SECP_521r1( SmallWeierstrassCurveFp ):
    curveId = 'secp256r1'
    strength = 256
    oid = (1,3,132,0,35)  # {iso(1) identified-organization(3) certicom(132) curve(0) 35}
    # p = 2**251 - 1   #  a Mersenne prime
    p = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    a = p - 3  
    b  = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
    n  = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
    xG = 0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
    yG = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
    h = 1
 
    seed = 0xd09e8800291cb85396cc6717393284aaa0da64ba 
    seed_c = 0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637

class NIST_P521(SECP_521r1):
    curveId = 'nistP521'


""" Brainpool Standard Curves and Curve Generation - RFC 5639, March 2010
    http://www.ecc-brainpool.org/download/Domain-parameters.pdf
"""

def brainPoolRequirements( curve ):
    """ Brainpool cryptographic requirements on the defined curves
        Not complete yet ... move to tests
    """
    a = curve.a;  b = curve.b;  p = curve.p
    assert  p > 3
    assert p % 4 == 3   # The prime number p shall be congruent 3 mod 4
    assert prime( p )
    assert (4*a**3 + 27*b**2) % p != 0

class BrainPoolP160r1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP160r1'
    strength = 80
    oid = (1,3,36,3,2,8,1,1,1)
    p  = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    a  = 0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300
    b  = 0x1E589A8595423412134FAA2DBDEC95C8D8675E58
    xG = 0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3
    yG = 0x1667CB477A1A8EC338F94741669C976316DA6321
    n  = 0xE95E4A5F737059DC60DF5991D45029409E60FC09
    h  = 1
    
    # Seed_p_160
    seed = 0x3243F6A8885A308D313198A2E03707344A409382

class BrainPoolP160t1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP160t1'    # Twisted version of brainpoolP160r1
    strength = 80
    oid = (1,3,36,3,2,8,1,1,2)
    p  = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    a  = p - 3 # for twistd Brainpool curve
    b  = 0x7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380
    xG = 0xB199B13B9B34EFC1397E64BAEB05ACC265FF2378
    yG = 0xADD6718B7C7C1961F0991B842443772152C9E0AD
    n  = 0xE95E4A5F737059DC60DF5991D45029409E60FC09
    h  = 1
    
    # z used only for twisted Branpool curves
    z  = 0x24DBFF5DEC9B986BBFE5295A29BFBAE45E0F5D0B 

class BrainPoolP192r1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP192r1'
    strength = 96
    oid = (1,3,36,3,2,8,1,1,3)
    p  = 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297
    a  = 0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF
    b  = 0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9
    xG = 0xC0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6
    yG = 0x14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F
    n  = 0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1
    h  = 1

class BrainPoolP192t1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP192t1'    # Twisted 
    strength = 96
    oid = (1,3,36,3,2,8,1,1,4)
    p  = 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297
    z  = 0x1B6F5CC8DB4DC7AF19458A9CB80DC2295E5EB9C3732104CB # z exists only for twisted curves
    a  = p - 3 # twisted so a = p-3
    b  = 0x13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79
    xG = 0x3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129
    yG = 0x097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9
    n  = 0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1
    h  = 1
    
class BrainPoolP224r1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP224r1'
    strength = 112
    oid = (1,3,36,3,2,8,1,1,5)
    p  = 0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF
    a  = 0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43
    b  = 0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B
    xG = 0x0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D
    yG = 0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD
    n  = 0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F
    h  = 1

class BrainPoolP224t1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP224t1'    # Twisted 
    strength = 112
    oid = (1,3,36,3,2,8,1,1,6)
    p  = 0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF
    z  = 0x2DF271E14427A346910CF7A2E6CFA7B3F484E5C2CCE1C8B730E28B3F
    a  = p - 3 # twisted version of brainpoolP224r1 so a = p-3
    b  = 0x4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D
    xG = 0x6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580
    yG = 0x0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C
    n  = 0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F
    h  = 1

class BrainPoolP256r1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP256r1'
    strength = 128
    oid = (1,3,36,3,2,8,1,1,7)
    p  = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
    a  = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
    b  = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
    xG = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
    yG = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
    n  = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    h  = 1

class BrainPoolP256t1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP256t1'    # Twisted 
    strength = 128
    oid = (1,3,36,3,2,8,1,1,8)
    p  = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
    z  = 0x3E2D4BD9597B58639AE7AA669CAB9837CF5CF20A2C852D10F655668DFC150EF0
    a  = p - 3  # twisted version of brainpoolP384r1 so that a = p-3
    b  = 0x662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04
    xG = 0xA3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4
    yG = 0x2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE
    n  = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    h  = 1

class BrainPoolP320r1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP320r1'
    strength = 160
    oid = (1,3,36,3,2,8,1,1,9)
    p  = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27
    a  = 0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4
    b  = 0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6
    xG = 0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611
    yG = 0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1
    n  = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311
    h  = 1

class BrainPoolP320t1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP320t1'    # 't' for Twisted 
    strength = 160
    oid = (1,3,36,3,2,8,1,1,10)
    p  = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27
    z  = 0x15F75CAF668077F7E85B42EB01F0A81FF56ECD6191D55CB82B7D861458A18FEFC3E5AB7496F3C7B1
    a  = p - 3  # twisted version of brainpoolP384r1 so that a = p-3
    b  = 0xA7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353
    xG = 0x925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52
    yG = 0x63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3
    n  = 0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311
    h  = 1

class BrainPoolP384r1( SmallWeierstrassCurveFp ):  
    curveId = 'brainpoolP384r1'
    strength = 192
    oid = (1,3,36,3,2,8,1,1,11)
    p  = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53
    a  = 0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826
    b  = 0x04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11
    xG = 0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E
    yG = 0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315
    n  = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565
    h  = 1

class BrainPoolP384t1( SmallWeierstrassCurveFp ):  
    curveId = 'brainpoolP384t1'    # Twisted 
    strength = 192
    oid = (1,3,36,3,2,8,1,1,12)
    p  = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53
    z  = 0x41DFE8DD399331F7166A66076734A89CD0D2BCDB7D068E44E1F378F41ECBAE97D2D63DBC87BCCDDCCC5DA39E8589291C
    a  = p - 3  # twisted version of brainpoolP384r1 so that a = p-3
    b  = 0x7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE
    xG = 0x18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54D8D0AA2F418808CC
    yG = 0x25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B2912675BF5B9E582928
    n  = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565
    h  = 1
   
class BrainPoolP512r1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP512r1'
    strength = 256
    oid = (1,3,36,3,2,8,1,1,13)
    p  = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
    a  = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
    b  = 0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723
    xG = 0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822
    yG = 0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892
    n  = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
    h  = 1

class BrainPoolP512t1( SmallWeierstrassCurveFp ):
    curveId = 'brainpoolP512t1'
    strength = 256
    oid = (1,3,36,3,2,8,1,1,14)
    p  = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
    a  = p - 3  # twisted version of brainpoolP512r1 so that a = p-3 
    b  = 0x7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E
    xG = 0x640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA
    yG = 0x5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332
    n  = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
    h  = 1
    
    z  = 0x12EE58E6764838B69782136F0F2D3BA06E27695716054092E60A80BEDB212B64E585D90BCE13761F85C3F1D2A64E3BE8FEA2220F01EBA5EEB0F35DBD29D922AB

""" Edwards and Montgomery curves """

class Curve25519( MontgomeryCurveFp ):
    """ y**2 == x**3 + 486662*x**2 + x  mod 2**255-19 """
    curveId = 'curve25519'
    strength = 126
    oid = None
    p  = 2**255-19
    a  = 486662
    xG = 9
    yG = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
    n  = 2**252 + 27742317777372353535851937790883648493 
    h  = 8
    
class Ed25519( EdwardsCurveFp ):
    """ (x**2 + y**2) % p == (1 + 121665/121666)*x**2 * y**2) % p """
    curveId = 'Ed25519'
    strength = 126
    oid = None
    p  = 2**255 - 19
    d =  1      #  d = (121665/121666) % p
    xG = 9
    yG = 14781619447589544791020593568409986887264606134616475288964881837755586237401
    yG = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
    n  = 2**252 + 27742317777372353535851937790883648493 
    h  = 8     
       
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
    curveId = 'm511'
    strength = 254
    oid = None
    p  = 2**511-187
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




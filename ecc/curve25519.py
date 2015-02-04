""" curve25519.py
    
    SmallWeierstrassCurveFp               y**2 == x**3 + a*x + b
    KoblitzCurveFp                        y**2 == x**3       + b
    TwistedEdwardsCurveFp        a*x**2 + y**2 ==    1 + d*x**2*y**2 
    EdwardsCurveFp                 x**2 + y**2 == c*(1 + d*x**2*y**2) 
    MontgomeryCurveFp                     y**2 == x**3 + a*x**2 + x 
       
 
"""
from ecc import SmallWeierstrassCurveFp, KoblitzCurveFp, TwistedEdwardsCurveFp, EdwardsCurveFp, MontgomeryCurveFp
import sys, inspect




""" Edwards and Montgomery curves """

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

# --- collect curves of same type ---

def get_all_classes():
    """ Python introspection return name and reference to all classes in module """
    return inspect.getmembers( sys.modules[__name__],
                lambda member: inspect.isclass(member) and
                member.__module__ == __name__)

smallWeierstrassCurves = []
koblitzCurves = []
twistedEdwardsCurves = []
edwardsCurves = []
montgomeryCurves = []

for curve_name, c in get_all_classes():
    if c.__bases__[0].__name__ == 'SmallWeierstrassCurveFp':
        smallWeierstrassCurves.append(c)
    elif c.__bases__[0].__name__ == 'TwistedEdwardsCurveFp':
        twistedEdwardsCurves.append(c)
    elif c.__bases__[0].__name__ == 'EdwardsCurveFp':
        edwardsCurves.append(c)
    elif c.__bases__[0].__name__ == 'MontgomeryCurveFp':
        montgomeryCurves.append(c)
    elif c.__bases__[0].__name__ == 'KoblitzCurveFp':
        koblitzCurves.append(c)
    else:
        pass # ignore other subclassed curves, so far they are all duplicates

allCurves = smallWeierstrassCurves + koblitzCurves + twistedEdwardsCurves + edwardsCurves + montgomeryCurves


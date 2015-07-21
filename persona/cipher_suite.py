#!/usr/bin/env python
""" cipher_suite.py
        
    Paul A. Lambert 2015
"""
from hashlib import sha256 as SHA256
from cryptopy.ecc.curves import NIST_P256, SECP_256k1
from cryptopy.cipher.aes_siv import AES_SIV

from cryptopy.cipher.common import string_to_int, int_to_string

"""
 - SEP1 Compressed
 - SEP1 XY
 - Raw XY
 - Raw X Only
 - X Only Little Endian
 - BaseXX any of above
 """
class PointSerialize( object ): pass

def SEP1_from_octets( curve, octets ):
    """ Convert octets to a point on the curve
        First octet indicates compressed or not
        and if compressed provides y mod 2
    """
    l = curve.coord_size
    if octets[0] == '\04': # uncompressed
        assert len( octets ) == 2*l+1
        x = string_to_int( octets[1:l+1] )
        y = string_to_int( octets[l+1:] )
        point = curve.point( x, y )
    else:
        assert len( octets ) == l+1
        yp = ord( octets[0] ) - 2
        assert (yp == 0) or (yp == 1)
        x = string_to_int( octets[1:l+1] )
        # y = ...
        # ...
    point = curve.point( x, y )
    assert curve.is_valid( point )
    return point
        

class Raw_XY( PointSerialize ):
    """ Point represented as BigEndian x and y coordinates """
    def to_octets( self, point ):
        """ Encode point as x & y Bigendian """
        l = point.curve.coord_size
        x_octets = int_to_string( point.x, padto=l )
        y_octets = int_to_string( point.y, padto=l )
        return x_octets + y_octets

    def from_octets( self, curve, octets ):
        """ Convert octets to a point on the curve """
        l = curve.coord_size
        assert len( octets ) == 2*l
        x = string_to_int( octets[0:l] )
        y = string_to_int( octets[l:] )
        point = curve.point( x, y )
        assert curve.is_valid( point )
        return point


class SEP1_Compressed( PointSerialize ):
    """ Point represented as BigEndian x and single bit for y """
    def to_octets( self, point ):
        """ Encode point """
        l = point.curve.coord_size
        x_octets = int_to_string( point.x, padto=l )
        yp = point.y % 2
        if yp == 0:
            octet_Y = '\02'
        else:
            octet_Y = '\03'
        return octet_Y + x_octets

    def from_octets( self, curve, octets ):
        """ Convert x coord octets to a point on the curve """
        assert octets[0] <> '\04' # not uncompressed
        return SEP1_from_octets( curve, octets )
    
class SEP1_Uncompressed( PointSerialize ):
    """ """
    def to_octets( self, point ):
        """ Encode point as x & y Bigendian """
        l = point.curve.coord_size
        x_octets = int_to_string( point.x, padto=l )
        y_octets = int_to_string( point.y, padto=l )
        return '\04' + x_octets + y_octets
    
    def from_octets( self, curve, octets ):
        """ Convert uncompressed octets to a point on the curve
        """
        assert octets[0] == '\04' # one byte indicating uncompressed
        return SEP1_from_octets( curve, octets )
    
class X_Only_Little_Endian( PointSerialize ): pass # to do
class X_Only( PointSerialize ): pass # to do



class CipherSuite( object ):
    """ Bundle of cryptographic algorithms and parameters
    """
    def __init__(self):
        """ """
        # use class name as suite text name for any display
        self.cipher_suite_name = self.__class__.__name__
    
    def hashUaid( self, publicKeyOctets ):
        """ Calcuate unique identififer from an octetstring holding the public key
            The format of the publicKeyOctets may be compresed or not
            based on the CipherSuite PubKeyEncoding.
            Default is 16 octets of hash defined for cipher suite
        """
        # default consruction - overload to change
        return self.Hash('uaid' + self.id + publicKeyOctets ).digest()[0:16]
    
    def pub_key_to_octets( self, publicKeyValue ):
        """ Convert the public key to octets using KeySerialize """
        to_octets = self.PubKeyEncoding().to_octets
        return to_octets( publicKeyValue )

class Suite_01( CipherSuite ):
    """ A Suite B compatible Cipher Suite using NIST P256 curve """
    id = '\01\01'
    Group = NIST_P256
    PubKeyEncoding = SEP1_Compressed
    Hash  = SHA256
    AeadCipher = AES_SIV
    
    
    
def BitcoinKeyHash( object ):
    print 'overloaded'
    pass # stubbed


class Bitcoin_Suite( CipherSuite ):
    """ A CipherSUite compatible with Bitcoin """
    id = '\01\02'
    Group = SECP_256k1
    Hash  = SHA256
    AeadCipher = AES_SIV
    hashUaid = BitcoinKeyHash
    
    


    
    








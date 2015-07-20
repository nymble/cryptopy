#!/usr/bin/env python
""" cipher_suite.py
        
    Paul A. Lambert 2015
"""
from hashlib import sha256 as SHA256
from cryptopy.ecc.curves import NIST_P256, SECP_256k1
from cryptopy.cipher.aes_siv import AES_SIV


class PointSerialize( object ): pass
class Raw_XY( PointSerialize ):
    def to_octets( self, point ):pass
class X_Only( PointSerialize ):
    pass
class SEP1_Compressed( PointSerialize ):
    pass
class SEP1_Uncompressed( PointSerialize ):
    pass
class X_Only_Little_Endian( PointSerialize ):
    pass

class CipherSuite( object ):
    """ Bundle of cryptographic algorithms and parameters
    """
    def __init__(self):
        
        # use class name as suite text name for any display
        self.cipher_suite_name = self.__class__.__name__
    
    def HashUaid( self, publicKeyOctets ):
        """ Calcuate a  from an octetstring holding the public key
            The format of the publicKeyOctets may be compresed or not
            based on the CipherSuite PubKeyEncode.
            Default is 16 octets of hash defined for cipher suite
        """
        return self.Hash('uaid' + self.id + publicKeyOctets )[0:16]
    

class Suite_01( CipherSuite ):
    """ A Suite B compatible Cipher Suite using NIST P256 curve """
    cipher_suite_id = 0x0101
    Group = NIST_P256
    KeySerialize = SEP1_Compressed
    Hash  = SHA256
    AeadCipher = AES_SIV
    
    
class BitcoinKeyHash: pass # stubbed


class Bitcoin_Suite( CipherSuite ):
    """ A CipherSUite compatible with Bitcoin """
    cipher_suite_id = 0x0102
    Group = SECP_256k1
    Hash  = SHA256
    AeadCipher = AES_SIV
    HashUaid = BitcoinKeyHash
    
    


    
    








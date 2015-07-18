#!/usr/bin/env python
""" public_key.py
        
    Paul A. Lambert 2015
"""
__all__ = ['PublicKey', 'PublicKeyPair']

class Eon: pass # serialization stubbed for now

class PublicKey( Eon ):
    """ Public keys are assoicated with a CipherSuite that determines
        the algorithms and encodings used with the key.
    """
    def __init__( self, cipherSuite, keyValue ):
        self.cipherSuite = cipherSuite
        assert cipherSuite.validKey( keyValue )
        self.publicKeyValue = keyValue
        self.uaid = cipherSuite.hashUaid( self )
    
    def validate( self, data, signature ):
        """ Validate a signature using this public key. """
        return self.cipherSuite.validate( self.publicKeyValue, data, signature )
    
    def decrypt( self, cipherText ):
        """ Decrypts the cipherText and returns a opaque octet string """
        plainText = self.cipherSuite.pubKeyDecrypt( self.publicKeyValue, cipherText )
        return plainText
    
   
class PublicKeyPair( PublicKey ):
    """ Public keys are created using the mechanisms defined by the Cipher Suite.
    """
    def __init__( self, cipherSuite ):
        self.cipherSuite = cipherSuite
        self.__secret = cipherSuite.newSecret()
        self.publicKeyValue = cipherSuite.calculatePublicKey( self )
        self.uaid = cipherSuite.hashUaid( self )
        
    def sign( self, data ):
        """ Sign data using the private key. Result is an opaque octet string.
        """
        return self.cipherSuite.sign( self, data )

    def encrypt( self, plainText ):
        """ Encrypts the plainText and returns an opaque octet string """
        cipherText = self.cipherSuite.pubKeyDecrypt( self.__secret, plainText )
        return cipherText        
           
           









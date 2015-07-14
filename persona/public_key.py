#!/usr/bin/env python
""" public_key.py
        
    Paul A. Lambert 2015
"""
class Eon: pass # serialization stubbed for now

class PublicKey( Eon ):
    """ Public keys are assoicated with a CipherSuite that determines
        the algorithms and encodings used with the key.
    """
    def __init__( self, cipherSuite, keyValue ):
        self.cipherSuite = cipherSuite
        self.publicKeyValue = keyValue
        assert cipherSuite.validKey( key )
        self.has = {}   # set of attributes of the key
        self.has['uaid'] = cipherSuite.hashUaid( self )
    
    def validate( self, data, signature ):
        """ Validate a signature using this key. """
        return self.cipherSuite.validate( self.key, data, signature )
    
   
class PublicKeyPair( PublicKey ):
    """ Public keys are created using the mechanisms defined by the Cipher Suite.
    """
    def __init__( self, cipherSuite ):
        self.cipherSuite = cipherSuite
        self.__secret = cipherSuite.newSecret()
        self.publicKeyValue = cipherSuite.calculatePublicKey( self )
        self.has = {}   # set of attributes of the key
        self.has['uaid'] = cipherSuite.hashUaid( self )
        
    def sign( self, data ):
        """ Sign data using this public key
            Result is an opaque octet string.
        """
        return self.cipherSuite.sign( data )

           
           
           









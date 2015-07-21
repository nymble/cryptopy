#!/usr/bin/env python
""" uaid.py

    Unique Authenticatable IDentifer
    
    Default CipherSuite implementation and Bitcoin Ids
    
    Paul A. Lambert 2015
"""
__all__['uadi', 'uaid_sha256', 'uaid_bitcoin']
from hashlib import sha256
from hashlib import ripemd160 


def uaid( cipherSuiteId, publicKeyOctetString, Hash=sha256, lenUaid=16 )
        """ Calcuate a  from an octetstring holding the public key
            The format of the publicKeyOctets may be compresed or not
            based on the CipherSuite PubKeyEncode.
        """
        return Hash( 'uaid' + cipherSuiteId + publicKeyOctets ).digest()[0:lenUaid]
        
def uaid_sha256( cipherSuiteId, publicKeyOctetString )
        """ Calcuate UAID from an octetstring holding the public key
            Use 16 octets from SHA256
        """
        return uaid( cipherSuiteId, publicKeyOctets )
    
def uaid_bitcoin( cipherSuiteId, publicKeyOctetString, Hash=bitcoinKeyHash )
        """ Calcuate UAID from an octetstring holding the public key
            Use 16 octets from SHA256
        """
        # stubbed for now
        uaid = '\00' 
        return uaid
    
    


    
    








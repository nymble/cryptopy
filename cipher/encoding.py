#!/usr/bin/env python
""" encoding.py

    encoding.py (c) 2013 by Paul A. Lambert
    
    encoding.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""
from __future__ import division   # ensure division returns float value 
__all__ = ['int_to_string', 'string_to_int', 'b27encode', 'b27decode',
           'b85encode', 'b85decode', 'b94encode', 'b94decode']


def int_to_string( long_int, padto=None ):
    """ Convert integer long_int into a string of bytes, as per X9.62.
        If 'padto' defined, result is zero padded to this length.
    """
    if long_int > 0:
        octet_string = ""
        while long_int > 0:
            long_int, r = divmod( long_int, 256 )
            octet_string = chr( r ) + octet_string
    elif long_int == 0:
        octet_string = chr(0)
    else:
        raise ValueError('int_to-string unable to convert negative numbers')
        
    if padto:
        padlen = padto - len(octet_string)
        assert padlen >= 0
        octet_string = padlen*chr(0) + octet_string
    return octet_string

def string_to_int( octet_string ):
    """ Convert a string of bytes into an integer, as per X9.62. """
    long_int = 0L
    for c in octet_string:
        long_int = 256 * long_int + ord( c )
    return long_int

def base_N_encode(octets, alphabet):
    """Encode a octet string using the provided alphabet. Base is len(alphabet)
       The octets are converted to a long integer, so this is NOT
       an eficient method for long strings (e.g over 32 charaters)
    """
    long_int = string_to_int( octets )   
    text_out = ''
    while long_int > 0: 
        long_int, remainder = divmod(long_int, len(alphabet))
        text_out = alphabet[remainder] + text_out
    return text_out

def base_N_decode(text, alphabet, padto=None):
    """Decode a text string 's' using the alphabet. Base 'N' is len(alphabet)
       Output octet string is padded if 'padto' length is set
    """
    base = len(alphabet)   
    long_int = 0L
    for c in text:
        long_int = base * long_int + alphabet.index(c)
    text_out = int_to_string(long_int, padto)
    return text_out

_b27chars = 'ABCDEFGHJKMNPQRTWXYZ2346789'
def b27encode(octet_string):
    """Encode a octet string using 27 characters. """
    return base_N_encode(octet_string, _b27chars )
    
def b27decode(text_string, padto=None):
    """Decode a text string 's' using 27 characters. """
    return base_N_decode(text_string, _b27chars )

_b85chars = "0123456789" \
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
            "abcdefghijklmnopqrstuvwxyz" \
            "!#$%&()*+-;<=>?@^_`{|}~"

def b85encode(octet_string):
    """Encode a octet_string using 85 characters.
       Compliant with RFC1924
       Intended originally for only 128 bit IPv6 addresses
       Longer or shorter strings will work.
    """
    return base_N_encode(octet_string, _b85chars )

def b85decode(text_string, padto=None):
    """Decode a text string 's' using 85 character alphabet. """
    return base_N_decode(text_string, _b85chars )
    
ascii_printable = ''.join( [chr(i) for i in range(33,127)] )    
def b94encode(octet_string):
    """Encode a octet_string using all ASCII non-space printable characters. """
    return base_N_encode(octet_string, ascii_printable )

def b94decode(text_string, padto=None):
    """Decode a text string using all ASCII non-space printable characters. """
    return base_N_decode(text_string, ascii_printable )    
    
if __name__ == '__main__':
    """ Examples of text encodings for 128 bit and 48 bits (USID and SID)
    """
    # calculate a USID and SID and use to demonstrate encodings
    service_name = 'service.name.example'
    from hashlib import sha256
    hash_value = sha256( service_name  ).digest()
    usid = hash_value[0:16]        # USIDs are 16 octets of the hash value
    service_id = hash_value[0:6]   # SIDs are 6 octets of the hash value
    
    print 'service name:    ', service_name
    print 'hash value:      ', hash_value.encode('hex')
    print 'usid:            ', usid.encode('hex')
    print 'usid b27         ', b27encode(usid)
    assert b27decode(b27encode(usid)) == usid  # test decode b27
    print 'usid b85         ', b85encode(usid)
    print 'usid b94:        ', b94encode(usid)    
    print 'service id:      ', service_id.encode('hex')
    print 'service id b27:  ', b27encode(service_id)
    print 'service id b85:  ', b85encode(service_id)
    print 'service id b94:  ', base_N_encode(service_id, ascii_printable)
 
 
    # Basic tests of encoding and decoding functions
    assert b27decode(b27encode(usid)) == usid  # test encode/decode b27
    assert b85decode(b85encode(usid)) == usid  # test encode/decode b85
    assert b94decode(b94encode(usid)) == usid  # test encode/decode b94
    # Test conformance of to RFC1924 definition of base85
    # RFC1924 example of a IPv6 address ->  1080:0:0:0:8:800:200C:417A
    rfc1924_example = int_to_string( 0x108000000000000000080800200c417a )
    assert b85encode(rfc1924_example) == '4)+k&C#VzJ4br>0wv%Yp'
    

    

    
    

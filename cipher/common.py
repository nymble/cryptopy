""" cryptopy.cipher.common

    Common utility routines for crypto modules

    common.py (c) 2002 by Paul A. Lambert

    common.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""

def xor(a,b):
    """ XOR two strings of same length"""
    assert len(a)==len(b)
    x = []
    for i in range(len(a)):
            x.append( chr(ord(a[i])^ord(b[i])))
    return ''.join(x)
      
def xor_min(a,b):
    """ XOR two strings """
    x = []
    for i in range(min(len(a),len(b))):
            x.append( chr(ord(a[i])^ord(b[i])))
    return ''.join(x)

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
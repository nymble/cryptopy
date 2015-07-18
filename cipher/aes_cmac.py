#!/usr/bin/env python
""" aes_cmac.py

    NIST, Special Publication 800-38B, "Recommendation for
    Block Cipher Modes of Operation: The CMAC Mode for
    Authentication", May 2005.
    http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
    
    RFC 4493 - http://www.rfc-editor.org/rfc/rfc4493.txt
    
    aes_cmac.py (c) 2013 by Paul A. Lambert

    aes_cmac.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""
from Crypto.Cipher import AES
from encoding import int_to_string, string_to_int

def aes_cmac(key, M, CIPH=AES):
    """ AES CMAC - Cipher based Authentication Code"""
    ciph = CIPH.new(key)
    block_size = ciph.block_size
    assert block_size == 16 # only 128 bit (16 octet) blocks supported!!
    
    k1, k2 = subkey(key)
    blocks, leftover = divmod(len(M), block_size)
  
    if leftover == 0 and blocks > 0:         # if last block is a complete block
        M_p = M[:(blocks-1)*block_size] + xor( M[(blocks-1)*block_size:], k1 )
    else:                                   
        M_p = M[:(blocks)*block_size] + xor( pad( M[(blocks)*block_size:] ), k2 )
    
    x = block_size*'\x00' # block of zeros
    for i in range( len(M_p)/block_size ):
        x   = ciph.encrypt( xor( x, M_p[(i)*block_size:][:16]) )

    return x

def subkey(key, CIPH=AES):
    """ CMAC subkey generation """
    ciph = CIPH.new(key)
    block_size = ciph.block_size
    assert block_size == 16      # only 128 bit blocks (16 octet) supported
    
    el = string_to_int( ciph.encrypt('\x00'*block_size) )

    if el & 0x80000000000000000000000000000000 == 0: 
        k1 = (el<<1)
    else:      # xor only if high bit set
        k1 = ((el<<1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) ^ 0x87 

    if k1 & 0x80000000000000000000000000000000 == 0: 
        k2 = (k1<<1)
    else:      # xor only if high bit set
        k2 = ((k1<<1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) ^ 0x87 

    k1 = int_to_string(k1)
    k2 = int_to_string(k2)
    return k1, k2

def pad(octet_string, block_size=16):
    """ Pad a string to a multiple of block_size octets"""
    pad_length = block_size - len(octet_string)
    return octet_string + b'\x80' + (pad_length-1)*b'\x00'


def xor(a,b):
    """ XOR two strings of same length"""
    assert len(a) == len(b)
    x = []
    for i in range(len(a)):
            x.append( chr(ord(a[i])^ord(b[i])))
    return ''.join(x)



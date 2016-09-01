#!/usr/bin/env python
""" aes_siv.py
    
    AES_SIV
    
    Usage:
        cipher = AES_SIV( key )
        ad_list = [ 'ab, 'cd']  # listt of additional data to integrity protect
        cipher_text = cipher.encrypt( message, ad_list )
        #
        recovered_plain_text = cipher.decrypt( message, ad_list )
        
    http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    
    aes_siv.py (c) 2013 by Paul A. Lambert

    aes_siv.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""
#__all__ =  [ 'AES_SIV', 'siv_encrypt', 'siv_decrypt' ]

from Crypto.Cipher import AES
from aes_cmac import aes_cmac
from common import xor
from encoding import int_to_string, string_to_int

def dbl(s):
    """ The SIV 'doubling' operation on a 16 octet input string """
    assert len(s)==16
    d = string_to_int(s)
    if d & 0x80000000000000000000000000000000: # xor only if high bit set
        d = ((d<<1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) ^ 0x87
    else:
        d = (d<<1)
    return int_to_string(d,  padto=16)

def pad(octet_string, block_size=16):
    """ Pad a string to a multiple of block_size octets """
    pad_length = block_size - len(octet_string)
    return  octet_string + '\x80' + '\x00'*(pad_length-1)

def s2v(key, ad_list, block_size=16):
    """ SIV mode s2v integrity and iv generation
        ad_list is a list of strings that are included in the integrity check
        """
    if len(ad_list) == 0:
        return aes_cmac(key, (block_size-1)*"\00"+"\01")
    d = aes_cmac(key, block_size*"\00")
    for i in range( len(ad_list)-1 ):
        d = xor( dbl(d), aes_cmac(key, ad_list[i]) )
    
    if len( ad_list[-1] ) >= block_size: # last item
        t = ad_list[-1][:-block_size] + xor( ad_list[-1][-block_size:], d) # xorend
    else:
        t = xor( dbl(d), pad(ad_list[-1]) )
    return aes_cmac(key, t)

def siv_encrypt(key, pt, ad_list):
    """ """
    blksize=16 # AES block size
    keysize = len(key)/2  # SIV key is two keys of equal size for CMAC and CTR
    key1 = key[0:keysize]      # leftmost half of key
    key2 = key[-keysize:]      # rightmost half of key
    ad = ad_list + [pt]
    iv = s2v(key1, ad )
    q = string_to_int(iv) & 0xffffffffffffffff7fffffff7fffffffL # clear 32nd and 64th bits
    m = (len(pt)+blksize-1)/blksize
    x = ''
    aes = AES.new(key2, AES.MODE_ECB)
    for i in range(m):
        x = x + aes.encrypt( int_to_string(q+i, padto=blksize) )
    x = x[0:len(pt)]  #  trim x to leftmost to match plain text which may not be block aligned
    ct = xor(pt,x)
    return iv + ct    # concatenate initialization vector and cipher text

def siv_decrypt(key, encrypted_string, ad_list):
    """ """
    blksize = 16 # AES block size
    iv = encrypted_string[:16]    # leftmost 128 bits (16 octets)
    ct = encrypted_string[16:]
    keysize = len(key)/2  # SIV key is two keys of equal size for CMAC and CTR
    key1 = key[0:keysize]      # leftmost half of key
    key2 = key[-keysize:]      # rightmost half of key
    q = string_to_int(iv)  & 0xffffffffffffffff7fffffff7fffffffL
    m = (len(ct)+blksize-1)/blksize
    x = ''
    aes = AES.new(key2, AES.MODE_ECB)
    for i in range(m):
        x = x + aes.encrypt( int_to_string(q+i, padto=blksize) )
    x = x = x[0:len(ct)]
    pt = xor(ct,x)
    ad = ad_list + [pt]
    t = s2v( key1, ad )
    if t == iv:
        return pt
    else:
        raise 'SIV Integrity Check Error'

class AES_SIV(object):
    """ An object wrapper for AES-SIV """
    def __init__(self, key):
        self.__key = key
        
    def encrypt(self, pt, ad_list):
        return siv_encrypt(self.__key, pt, ad_list)
    
    def decrypt(self, ct, ad_list):
        return siv_decrypt(self.__key, ct, ad_list)
    



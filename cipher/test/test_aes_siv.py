#!/usr/bin/env python
""" test_aes_siv.py

    Tests for AES SIV
    Copyright (c) 2013 by Paul A. Lambert   
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))   
    from aes_siv import siv_encrypt, siv_decrypt
else:
    from ..aes_siv import siv_encrypt, siv_decrypt


""" Test Vectors from RFC 5297 """

# A.1. Deterministic Authenticated Encryption Example
key = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
key = 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'.decode('hex')
ad  = '101112131415161718191a1b1c1d1e1f2021222324252627'.decode('hex')
pt  = '112233445566778899aabbccddee'.decode('hex')
iv_ct = siv_encrypt(key, pt, [ad])
assert iv_ct == '85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c'.decode('hex')
pt2 = siv_decrypt(key, iv_ct, [ad])
assert pt == pt2
print "aes_siv  A.1. pass"

# A.2. Nonce-based Authenticated Encryption Example
key = '7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f'.decode('hex')
ad1 = '00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100'.decode('hex')
ad2 = '102030405060708090a0'.decode('hex')
nonce = '09f911029d74e35bd84156c5635688c0'.decode('hex')
ad = [ad1, ad2, nonce]
pt = '7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553'.decode('hex')
iv_ct = siv_encrypt(key, pt, ad)
assert iv_ct == '7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d'.decode('hex')
pt2 = siv_decrypt(key, iv_ct, ad)  
assert pt == pt2
print "aes_siv  A.2. pass"

# Test edge conditions - zero lengths

# zero pt, multiple sd
pt = ''
iv_ct = siv_encrypt(key, pt, ad)
pt2 = siv_decrypt(key, iv_ct, ad)
assert pt == pt2

iv_ct = siv_encrypt(key, 'a', [])
pt2 = siv_decrypt(key, iv_ct, [])
assert 'a' == pt2

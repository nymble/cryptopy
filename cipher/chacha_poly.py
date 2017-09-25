#!/usr/bin/env python
""" chacha_poly.py

    A pure python implementation of the ChaCha stream cipher
    and Poly1305 MAC based on RFC 7539. Text from the RFC is 
    used as comments of this reference implementation.
    
    The implementtaion supports encryption of large files 
    with incremental encryption.

    [RFC7539] Y. Nir Y., Langley A.,
              "ChaCha20 and Poly1305 for IETF Protocols", May 2015,
              <https://tools.ietf.org/html/rfc7539>

    [ChaCha]  Bernstein, D., "ChaCha, a variant of Salsa20", January
              2008, <http://cr.yp.to/chacha/chacha-20080128.pdf>.

    [Poly1305] Bernstein, D., "The Poly1305-AES message-authentication
               code", March 2005,
               <http://cr.yp.to/mac/poly1305-20050329.pdf>.
               
    Paul A. Lambert 2017
"""
from struct import pack, unpack
from os import urandom
from math import ceil
import binascii

def quarter_round(a, b, c, d):
    """ The ChaCha quarter round.

        The basic operation of the ChaCha algorithm is the quarter round.  It
        operates on four 32-bit unsigned integers, denoted a, b, c, and d.
        The operation is as follows (in C-like notation):

        1.  a += b; d ^= a; d <<<= 16;
        2.  c += d; b ^= c; b <<<= 12;
        3.  a += b; d ^= a; d <<<= 8;
        4.  c += d; b ^= c; b <<<= 7;
    """
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 16) & 0xFFFFFFFF) | (d >> 16)

    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = ((b << 12) & 0xFFFFFFFF) | (b >> 20)

    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = ((d << 8) & 0xFFFFFFFF) | (d >> 24)

    c = (c + d)  & 0xFFFFFFFF
    b ^= c
    b = ((b << 7) & 0xFFFFFFFF) | (b >> 25)
    return a, b, c, d

def q_round(state, i, j, k, l):
    """ Use the quarter round function on the ChaCha state matrix
        using the provided index values for the matrix value locations.
    """
    a, b, c, d = state[i], state[j], state[k], state[l]
    state[i], state[j], state[k], state[l] = quarter_round(a, b, c, d)

def inner_block(state):
    """ Perform two rounds of transformation on the state matrix.
        """
    # Column rounds
    q_round(state, 0, 4,  8, 12)
    q_round(state, 1, 5,  9, 13)
    q_round(state, 2, 6, 10, 14)
    q_round(state, 3, 7, 11, 15)
    # Diagonal rounds
    q_round(state, 0, 5, 10, 15)
    q_round(state, 1, 6, 11, 12)
    q_round(state, 2, 7,  8, 13)
    q_round(state, 3, 4,  9, 14)

class ChaCha(object):
    """
        chacha = ChaCha(key) # urandom used for nonce
        cipher_text = chacha.encrypt(plain_text)

        or

        chacha = ChaCha(key, nonce, initial_block_counter=1)
        cipher_text = chacha.encrypt(plain_text)

    """
    block_size = 64

    def initialize(self, key, nonce, block_counter):
        """ The ChaCha20 state is initialized as follows:

            cccccccc  cccccccc  cccccccc  cccccccc
            kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
            kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
            bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

            c=constant k=key b=block_counter n=nonce
        """
        self.state = 16*[0]

        # The first four words (0-3) are constants:
        self.state[ 0] = 0x61707865
        self.state[ 1] = 0x3320646e
        self.state[ 2] = 0x79622d32
        self.state[ 3] = 0x6b206574

        # The next eight words (4-11) are taken from the 256-bit key by
        # reading the bytes in little-endian order, in 4-byte chunks.
        k = unpack('<IIIIIIII', key)
        self.state[ 4] = k[0]
        self.state[ 5] = k[1]
        self.state[ 6] = k[2]
        self.state[ 7] = k[3]
        self.state[ 8] = k[4]
        self.state[ 9] = k[5]
        self.state[10] = k[6]
        self.state[11] = k[7]

        # Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
        # word is enough for 256 gigabytes of data.
        self.state[12] = block_counter

        # Words 13-15 are a nonce, which should not be repeated for the same
        # key.  The 13th word is the first 32 bits of the input nonce taken
        # as a little-endian integer, while the 15th word is the last 32
        # bits.
        n = unpack('<III', nonce)
        self.state[13] = n[0]
        self.state[14] = n[1]
        self.state[15] = n[2]

    def chacha20_block(self):
        """ The ChaCha 'block' function.
            A key stream of 256 bytes is returned as
            a function of the current state matrix.
        """
        working_state = list(self.state) # a copy of state

        for i in range(10):
            inner_block(working_state)   # 2 iterations per inner block
        # out_state = state + working_state
        out_state = [ (s+ws)&0xFFFFFFFF for s,ws in zip(self.state, working_state) ]
        # return serialize(out_state) for use as key stream
        return ''.join([ pack('<I', word) for word in out_state ])


    def encrypt(self, plain_text, more=False):
        """ Encrypt plaintext with key, nonce and initial counter
            set by object initialization.
            When 'more' is True, additional encryption operations
            will continue with prior counter, nonce value. This
            is to support large file encryption.
        """
        if self.nonce_used: raise ValueError("Nonce reused")

        blocks, remainder = divmod(len(plain_text), 64)
        if more and remainder>0:
            raise ValueError("'more' only valid for exact multiples of block size")
        if remainder > 0:
            blocks += 1

        counter = self.state[12]
        encrypted_message = []

        for j in range(blocks):
            key_stream = self.chacha20_block()
            self.state[12] += 1  # increment counter
            #block = plain_text[ j*64 : (j+1)*64 ]
            block = plain_text[ j*64 : ]  # zip below stops at one block

            # encrypted_message +=  block ^ key_stream
            encrypted_block = [chr(ord(b_char)^ord(k_char)) for b_char, k_char in zip(block, key_stream)]
            encrypted_message.extend( encrypted_block )

        if not more:
            self.nonce_used = True
        return ''.join(encrypted_message) # converted from list of chars to octet string

    def decrypt(self, plain_text, more=False):
        """ Decryption is done in the same way as encryption.
        """
        return self.encrypt( plain_text )

    def __init__(self, key, nonce=None, initial_block_counter=0):
        """ ChaCha object initialization """
        if nonce:
            self.nonce = nonce
        else:
            nonce = urandom(12)
        self.nonce = nonce
        self.nonce_used = False # track nonce usage to prevent inappropriate reuse
        self.initialize( key, nonce, initial_block_counter )

class Poly1305(object):
    """ 2.5.  The Poly1305 Algorithm
    
    Poly1305 is a one-time authenticator designed by D. J. Bernstein.
    Poly1305 takes a 32-byte one-time key and a message and produces a
    16-byte tag.  This tag is used to authenticate the message.
    
    The original article ([Poly1305]) is titled "The Poly1305-AES
    message-authentication code", and the MAC function there requires a
    128-bit AES key, a 128-bit "additional key", and a 128-bit (non-
    secret) nonce.  AES is used there for encrypting the nonce, so as to
    get a unique (and secret) 128-bit string, but as the paper states,
    "There is nothing special about AES here.  One can replace AES with
    an arbitrary keyed function from an arbitrary set of nonces to
    16-byte strings."
    
    Regardless of how the key is generated, the key is partitioned into
    two parts, called "r" and "s".  The pair (r,s) should be unique, and
    MUST be unpredictable for each invocation (that is why it was
    originally obtained by encrypting a nonce), while "r" MAY be
    constant, but needs to be modified as follows before being used: ("r"
    is treated as a 16-octet little-endian number):
    
    o  r[3], r[7], r[11], and r[15] are required to have their top four
    bits clear (be smaller than 16)
    
    o  r[4], r[8], and r[12] are required to have their bottom two bits
    clear (be divisible by 4)
    
    The following  code clamps "r" to be appropriate:
    
    The "s" should be unpredictable, but it is perfectly acceptable to
    generate both "r" and "s" uniquely each time.  Because each of them
    is 128 bits, pseudorandomly generating them (see Section 2.6) is also
    acceptable.
    
    The inputs to Poly1305 are:
    
    o  A 256-bit one-time key
    
    o  An arbitrary length message
    
    The output is a 128-bit tag.
    
    2.5.1.  The Poly1305 Algorithms in Python
    """

def clamp(r):
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    return r
      
def poly1305_mac(msg, key):
    """ """
    r = le_bytes_to_num(key[0:16])
    r = clamp(r)
    s = le_bytes_to_num(key[16:32])
    a = 0
    p = (1<<130)-5
    blocks, remainder = divmod( len(msg), 16 )
    for i in range( blocks ):
        n = le_bytes_to_num(msg[ i*16 : (i+1)*16 ] + chr(0x01) )
        a += n
        a = (r * a) % p
    
    if remainder: # proces final partial block
        n = le_bytes_to_num( msg[ blocks*16 : ] + chr(0x01) )
        a += n
        a = (r * a) % p

    a += s
    return num_to_16_le_bytes(a)
         
def le_bytes_to_num(bytes):
    """ Convert little-endian bytes to number """
    return int(binascii.hexlify(bytes[::-1]), 16)

def num_to_16_le_bytes(num):
    """ Convert number to little-endian octet string """
    return ''.join(map(lambda i: chr(0xff & (num >> 8*i)), range(16)))


    


#!/usr/bin/env python
""" chacha_poly.py

A pure python implementation of the ChaCha stream cipher, the
Poly1305 MAC, and ChaCha20 AEAD based on RFC 7539.
Text from the RFC is used as comments in this reference implementation.

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

"""
2.  The Algorithms

   The subsections below describe the algorithms used and the AEAD
   construction.
"""
def chacha_q_round(a, b, c, d):
    """
2.1.  The ChaCha Quarter Round

   The basic operation of the ChaCha algorithm is the quarter round.  It
   operates on four 32-bit unsigned integers, denoted a, b, c, and d.
   The operation is as follows:
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

def quarter_round(state, x, y, z, w):
    """
2.2.  A Quarter Round on the ChaCha State

   The ChaCha state does not have four integer numbers: it has 16.  So
   the quarter-round operation works on only four of them -- hence the
   name.  Each quarter round operates on four predetermined numbers in
   the ChaCha state.  We will denote by QUARTERROUND(x,y,z,w) a quarter-
   round operation on the numbers at indices x, y, z, and w of the
   ChaCha state when viewed as a vector.  For example, if we apply
   QUARTERROUND(1,5,9,13) to a state, this means running the quarter-
   round operation on the elements marked with an asterisk, while
   leaving the others alone:

      0  *a   2   3
      4  *b   6   7
      8  *c  10  11
     12  *d  14  15

   Note that this run of quarter round is part of what is called a
   "column round".
"""
    a, b, c, d = state[x], state[y], state[z], state[w]
    state[x], state[y], state[z], state[w] = chacha_q_round(a, b, c, d)

"""
2.3.  The ChaCha20 Block Function

   The ChaCha block function transforms a ChaCha state by running
   multiple quarter rounds.

   The inputs to ChaCha20 are:

   o  A 256-bit key, treated as a concatenation of eight 32-bit little-
      endian integers.

   o  A 96-bit nonce, treated as a concatenation of three 32-bit little-
      endian integers.

   o  A 32-bit block count parameter, treated as a 32-bit little-endian
      integer.

   The output is 64 random-looking bytes.

   The ChaCha algorithm described here uses a 256-bit key.  The original
   algorithm also specified 128-bit keys and 8- and 12-round variants,
   but these are out of scope for this document.  In this section, we
   describe the ChaCha block function.

   Note also that the original ChaCha had a 64-bit nonce and 64-bit
   block count.  We have modified this here to be more consistent with
   recommendations in Section 3.2 of [RFC5116].  This limits the use of
   a single (key,nonce) combination to 2^32 blocks, or 256 GB, but that
   is enough for most uses.  In cases where a single key is used by
   multiple senders, it is important to make sure that they don't use
   the same nonces.  This can be assured by partitioning the nonce space
   so that the first 32 bits are unique per sender, while the other 64
   bits come from a counter.

   ChaCha20 runs 20 rounds, alternating between "column rounds" and
   "diagonal rounds".  Each round consists of four quarter-rounds, and
   they are run as follows.  Quarter rounds 1-4 are part of a "column"
   round, while 5-8 are part of a "diagonal" round:
    """

def inner_block(state):
    """ Inner block function
    """
    # Column rounds
    quarter_round(state, 0, 4,  8, 12)
    quarter_round(state, 1, 5,  9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)
    # Diagonal rounds
    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7,  8, 13)
    quarter_round(state, 3, 4,  9, 14)
    """
   At the end of 20 rounds (or 10 iterations of the above list), we add
   the original input words to the output words, and serialize the
   result by sequencing the words one-by-one in little-endian order.

   Note: "addition" in the above paragraph is done modulo 2^32.  In some
   machine languages, this is called carryless addition on a 32-bit
   word.
    """


class ChaCha(object):
    """
        chacha = ChaCha(key) # urandom used for nonce
        cipher_text = chacha.encrypt(plain_text)

        or

        chacha = ChaCha(key, nonce, initial_block_counter=1)
        cipher_text = chacha.encrypt(plain_text)

    """
    block_size = 64

    def initialize(self, key, block_counter, nonce):
        """ The ChaCha20 state is initialized as follows:

            cccccccc  cccccccc  cccccccc  cccccccc
            kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
            kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
            bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

            c=constant k=key b=block_counter n=nonce
        """
        self.state = 16*[0]
        # The first four words (0-3) are constants:
        self.state[0:4] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

        # The next eight words (4-11) are taken from the 256-bit key by
        # reading the bytes in little-endian order, in 4-byte chunks.
        assert len(key) == 32
        self.state[4:12] = unpack('<IIIIIIII', key)

        # Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
        # word is enough for 256 gigabytes of data.
        self.state[12] = block_counter

        # Words 13-15 are a nonce, which should not be
        # repeated for the same key.
        assert len(nonce) == 12
        self.state[13:16] = unpack('<III', nonce)

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

    def encrypt(self, plain_text):
        """ Encrypt plaintext with key. The nonce and initial counter
            values were set by object initialization.
        """
        blocks, remainder = divmod(len(plain_text), 64)
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

        return ''.join(encrypted_message) # converted from list of chars to octet string

    def decrypt(self, plain_text):
        """ Decryption is done in the same way as encryption.
        """
        return self.encrypt( plain_text )

    def __init__(self, key, counter=0, nonce=None):
        """ Random nonce if not provided. """
        if not nonce:
            nonce = urandom(12)
        
        self.initialize( key, counter, nonce )

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

    The following code clamps "r" to be appropriate:

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

"""
    2.6.  Generating the Poly1305 Key Using ChaCha20

    As said in Section 2.5, it is acceptable to generate the one-time
    Poly1305 pseudorandomly.  This section defines such a method.

    To generate such a key pair (r,s), we will use the ChaCha20 block
    function described in Section 2.3.  This assumes that we have a
    256-bit session key for the Message Authentication Code (MAC)
    function, such as SK_ai and SK_ar in Internet Key Exchange Protocol
    version 2 (IKEv2) ([RFC7296]), the integrity key in the Encapsulating
    Security Payload (ESP) and Authentication Header (AH), or the
    client_write_MAC_key and server_write_MAC_key in TLS.  Any document
    that specifies the use of Poly1305 as a MAC algorithm for some
    protocol must specify that 256 bits are allocated for the integrity
    key.  Note that in the AEAD construction defined in Section 2.8, the
    same key is used for encryption and key generation, so the use of
    SK_a* or *_write_MAC_key is only for stand-alone Poly1305.

    The method is to call the block function with the following
    parameters:

    o  The 256-bit session integrity key is used as the ChaCha20 key.

    o  The block counter is set to zero.

    o  The protocol will specify a 96-bit or 64-bit nonce.  This MUST be
    unique per invocation with the same key, so it MUST NOT be
    randomly generated.  A counter is a good way to implement this,
    but other methods, such as a Linear Feedback Shift Register (LFSR)
    are also acceptable.  ChaCha20 as specified here requires a 96-bit
    nonce.  So if the provided nonce is only 64-bit, then the first 32
    bits of the nonce will be set to a constant number.  This will
    usually be zero, but for protocols with multiple senders it may be
    different for each sender, but should be the same for all
    invocations of the function with the same key by a particular
    sender.

    After running the block function, we have a 512-bit state.  We take
    the first 256 bits or the serialized state, and use those as the one-
    time Poly1305 key: the first 128 bits are clamped and form "r", while
    the next 128 bits become "s".  The other 256 bits are discarded.

    Note that while many protocols have provisions for a nonce for
    encryption algorithms (often called Initialization Vectors, or IVs),
    they usually don't have such a provision for the MAC function.  In
    that case, the per-invocation nonce will have to come from somewhere
    else, such as a message counter.

    2.6.1.  Poly1305 Key Generation in Python
"""
def poly1305_key_gen(key, nonce):
    counter = 0
    # block = chacha20_block(key,counter,nonce)
    block = ChaCha(key, counter, nonce).chacha20_block()
    return block[:32]

"""
2.7.  A Pseudorandom Function for Crypto Suites based on ChaCha/Poly1305

   Some protocols, such as IKEv2 ([RFC7296]), require a Pseudorandom
   Function (PRF), mostly for key derivation.  In the IKEv2 definition,
   a PRF is a function that accepts a variable-length key and a
   variable-length input, and returns a fixed-length output.  Most
   commonly, Hashed MAC (HMAC) constructions are used for this purpose,
   and often the same function is used for both message authentication
   and PRF.

   Poly1305 is not a suitable choice for a PRF.  Poly1305 prohibits
   using the same key twice, whereas the PRF in IKEv2 is used multiple
   times with the same key.  Additionally, unlike HMAC, Poly1305 is
   biased, so using it for key derivation would reduce the security of
   the symmetric encryption.

   Chacha20 could be used as a key-derivation function, by generating an
   arbitrarily long keystream.  However, that is not what protocols such
   as IKEv2 require.

   For this reason, this document does not specify a PRF and recommends
   that crypto suites use some other PRF such as PRF_HMAC_SHA2_256 (see
   Section 2.1.2 of [RFC4868]).

2.8.  AEAD Construction

   AEAD_CHACHA20_POLY1305 is an authenticated encryption with additional
   data algorithm.  The inputs to AEAD_CHACHA20_POLY1305 are:

   o  A 256-bit key

   o  A 96-bit nonce -- different for each invocation with the same key

   o  An arbitrary length plaintext

   o  Arbitrary length additional authenticated data (AAD)

   Some protocols may have unique per-invocation inputs that are not 96
   bits in length.  For example, IPsec may specify a 64-bit nonce.  In
   such a case, it is up to the protocol document to define how to
   transform the protocol nonce into a 96-bit nonce, for example, by
   concatenating a constant value.

   The ChaCha20 and Poly1305 primitives are combined into an AEAD that
   takes a 256-bit key and 96-bit nonce as follows:

   o  First, a Poly1305 one-time key is generated from the 256-bit key
      and nonce using the procedure described in Section 2.6.

   o  Next, the ChaCha20 encryption function is called to encrypt the
      plaintext, using the same key and nonce, and with the initial
      counter set to 1.

   o  Finally, the Poly1305 function is called with the Poly1305 key
      calculated above, and a message constructed as a concatenation of
      the following:

      *  The AAD

      *  padding1 -- the padding is up to 15 zero bytes, and it brings
         the total length so far to an integral multiple of 16.  If the
         length of the AAD was already an integral multiple of 16 bytes,
         this field is zero-length.

      *  The ciphertext

      *  padding2 -- the padding is up to 15 zero bytes, and it brings
         the total length so far to an integral multiple of 16.  If the
         length of the ciphertext was already an integral multiple of 16
         bytes, this field is zero-length.

      *  The length of the additional data in octets (as a 64-bit
         little-endian integer).

      *  The length of the ciphertext in octets (as a 64-bit little-
         endian integer).

   The output from the AEAD is the concatenation of:

   o  A ciphertext of the same length as the plaintext.

   o  A 128-bit tag, which is the output of the Poly1305 function.

   Decryption is similar with the following differences:

   o  The roles of ciphertext and plaintext are reversed, so the
      ChaCha20 encryption function is applied to the ciphertext,
      producing the plaintext.

   o  The Poly1305 function is still run on the AAD and the ciphertext,
      not the plaintext.

   o  The calculated tag is bitwise compared to the received tag.  The
      message is authenticated if and only if the tags match.

   A few notes about this design:

   1.  The amount of encrypted data possible in a single invocation is
       2^32-1 blocks of 64 bytes each, because of the size of the block
       counter field in the ChaCha20 block function.  This gives a total
       of 247,877,906,880 bytes, or nearly 256 GB.  This should be
       enough for traffic protocols such as IPsec and TLS, but may be
       too small for file and/or disk encryption.  For such uses, we can
       return to the original design, reduce the nonce to 64 bits, and
       use the integer at position 13 as the top 32 bits of a 64-bit
       block counter, increasing the total message size to over a
       million petabytes (1,180,591,620,717,411,303,360 bytes to be
       exact).

   2.  Despite the previous item, the ciphertext length field in the
       construction of the buffer on which Poly1305 runs limits the
       ciphertext (and hence, the plaintext) size to 2^64 bytes, or
       sixteen thousand petabytes (18,446,744,073,709,551,616 bytes to
       be exact).

   The AEAD construction in this section is a novel composition of
   ChaCha20 and Poly1305.  A security analysis of this composition is
   given in [Procter].

   Here is a list of the parameters for this construction as defined in
   Section 4 of RFC 5116:

   o  K_LEN (key length) is 32 octets.

   o  P_MAX (maximum size of the plaintext) is 247,877,906,880 bytes, or
      nearly 256 GB.

   o  A_MAX (maximum size of the associated data) is set to 2^64-1
      octets by the length field for associated data.

   o  N_MIN = N_MAX = 12 octets.

   o  C_MAX = P_MAX + tag length = 274,877,906,896 octets.

   Distinct AAD inputs (as described in Section 3.3 of RFC 5116) shall
   be concatenated into a single input to AEAD_CHACHA20_POLY1305.  It is
   up to the application to create a structure in the AAD input if it is
   needed.

2.8.1.  Code for the AEAD Construction
"""
def pad16(x):
    extra_bytes = len(x) % 16
    if extra_bytes == 0:
        return ''
    else:
        return (16 - extra_bytes)*chr(0x00) # pad with zeros to 16

def num_to_8_le_bytes(num):
    """ Convert number to little-endian 4 octet string """
    return ''.join(map(lambda i: chr(0xff & (num >> 8*i)), range(8)))

class ChaCha20_AEAD(object):
    """
      chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
         nonce = constant | iv
         otk = poly1305_key_gen(key, nonce)
         ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
         mac_data = aad | pad16(aad)
         mac_data |= ciphertext | pad16(ciphertext)
         mac_data |= num_to_8_le_bytes(aad.length)
         mac_data |= num_to_8_le_bytes(ciphertext.length)
         tag = poly1305_mac(mac_data, otk)
         return (ciphertext, tag)
    """
    def __init__(self, key, constant):
        self.__key = key
        self.constant = constant

    def encrypt(self, aad, iv, plain_text):
        nonce = self.constant + iv
        otk = poly1305_key_gen(self.__key, nonce)
        chacha20 = ChaCha(self.__key, counter=1, nonce=nonce)
        cipher_text = chacha20.encrypt( plain_text )
        mac_data = aad + pad16(aad)
        mac_data += cipher_text + pad16(cipher_text)
        mac_data += num_to_8_le_bytes( len(aad) )
        mac_data += num_to_8_le_bytes( len(cipher_text) )
        tag = poly1305_mac(mac_data, otk)
        return (cipher_text, tag)
    
    def decrypt(self, aad, iv, cipher_text):
        """ decrypt is same as encrypt """
        return self.encrypt(aad, iv, cipher_text)
    
class ChaCha_Poly_AEAD(ChaCha20_AEAD):
    """ """
    def encrypt(self, aad, iv, plain_text):
        cipher_text, tag = super().encrypt(aad, iv, plain_text)
        return iv + cipher_text + tag
    
    def decrypt(self, aad, iv_cipher_text_tag):
        iv = iv_cipher_text_tag[0:]
        tag = iv_cipher_text_tag[-tag_length:]
        plain_text, calculated_tag = super().encrypt(aad, iv, plain_text)
        assert tag == calculated_tag


    """
3.  Implementation Advice

   Each block of ChaCha20 involves 16 move operations and one increment
   operation for loading the state, 80 each of XOR, addition and Roll
   operations for the rounds, 16 more add operations and 16 XOR
   operations for protecting the plaintext.  Section 2.3 describes the
   ChaCha block function as "adding the original input words".  This
   implies that before starting the rounds on the ChaCha state, we copy
   it aside, only to add it in later.  This is correct, but we can save
   a few operations if we instead copy the state and do the work on the
   copy.  This way, for the next block you don't need to recreate the
   state, but only to increment the block counter.  This saves
   approximately 5.5% of the cycles.

   It is not recommended to use a generic big number library such as the
   one in OpenSSL for the arithmetic operations in Poly1305.  Such
   libraries use dynamic allocation to be able to handle an integer of
   any size, but that flexibility comes at the expense of performance as
   well as side-channel security.  More efficient implementations that
   run in constant time are available, one of them in D. J. Bernstein's
   own library, NaCl ([NaCl]).  A constant-time but not optimal approach
   would be to naively implement the arithmetic operations for 288-bit
   integers, because even a naive implementation will not exceed 2^288
   in the multiplication of (acc+block) and r.  An efficient constant-
   time implementation can be found in the public domain library
   poly1305-donna ([Poly1305_Donna]).

4.  Security Considerations

   The ChaCha20 cipher is designed to provide 256-bit security.

   The Poly1305 authenticator is designed to ensure that forged messages
   are rejected with a probability of 1-(n/(2^102)) for a 16n-byte
   message, even after sending 2^64 legitimate messages, so it is
   SUF-CMA (strong unforgeability against chosen-message attacks) in the
   terminology of [AE].

   Proving the security of either of these is beyond the scope of this
   document.  Such proofs are available in the referenced academic
   papers ([ChaCha], [Poly1305], [LatinDances], [LatinDances2], and
   [Zhenqing2012]).

   The most important security consideration in implementing this
   document is the uniqueness of the nonce used in ChaCha20.  Counters
   and LFSRs are both acceptable ways of generating unique nonces, as is

   encrypting a counter using a 64-bit cipher such as DES.  Note that it
   is not acceptable to use a truncation of a counter encrypted with a
   128-bit or 256-bit cipher, because such a truncation may repeat after
   a short time.

   Consequences of repeating a nonce: If a nonce is repeated, then both
   the one-time Poly1305 key and the keystream are identical between the
   messages.  This reveals the XOR of the plaintexts, because the XOR of
   the plaintexts is equal to the XOR of the ciphertexts.

   The Poly1305 key MUST be unpredictable to an attacker.  Randomly
   generating the key would fulfill this requirement, except that
   Poly1305 is often used in communications protocols, so the receiver
   should know the key.  Pseudorandom number generation such as by
   encrypting a counter is acceptable.  Using ChaCha with a secret key
   and a nonce is also acceptable.

   The algorithms presented here were designed to be easy to implement
   in constant time to avoid side-channel vulnerabilities.  The
   operations used in ChaCha20 are all additions, XORs, and fixed
   rotations.  All of these can and should be implemented in constant
   time.  Access to offsets into the ChaCha state and the number of
   operations do not depend on any property of the key, eliminating the
   chance of information about the key leaking through the timing of
   cache misses.

   For Poly1305, the operations are addition, multiplication. and
   modulus, all on numbers with greater than 128 bits.  This can be done
   in constant time, but a naive implementation (such as using some
   generic big number library) will not be constant time.  For example,
   if the multiplication is performed as a separate operation from the
   modulus, the result will sometimes be under 2^256 and sometimes be
   above 2^256.  Implementers should be careful about timing side-
   channels for Poly1305 by using the appropriate implementation of
   these operations.

   Validating the authenticity of a message involves a bitwise
   comparison of the calculated tag with the received tag.  In most use
   cases, nonces and AAD contents are not "used up" until a valid
   message is received.  This allows an attacker to send multiple
   identical messages with different tags until one passes the tag
   comparison.  This is hard if the attacker has to try all 2^128
   possible tags one by one.  However, if the timing of the tag
   comparison operation reveals how long a prefix of the calculated and
   received tags is identical, the number of messages can be reduced
   significantly.  For this reason, with online protocols,
   implementation MUST use a constant-time comparison function rather
   than relying on optimized but insecure library functions such as the
   C language's memcmp().

5.  IANA Considerations

   IANA has assigned an entry in the "Authenticated Encryption with
   Associated Data (AEAD) Parameters" registry with 29 as the Numeric
   ID, "AEAD_CHACHA20_POLY1305" as the name, and this document as
   reference.

6.  References

6.1.  Normative References

   [ChaCha]   Bernstein, D., "ChaCha, a variant of Salsa20", January
              2008, <http://cr.yp.to/chacha/chacha-20080128.pdf>.

   [Poly1305] Bernstein, D., "The Poly1305-AES message-authentication
              code", March 2005,
              <http://cr.yp.to/mac/poly1305-20050329.pdf>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <http://www.rfc-editor.org/info/rfc2119>.

6.2.  Informative References

   [AE]       Bellare, M. and C. Namprempre, "Authenticated Encryption:
              Relations among notions and analysis of the generic
              composition paradigm", September 2008,
              <http://dl.acm.org/citation.cfm?id=1410269>.

   [Cache-Collisions]
              Bonneau, J. and I. Mironov, "Cache-Collision Timing
              Attacks Against AES", 2006,
              <http://research.microsoft.com/pubs/64024/aes-timing.pdf>.

   [FIPS-197] National Institute of Standards and Technology, "Advanced
              Encryption Standard (AES)", FIPS PUB 197, November 2001,
              <http://csrc.nist.gov/publications/fips/fips197/
              fips-197.pdf>.

   [LatinDances]
              Aumasson, J., Fischer, S., Khazaei, S., Meier, W., and C.
              Rechberger, "New Features of Latin Dances: Analysis of
              Salsa, ChaCha, and Rumba", December 2007,
              <http://cr.yp.to/rumba20/newfeatures-20071218.pdf>.

   [LatinDances2]
              Ishiguro, T., Kiyomoto, S., and Y. Miyake, "Modified
              version of 'Latin Dances Revisited: New Analytic Results
              of Salsa20 and ChaCha'", February 2012,
              <https://eprint.iacr.org/2012/065.pdf>.

   [NaCl]     Bernstein, D., Lange, T., and P. Schwabe, "NaCl:
              Networking and Cryptography library", July 2012,
              <http://nacl.cr.yp.to>.

   [Poly1305_Donna]
              Floodyberry, A., "poly1305-donna", February 2014,
              <https://github.com/floodyberry/poly1305-donna>.

   [Procter]  Procter, G., "A Security Analysis of the Composition of
              ChaCha20 and Poly1305", August 2014,
              <http://eprint.iacr.org/2014/613.pdf>.

   [RFC4868]  Kelly, S. and S. Frankel, "Using HMAC-SHA-256, HMAC-SHA-
              384, and HMAC-SHA-512 with IPsec", RFC 4868,
              DOI 10.17487/RFC4868, May 2007,
              <http://www.rfc-editor.org/info/rfc4868>.

   [RFC5116]  McGrew, D., "An Interface and Algorithms for Authenticated
              Encryption", RFC 5116, DOI 10.17487/RFC5116, January 2008,
              <http://www.rfc-editor.org/info/rfc5116>.

   [RFC7296]  Kaufman, C., Hoffman, P., Nir, Y., Eronen, P., and T.
              Kivinen, "Internet Key Exchange Protocol Version 2
              (IKEv2)", STD 79, RFC 7296, DOI 10.17487/RFC7296, October
              2014, <http://www.rfc-editor.org/info/rfc7296>.

   [SP800-67] National Institute of Standards and Technology,
              "Recommendation for the Triple Data Encryption Algorithm
              (TDEA) Block Cipher", NIST 800-67, January 2012,
              <http://csrc.nist.gov/publications/nistpubs/800-67-Rev1/
              SP-800-67-Rev1.pdf>.

   [Standby-Cipher]
              McGrew, D., Grieco, A., and Y. Sheffer, "Selection of
              Future Cryptographic Standards", Work in Progress,
              draft-mcgrew-standby-cipher-00, January 2013.

   [Zhenqing2012]
              Zhenqing, S., Bin, Z., Dengguo, F., and W. Wenling,
              "Improved Key Recovery Attacks on Reduced-Round Salsa20
              and ChaCha*", 2012.
"""







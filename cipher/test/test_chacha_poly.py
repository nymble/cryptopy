#!/usr/bin/env python
""" test_chacha_poly.py

    Unit tests for the ChaCha stream cipher.
    Test vectors are taken from:

      [RFC7539] Y. Nir Y., Langley A., "ChaCha20 and Poly1305 for
                IETF Protocols", May 2015,
                <https://tools.ietf.org/html/rfc7539>

    Paul A. Lambert 2017
"""
import binascii
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from chacha_poly import ChaCha, quarter_round, inner_block
from chacha_poly import le_bytes_to_num, num_to_16_le_bytes, clamp

def to_octets(text):
    """ Convert ascii hex value with whitespaces
        and separators to octets.
    """
    text = text.replace(':','')
    return binascii.a2b_hex( ''.join(text.split()) )

class ChaCha_Tests_RFC7539(unittest.TestCase):
    """ ChaCha20 tests from RFC 7539
        <https://tools.ietf.org/html/rfc7539>
    """
    def test_quarter_round(self):
        """ Test vectors for the ChaCha quarter round
            Section 2.1.1
        """
        a = 0x11111111
        b = 0x01020304
        c = 0x9b8d6f43
        d = 0x01234567

        # After running a Quarter Round on these
        # four numbers, we get these:

        a_qr, b_qr, c_qr, d_qr = quarter_round(a, b, c, d)

        # the expected values after the quarter round are:
        a_qr_expected = 0xea2a92f4
        b_qr_expected = 0xcb1cf8ce
        c_qr_expected = 0x4581472e
        d_qr_expected = 0x5881c4bb

        self.assertEqual( a_qr, a_qr_expected )
        self.assertEqual( b_qr, b_qr_expected )
        self.assertEqual( c_qr, c_qr_expected )
        self.assertEqual( d_qr, d_qr_expected )

    def test_block(self):
        """ Test vectors for key/state setup and block function

            Section 2.3.2 of RFC-7539
        """
        key = to_octets("""
              00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:
              10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
              """)
        nonce = to_octets("""
                00:00:00:09:00:00:00:4a:00:00:00:00
                """)
        block_counter = 1

        # After setting up the ChaCha state, it should like this:
        #
        #   ChaCha expected state after the key setup.
        e_state= (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                  0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                  0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                  0x00000001, 0x09000000, 0x4a000000, 0x00000000)
        # validate ChaCha key setup
        chacha = ChaCha( key, nonce, initial_block_counter=block_counter )
        for expected, calculated in zip( e_state, chacha.state ):
            self.assertEqual( expected, calculated )


        # After running 20 rounds (10 column rounds interleaved
        # with 10 "diagonal rounds"), the ChaCha state
        # looks like this:
        #
        #   ChaCha expected state after 20 rounds
        e_state = (0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
                   0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
                   0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
                   0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2)

        # validate that calculated state equals expected state
        test_state = list(chacha.state) # copy state
        for i in range(10):
            inner_block(test_state)

        for expected, calculated in zip( e_state, test_state ):
            self.assertEqual( expected, calculated )

    def test_encryption(self):
        """ A.2.  ChaCha20 Encryption Tests
            From RFC 7539
        """
        def to_octets(s):
            """ Convert ascii hex value with whitespaces
                to octets.
            """
            return binascii.a2b_hex( ''.join(s.split()) )

        def validate_test_vectors():
            """ Create new ChaCha instance, encrypt and decrypt test vectors """
            chacha = ChaCha(key, nonce, initial_block_counter=initial_block_counter)
            ct = chacha.encrypt( plain_text )
            self.assertEqual( ct, cipher_text ) # validate encryption

            chacha = ChaCha(key, nonce, initial_block_counter=initial_block_counter)
            pt = chacha.decrypt( cipher_text )
            self.assertEqual( pt, plain_text )  # validate decryption

        # Test Vector #1:
        key =   to_octets("""
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                """)
        nonce = to_octets("""
                00 00 00 00 00 00 00 00 00 00 00 00
                """)
        initial_block_counter = 0
        plain_text = to_octets("""
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                """)
        cipher_text = to_octets("""
                76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
                bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
                da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
                6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
                """)
        validate_test_vectors()

        # Test Vector #2:
        key = to_octets("""
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
                """)
        nonce = to_octets("""
               00 00 00 00 00 00 00 00 00 00 00 02
               """)
        initial_block_counter = 1
        plain_text = """Any submission to the IETF intended by the Contributor \
for publication as all or part of an IETF Internet-Draft or RFC and any \
statement made within the context of an IETF activity is considered an \
"IETF Contribution". Such statements include oral statements in IETF sessions, \
as well as written and electronic communications made at any time or place, \
which are addressed to"""
        cipher_text = to_octets("""
                a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70
                41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec
                2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05
                0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d
                40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e
                20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50
                42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c
                68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a
                d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66
                42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d
                c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28
                e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b
                08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f
                a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c
                cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84
                a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b
                c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0
                8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f
                58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62
                be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6
                98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85
                14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab
                7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd
                c4 fd 80 6c 22 f2 21 """)
        validate_test_vectors()

        # Test Vector #3:
        key = to_octets("""
                1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
                47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
                """)
        nonce = to_octets("""
                00 00 00 00 00 00 00 00 00 00 00 02
                """)
        initial_block_counter = 42
        plain_text = """'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe:
All mimsy were the borogoves,
And the mome raths outgrabe."""
        cipher_text = to_octets("""
                62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df
                5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf
                16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71
                fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb
                f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6
                1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77
                04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1
                87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1
        """)
        validate_test_vectors()

    def test_nonce_api(self):
        """ Tests of nonce usage and detection of nonce reuse"""
        key = to_octets("""
                00 01 00 00 00 00 00 00 00 ff 00 00 00 00 00 01
                01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00
                """)
        nonce = to_octets("""
                01 02 03 00 00 00 00 00 00 00 00 00
                """)
        plain_text = 11*"""API related test"""

        chacha = ChaCha(key, nonce=nonce)
        ct1 = chacha.encrypt( plain_text )
        chacha = ChaCha(key, nonce=nonce)
        pt1 = chacha.decrypt( ct1 )

        # check for error on second use of the manually set nonce
        self.assertRaises(ValueError, chacha.encrypt, plain_text)

        chacha=ChaCha(key) # auto deneration of nonce
        ct2 = chacha.encrypt( plain_text )
        self.assertNotEqual(ct1, ct2)

        nonce = chacha.nonce # retrieve nonce from prior usage
        chacha = ChaCha( key, nonce )
        pt2 = chacha.decrypt( ct2 )
        self.assertEqual( pt1, pt2 )

    def test_block_oriented(self):
        """ Test usage of block oriented encrypt/decrypt
            for large files.
        """
        key = to_octets("""
                00 01 00 00 00 00 00 00 00 ff 00 00 00 00 00 01
                01 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00
                """)
        nonce = to_octets("""
            01 02 03 00 00 00 00 00 00 00 00 00
            """)
        
        # test various sizes of plain text to validate
        for pt_size in (0, 1, 63, 64, 65, 127, 128, 129, 130):
            pt = ''.join([chr(i) for i in range(pt_size)])

            chacha=ChaCha(key)
            b_size = ChaCha.block_size
            # this would typically be performed by reading file blocks
            blocks, remainder = divmod( len(pt), ChaCha.block_size )
            ct = ''
            for j in range(blocks):
                ct += chacha.encrypt( pt[j*b_size:(j+1)*b_size], more=True)
            ct += chacha.encrypt( pt[blocks*b_size:], more=False)

            nonce = chacha.nonce # reuse noce to test block oriented encryption
            chacha = ChaCha(key, nonce)
            ct2 = chacha.encrypt( pt )

            self.assertEqual(ct, ct2)



from chacha_poly import poly1305_mac

class Poly1305_Tests_RFC7539(unittest.TestCase):
    """ Poly1305 tests from:
        <https://tools.ietf.org/html/rfc7539>
    """

    def test_example(self):
        """ 
2.5.2.  Poly1305 Example and Test Vector
    
    For our example, we will dispense with generating the one-time key
    using AES, and assume that we got the following keying material:
        """
        #  Key Material:
        key = to_octets("""
          85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:
          01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
          """)
    
        #  s as an octet string:
        s = to_octets("""
          01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
          """)
        
        #  s as a 128-bit number:
        s_num = 0x1bf54941aff6bf4afdb20dfb8a800301
        
        #  r before clamping:
        r = to_octets("""
            85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8
            """)
        
        #  Clamped r as a number:
        r_num = 0x806d5400e52447c036d555408bed685
        
        # validate above examples
        self.assertEqual( le_bytes_to_num(s), s_num )
        
        self.assertEqual( s, num_to_16_le_bytes(s_num) )
        
        self.assertEqual( r_num, clamp(le_bytes_to_num(r)) )

        """
    For our message, we'll use a short text:
        """
        message = to_octets("""
         43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f
         72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f
         75 70 
         """)
             
        """
    Since Poly1305 works in 16-byte chunks, the 34-byte message divides
    into three blocks.  In the following calculation, "Acc" denotes the
    accumulator and "Block" the current block:
    
    Block #1
    
    Acc = 00
    Block = 6f4620636968706172676f7470797243
    Block with 0x01 byte = 016f4620636968706172676f7470797243

    Acc + block = 016f4620636968706172676f7470797243
    (Acc+Block) * r =
    b83fe991ca66800489155dcd69e8426ba2779453994ac90ed284034da565ecf
    Acc = ((Acc+Block)*r) % P = 2c88c77849d64ae9147ddeb88e69c83fc
    
    Block #2
    
    Acc = 2c88c77849d64ae9147ddeb88e69c83fc
    Block = 6f7247206863726165736552206d7572
    Block with 0x01 byte = 016f7247206863726165736552206d7572
    Acc + block = 437febea505c820f2ad5150db0709f96e
    (Acc+Block) * r =
    21dcc992d0c659ba4036f65bb7f88562ae59b32c2b3b8f7efc8b00f78e548a26
    Acc = ((Acc+Block)*r) % P = 2d8adaf23b0337fa7cccfb4ea344b30de
    
    Last Block
    
    Acc = 2d8adaf23b0337fa7cccfb4ea344b30de
    Block = 7075
    Block with 0x01 byte = 017075
    Acc + block = 2d8adaf23b0337fa7cccfb4ea344ca153
    (Acc + Block) * r =
    16d8e08a0f3fe1de4fe4a15486aca7a270a29f1e6c849221e4a6798b8e45321f
    ((Acc + Block) * r) % P = 28d31b7caff946c77c8844335369d03a7
    
    Adding s, we get this number, and serialize if to get the tag:
    
    Acc + s = 2a927010caf8b2bc2c6365130c11d06a8
        """

        tag = to_octets("""
        a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
        """)

        self.assertEqual( poly1305_mac(message, key), tag )
        
        """

A.3.  Poly1305 Message Authentication Code

   Notice how, in test vector #2, r is equal to zero.  The part of the
   Poly1305 algorithm where the accumulator is multiplied by r means
   that with r equal zero, the tag will be equal to s regardless of the
   content of the text.  Fortunately, all the proposed methods of
   generating r are such that getting this particular weak key is very
   unlikely.
        """
    def validate_poly_test_vector(self, key, text, tag):
        self.assertEqual( poly1305_mac(text, key), tag )
    
    def test_vector_1(self):
        """ Test Vector #1:
        """
        
        # One-time Poly1305 Key:
        key = to_octets("""
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            """)

        # Text to MAC:
        text = to_octets("""
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            """)

        # Tag:
        tag = to_octets("""
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            """)
                
        self.validate_poly_test_vector(key, text, tag)
        """
  Test Vector #2:
  ==============

  One-time Poly1305 Key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>

  Text to MAC:
  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
  368  73 73 65 64 20 74 6f                             ssed to

  Tag:
  000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>


  Test Vector #3:
  ==============

  One-time Poly1305 Key:
  000  36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e  6.....`p...."z.>
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  Text to MAC:
  000  41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74  Any submission t
  016  6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e  o the IETF inten
  032  64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72  ded by the Contr
  048  69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69  ibutor for publi
  064  63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72  cation as all or
  080  20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46   part of an IETF
  096  20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20   Internet-Draft
  112  6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73  or RFC and any s
  128  74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69  tatement made wi
  144  74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74  thin the context
  160  20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69   of an IETF acti
  176  76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72  vity is consider
  192  65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74  ed an "IETF Cont
  208  72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20  ribution". Such
  224  73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75  statements inclu
  240  64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e  de oral statemen
  256  74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69  ts in IETF sessi
  272  6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20  ons, as well as
  288  77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63  written and elec
  304  74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61  tronic communica
  320  74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e  tions made at an
  336  79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c  y time or place,
  352  20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65   which are addre
  368  73 73 65 64 20 74 6f                             ssed to

  Tag:
  000  f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0  .G~|.T.....yL1..


  Test Vector #4:
  ==============

  One-time Poly1305 Key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  Text to MAC:
  000  27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61  'Twas brillig, a
  016  6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f  nd the slithy to
  032  76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64  ves.Did gyre and
  048  20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77   gimble in the w
  064  61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77  abe:.All mimsy w
  080  65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65  ere the borogove
  096  73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20  s,.And the mome
  112  72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e     raths outgrabe.

  Tag:
  000  45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62  EAf.~..a...|...b

   Test Vector #5: If one uses 130-bit partial reduction, does the code
   handle the case where partially reduced final result is not fully
   reduced?

   R:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   data:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   tag:
   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #6: What happens if addition of s overflows modulo 2^128?

   R:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   S:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   data:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   tag:
   03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


   Test Vector #7: What happens if data limb is all ones and there is
   carry from lower limb?

   R:
   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   data:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   tag:
   05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #8: What happens if final result from polynomial part is
   exactly 2^130-5?

   R:
   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   data:
   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE
   01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
   tag:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

   Test Vector #9: What happens if final result from polynomial part is
   exactly 2^130-6?

   R:
   02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   data:
   FD FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
   tag:
   FA FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF

   Test Vector #10: What happens if 5*H+L-type reduction produces
   131-bit intermediate result?

   R:
   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   data:
   E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
   33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   tag:
   14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00

   Test Vector #11: What happens if 5*H+L-type reduction produces
   131-bit final result?

   R:
   01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
   S:
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   data:
   E3 35 94 D7 50 5E 43 B9 00 00 00 00 00 00 00 00
   33 94 D7 50 5E 43 79 CD 01 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   tag:
   13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

A.4.  Poly1305 Key Generation Using ChaCha20

  Test Vector #1:
  ==============

  The key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

  The nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 00              ............

  Poly1305 one-time key:
  000  76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28  v.....=.@]j.S..(
  016  bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7  .........6...w..

  Test Vector #2:
  ==============

  The key:
  000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  016  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01  ................

  The nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Poly1305 one-time key:
  000  ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76  ..%O._dts......v
  016  06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39  ..3.lD{..&f....9

  Test Vector #3:
  ==============

  The key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  The nonce:
  000  00 00 00 00 00 00 00 00 00 00 00 02              ............

  Poly1305 one-time key:
  000  96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b  .^;...~.V....).K
  016  13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae  ...u..?..Y...3..

A.5.  ChaCha20-Poly1305 AEAD Decryption

   Below we see decrypting a message.  We receive a ciphertext, a nonce,
   and a tag.  We know the key.  We will check the tag and then
   (assuming that it validates) decrypt the ciphertext.  In this
   particular protocol, we'll assume that there is no padding of the
   plaintext.


  The key:
  000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
  016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

  Ciphertext:
  000  64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd  d...u...`.b...C.
  016  5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2  ^.\.4\....g..l..
  032  4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0  Ll..u]C....N8-&.
  048  bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf  ...<2.....;.5X..
  064  33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81  3/..q......J....
  080  14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55  ...n..3.`....7.U
  096  97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38  ...n...a..2N+5.8
  112  36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4  6..{j|.....{S.g.
  128  b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9  ..lv{.MF..R.....
  144  90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e  .@...3"^.....lR>
  160  af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a  .E4..?..[.Gq..Tj
  176  0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a  ..+..VN..B"s.H'.
  192  0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e  ..1`S.v..U..1YCN
  208  ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10  ..NFm.Z.s.rv'.z.
  224  49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30  I....6...h..w.q0
  240  30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29  0[.......{qMlo,)
  256  a6 ad 5c b4 02 2b 02 70 9b                       ..\..+.p.

  The nonce:
  000  00 00 00 00 01 02 03 04 05 06 07 08              ............

  The AAD:
  000  f3 33 88 86 00 00 00 00 00 00 4e 91              .3........N.

  Received Tag:
  000  ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38  ...g..."9#6....8


   First, we calculate the one-time Poly1305 key

  @@@  ChaCha state with key setup
        61707865  3320646e  79622d32  6b206574
        a540921c  8ad355eb  868833f3  f0b5f604
        c1173947  09802b40  bc5cca9d  c0757020
        00000000  00000000  04030201  08070605

  @@@  ChaCha state after 20 rounds
        a94af0bd  89dee45c  b64bb195  afec8fa1
        508f4726  63f554c0  1ea2c0db  aa721526
        11b1e514  a0bacc0f  828a6015  d7825481
        e8a4a850  d9dcbbd6  4c2de33a  f8ccd912

  @@@ out bytes:
  bd:f0:4a:a9:5c:e4:de:89:95:b1:4b:b6:a1:8f:ec:af:
  26:47:8f:50:c0:54:f5:63:db:c0:a2:1e:26:15:72:aa

  Poly1305 one-time key:
  000  bd f0 4a a9 5c e4 de 89 95 b1 4b b6 a1 8f ec af  ..J.\.....K.....
  016  26 47 8f 50 c0 54 f5 63 db c0 a2 1e 26 15 72 aa  &G.P.T.c....&.r.

   Next, we construct the AEAD buffer

  Poly1305 Input:
  000  f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00  .3........N.....
  016  64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd  d...u...`.b...C.
  032  5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2  ^.\.4\....g..l..
  048  4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0  Ll..u]C....N8-&.
  064  bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf  ...<2.....;.5X..
  080  33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81  3/..q......J....
  096  14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55  ...n..3.`....7.U
  112  97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38  ...n...a..2N+5.8
  128  36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4  6..{j|.....{S.g.
  144  b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9  ..lv{.MF..R.....
  160  90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e  .@...3"^.....lR>
  176  af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a  .E4..?..[.Gq..Tj
  192  0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a  ..+..VN..B"s.H'.
  208  0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e  ..1`S.v..U..1YCN
  224  ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10  ..NFm.Z.s.rv'.z.
  240  49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30  I....6...h..w.q0
  256  30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29  0[.......{qMlo,)
  272  a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00  ..\..+.p........
  288  0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00  ................


   We calculate the Poly1305 tag and find that it matches

  Calculated Tag:
  000  ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38  ...g..."9#6....8

   Finally, we decrypt the ciphertext

  Plaintext::
  000  49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20  Internet-Drafts
  016  61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65  are draft docume
  032  6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20  nts valid for a
  048  6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d  maximum of six m
  064  6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65  onths and may be
  080  20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63   updated, replac
  096  65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64  ed, or obsoleted
  112  20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65   by other docume
  128  6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e  nts at any time.
  144  20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72   It is inappropr
  160  69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65  iate to use Inte
  176  72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72  rnet-Drafts as r
  192  65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61  eference materia
  208  6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65  l or to cite the
  224  6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20  m other than as
  240  2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67  /...work in prog
  256  72 65 73 73 2e 2f e2 80 9d                       ress./...


"""

# Make this test module runnable from the command prompt
if __name__ == "__main__":
    unittest.main()

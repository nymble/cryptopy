""" argon2.py

    The memory-hard Argon2 password hash function
    based on: draft-josefsson-argon2-00
    
    Normative References:

       [I-D.saarinen-blake2]
            Saarinen, M. and J. Aumasson, "The BLAKE2 Cryptographic
            Hash and MAC", draft-saarinen-blake2-06 (work in
            progress), August 2015.

    Informative References:

       [RFC4086]
            Eastlake, D., Schiller, J., and S. Crocker, "Randomness
            Requirements for Security", BCP 106, RFC 4086, June 2005.

       [ARGON2]
            Biryukov, A., Dinu, D., and D. Khovratovich, "Argon2: the
            memory-hard function for password hashing and other
            applications", WWW https://password-hashing.net/
            argon2-specs.pdf, October 2015.


   This is a reference implementation of Argon2 memory-hard function
   for password hashing and other applications.
   
   
   We provide a implementer oriented
   description together with sample code and test vectors.  The purpose
   is to simplify adoption of Argon2 for Internet protocols.

   Argon2 is optimized for the x86 architecture and exploits the cache
   and memory organization of the recent Intel and AMD processors.
   Argon2 has two variants: Argon2d and Argon2i.  Argon2d is faster and
   uses data-depending memory access, which makes it suitable for
   cryptocurrencies and applications with no threats from side-channel
   timing attacks.  Argon2i uses data-independent memory access, which
   is preferred for password hashing and password-based key derivation.
   Argon2i is slower as it makes more passes over the memory to protect
   from tradeoff attacks.

   For further background and discussion, see the Argon2 paper [ARGON2].
   
    
    Paul A. Lambert 2015
"""
from struct import pack

"""

2.  Notation and Conventions

   x^y --- x multiplied by itself y times

   a*b --- multiplication of a and b

   c-d --- substraction of c with d

   E_f --- variable E with subscript index f

   g / h --- g divided by h

   I(j) --- function I evaluated on parameters j

   K || L --- string K concatenated with string L

"""

def argon2( P, nonce_S, p=1, T=4, m=8, t=3, K='', X='' ):
    """ """
    # Message string P, typically a password.
    assert 0 <= len(P) < 2^32

    # Nonce S, typically a random salt.  May have any length from 8 to
    # 2^32 - 1 bytes.  16 bytes is recommended for password hashing.
    # See [RFC4086] for discussion about randomness.
    assert 8 <= len(S) < 2^32

    # Degree of parallelism p determines how many independent (but
    # synchronizing) computational chains can be run.  It may take any
    # integer value from 1 to 255.
    assert 1 <= p <= 255

    # Tag length T may be any integer number of bytes from 4 to 2^32-1.
    assert 4 <= T < 2^32
    
    # Memory size m can be any integer number of kilobytes from 8*p to
    # 2^32-1.  The actual number of blocks is m', which is m rounded
    # down to the nearest multiple of 4*p.
    assert 8*p <= m < 2^32

    # Number of iterations t (used to tune the running time
    # independently of the memory size) can be any integer number from 1
    # to 2^32-1.
    assert 0 < t < 2^32

    # Version number v is one byte 0x10. ?? later it's encoded as 4 bytes
    assert v == 0x10

    # Secret value K (serves as key if necessary, but we do not assume
    # any key use by default) may have any length from 0 to 32 bytes.
    assert len(K) < 32

    # Associated data X may have any length from 0 to 2^32-1 bytes.
    assert len(X) < 2^32

   # Type y of Argon2: 0 for Argon2d, 1 for Argon2i.
   y = 0

   # The Argon2 output is a T-length string.

   

     
     
    H_0 = H( pack('<HHHHHH', p, T, m, t, v, y),
             pack('<H', len(P)), P,
             pack('<H', len(S)), S,
             pack('<H', len(K)), K,
             pack('<H', len(X)), X)
    
    """
    
3.2.  Argon2 Operation

   Argon2 uses an internal compression function G with two 1024-byte
   inputs and a 1024-byte output, and an internal hash function H.  Here
   H is the Blake2b [I-D.saarinen-blake2] hash function, and the
   compression function G is based on its internal permutation.  A
   variable-length hash function H' built upon H is also used.  G and H'
   are described in later section.

   The Argon2 operation is as follows.

   1.  Establish H_0 as the 64-bit value as shown in the figure below.
       H is BLAKE2b and the non-strings p, T, m, t, v, y, length(P),
       length(S), length(K), and length(X) are treated as a 32-bit
       little-endian encoding of the integer.

             H_0 = H(p, T, m, t, v, y, length(P), P, length(S), S,
                     length(K), K, length(X), X)

   2.  Allocate the memory as m' 1024-byte blocks where m' is derived
       as:

             m' = 4 * p * floor (m / 4p)

       For tunable parallelism with p threads, the memory is organized
       in a matrix B[i][j] of blocks with p rows (lanes) and q = m' / p
       columns.

   3.  Compute B[i][0] for all i ranging from (and including) 0 to (not
       including) p.

             B[i][0] = H'(H0, 4byteencode(i), 4byteencode(0))

       Here 4byteencode is a function which takes an integer and little-
       endian encode and padds it to 4 bytes.

   4.  Compute B[i][1] for all i ranging from (and including) 0 to (not
       including) p.

             B[i][1] = H'(H0, 4byteencode(i), 4byteencode(1))

   5.  Compute B[i][j] for all i ranging from (and including) 0 to (not
       including) p, and for all j ranging from (and including) 2) to
       (not including) q.  The block indices i' and j' are determined
       differently for Argon2d and Argon2i.

             B[i][j] = G(B[i][j-1], B[i'][j'])

   6.  If the number of iterations t is larger than 1, we repeat the
       steps however replacing the computations with with the following
       expression:

             B[i][0] = G(B[i][q-1], B[i'][j'])
             B[i][j] = G(B[i][j-1], B[i'][j'])

   7.  After t steps have been iterated, we compute the final block C as
       the XOR of the last column:

             C = B[0][q-1] XOR B[1][q-1] XOR ... XOR B[p-1][q-1]

   8.  The output tag is computed as H'(C).

3.3.  Variable-length hash function H'

   Let H_x be a hash function with x-byte output (in our case H_x is
   Blake2b, which supports x between 1 and 64 inclusive).  Let V_i be a
   64-byte block, and A_i be its first 32 bytes, and T < 2^32 be the tag
   length in bytes.  Then we define

           V_0 = T||X
           V_1 = H_64(V_0)
               V_2 = H_64(V_1)
           ...
           V_r = H_64(V_{r-1})   with r=floor(T/32)-1
           V_{r+1} = H_{T mod 64}(V_{r-1}) absent if 64 divides T
           H'(X) = A_1 || A_2 || ... || A_r || V_{r+1}

   FIXME: improve this description.  FIXME2: V_{r+1} is not properly
   described, is it a 64-byte block or a {T mod 64} block?

3.4.  Indexing

   TBD



3.5.  Compression function G

   Compression function G is built upon the Blake2b round function P.  P
   operates on the 128-byte input, which can be viewed as 8 16-byte
   registers:

           P(A_0, A_1, ... ,A_7) = (B_0, B_1, ... ,B_7)

   Compression function G(X, Y) operates on two 1024-byte blocks X and
   Y.  It first computes R = X XOR Y.  Then R is viewed as a 8x8-matrix
   of 16-byte registers R_0, R_1, ... , R_63.  Then P is first applied
   rowwise, and then columnwise to get Z:

   (Q_0, Q_1, ... , Q_7 ) <- P(R_0, R_1, ... , R_7)
   (Q_8, Q_9, ... , Q_15) <- P(R_8, R_9, ... , R_15)
   ...
   (Q_56, Q_57, ... , Q_63 ) <- P(R_56, R_57, ... , R_63)
   (Z_0, Z_8, Z_16 , ... , Z_56) < P(Q_0, Q_8, Q_16, ... , Q_56)
   (Z_1, Z_9, Z_17 , ... , Z_57) < P(Q_1, Q_9, Q_17, ... , Q_57)
   ...
   (Z_7, Z_15, Z 23 , ... , Z_63) < P(Q_7, Q_15, Q_23, ... , Q_63)

   Finally, G outputs Z XOR R:

           G: (X,Y) -> R = X XOR Y -P-> Q -P-> Z -P-> Z XOR R

   FIXME: improve this description.

3.6.  Permutation P

   TBD

4.  Parameter Choice

   Argon2d is optimized for settings where the adversary does not get
   regular access to system memory or CPU, i.e. he can not run side-
   channel attacks based on the timing information, nor he can recover
   the password much faster using garbage collection.  These settings
   are more typical for backend servers and cryptocurrency minings.  For
   practice we suggest the following settings:

   o  Cryptocurrency mining, that takes 0.1 seconds on a 2 Ghz CPU using
      1 core -- Argon2d with 2 lanes and 250 MB of RAM.

   o  Backend server authentication, that takes 0.5 seconds on a 2 GHz
      CPU using 4 cores -- Argon2d with 8 lanes and 4 GB of RAM.



   Argon2i is optimized for more realistic settings, where the adversary
   possibly can access the same machine, use its CPU or mount cold-boot
   attacks.  We use three passes to get rid entirely of the password in
   the memory.  We suggest the following settings:

   o  Key derivation for hard-drive encryption, that takes 3 seconds on
      a 2 GHz CPU using 2 cores - Argon2i with 4 lanes and 6 GB of RAM

   o  Frontend server authentication, that takes 0.5 seconds on a 2 GHz
      CPU using 2 cores - Argon2i with 4 lanes and 1 GB of RAM.

   We recommend the following procedure to select the type and the
   parameters for practical use of Argon2.

   1.  Select the type y.  If you do not know the difference between
       them or you consider side-channel attacks as viable threat,
       choose Argon2i.

   2.  Figure out the maximum number h of threads that can be initiated
       by each call to Argon2.

   3.  Figure out the maximum amount m of memory that each call can
       afford.

   4.  Figure out the maximum amount x of time (in seconds) that each
       call can afford.

   5.  Select the salt length. 128 bits is sufficient for all
       applications, but can be reduced to 64 bits in the case of space
       constraints.

   6.  Select the tag length. 128 bits is sufficient for most
       applications, including key derivation.  If longer keys are
       needed, select longer tags.

   7.  If side-channel attacks is a viable threat, enable the memory
       wiping option in the library call.

   8.  Run the scheme of type y, memory m and h lanes and threads, using
       different number of passes t.  Figure out the maximum t such that
       the running time does not exceed x.  If it exceeds x even for t =
       1, reduce m accordingly.

   9.  Hash all the passwords with the just determined values m, h, and
       t.

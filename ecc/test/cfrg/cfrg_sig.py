#!/usr/bin/env python


# Derivered from:
# cfrg/signatures.py version 2015.08.04
# Daniel J. Bernstein


import hashlib
import random


b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
  
def expmod(b,e,m):
  if e == 0: return 1
  t = expmod(b,e/2,m)**2 % m
  if e & 1: t = (t*b) % m
  return t
  
def inv(x):
  #return expmod(x,q-2,q)
  return inverse_mod(x,q)

def inverse_mod( a, m ):
    """Inverse of a mod m."""   
    if a < 0 or m <= a: a = a % m   
    # From Ferguson and Schneier, roughly:
    
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod( d, c ) + ( c, )
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
    
    # At this point, d is the GCD, and ud*a+vd*m = d.
    # If d == 1, this means that ud is a inverse.
    
    assert d == 1
    if ud > 0: return ud
    else: return ud + m

d = -121665 * inv(121666)
I = expmod(2,(q-1)/4,q)
  
def xrecover(y):
  xx = (y*y-1) * inv(d*y*y+1)
  x = expmod(xx,(q+3)/8,q)
  if (x*x - xx) % q != 0: x = (x*I) % q
  if x % 2 != 0: x = q-x
  return x

By = 4 * inv(5)
Bx = xrecover(By)
B = (Bx % q,By % q)

def isoncurve(P):
  x,y = P
  return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

def edwards(P,Q):
  x1,y1 = P
  x2,y2 = Q
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
  return (x3 % q,y3 % q)
  
def scalarmult(P,e):
  if e == 0: return (0,1)
  Q = scalarmult(P,e/2)
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,P)
  return Q
  
def encodeint(y,bytes):
  return ''.join([chr((y >> (8 * i)) % 256) for i in range(bytes)])
  
def decodeint(s):
  return sum(256**i * ord(s[i]) for i in range(len(s)))
  
def encodepoint(P):
  x,y = P
  return encodeint(y + ((x & 1) << (b - 1)),b/8)
  
def decodepoint(s):
  yx = decodeint(s)
  y = yx % (1 << (b - 1))
  x = xrecover(y)
  if (x & 1) != (yx >> (b - 1)): x = q-x
  P = (x,y)
  if not isoncurve(P): raise Exception('decoding point that is not on curve')
  return P

assert b >= 10
assert expmod(2,q-1,q) == 1
assert q % 4 == 1
assert expmod(2,l-1,l) == 1
assert l >= 2**(b-4)
assert l <= 2**(b-3)
assert expmod(d,(q-1)/2,q) == q-1
assert expmod(I,2,q) == q-1
assert isoncurve(B)
assert scalarmult(B,l) == (0,1)

for scheme in ['brown','eddsa','ford','hamburg','ladd','liusvaara']:

  brown = (scheme == 'brown')
  eddsa = (scheme == 'eddsa')
  ford = (scheme == 'ford')
  hamburg = (scheme == 'hamburg')
  ladd = (scheme == 'ladd')
  liusvaara = (scheme == 'liusvaara')

  if hamburg:
    def H(m):
      return hashlib.md5(m).digest()
    hbytes = len(H(''))
  if brown:
    def H(m):
      return hashlib.sha384(m).digest()
  if eddsa or ladd or liusvaara:
    def H(m):
      return hashlib.sha512(m).digest()
  if ford:
    def H(m):
      return hashlib.sha512(m).digest()  # XXX pretend this is SHAKE128(M,512)
      # return somelib.shake128(m,512).digest()  # what we want

  if eddsa or hamburg or liusvaara:
    def prehash(m):
      return hashlib.sha256(m).digest()
  
  if brown:
    def linv(x):
      return expmod(x,l-2,l)

    def truncate(h):
      return h % (2**253) # l has 253 bits

  if hamburg:
    context = '\0\0\0\0\0\0\0\0\0\0\0\0'
    def prf(sk,m):
      return hashlib.sha512(sk + m).digest()[:40]

  if liusvaara:
    hashid = '\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00'
    context = ''
    def selfdelim(x):
      result = ''
      n = len(x)
      while n > 128:
        result += chr(128 + (n % 128))
        n /= 128
      result += chr(n)
      return result + x

  if hamburg:
    def secretscalar(sk):
      return decodeint(prf(sk,"SCRT"))
  else:
    def secretscalarandseed(sk):
      if brown or eddsa:
        sk = H(sk)
      a = decodeint(sk[:b/8])
      if eddsa:
        a -= a % 8
        a %= 2**(b-2)
        a += 2**(b-2)
      if ford:
        return a,(sk + 'r')
      return a,sk[b/8:]
  
    def secretscalar(sk):
      return secretscalarandseed(sk)[0]
  
  def publickey(sk):
    return encodepoint(scalarmult(B,secretscalar(sk)))

  def signature(m,sk,pk):
    if hamburg:
      a = secretscalar(sk)
    else:
      a,seed = secretscalarandseed(sk)

    if brown or ladd:
      rinput = seed + m
    if eddsa:
      m = prehash(m)
      rinput = seed + m
    if hamburg:
      m = prehash(m)
      rinput = 'EPHE' + context + m
    if liusvaara:
      m = selfdelim(hashid) + selfdelim(context) + selfdelim(prehash(m))
      rinput = '\x02' + selfdelim(seed) + m
    if ford:
      rinput = m + seed + 'r'   # should pad to sponge rate

    if hamburg:
      r = prf(sk,rinput)
    else:
      r = H(rinput)

    r = decodeint(r)
    R = encodepoint(scalarmult(B,r))

    if brown or ladd:
      hinput = m + R
    if eddsa:
      hinput = R + pk + m
    if hamburg:
      hinput = 'CHAL' + context + pk + R + m
    if liusvaara:
      hinput = '\x03' + encodeint(b,16) + R + pk + m
    if ford:
      hinput = m + R + pk + 'c'

    h = H(hinput)
    inth = decodeint(h)
    if brown:
      S = ((truncate(inth) + a * decodeint(R)) * linv(r)) % l
    if eddsa or ford:
      S = (r + inth * a) % l
    if hamburg or ladd or liusvaara:
      S = (r - inth * a) % l

    if hamburg:
      return h + encodeint(S,b/8)
    else:
      return R + encodeint(S,b/8)
  
  def checkvalid(s,m,pk):
    A = decodepoint(pk)

    if hamburg:
      h = s[:hbytes]
      S = decodeint(s[hbytes:])
      R = edwards(scalarmult(B,S),scalarmult(A,decodeint(h)))
      hinput = 'CHAL' + context + pk + encodepoint(R) + prehash(m)
      if h == H(hinput): return

    else:
      R = decodepoint(s[:b/8])
      S = decodeint(s[b/8:])
  
      if brown or ladd:
        hinput = m + encodepoint(R)
      if eddsa:
        hinput = encodepoint(R) + pk + prehash(m)
      if liusvaara:
        m = selfdelim(hashid) + selfdelim(context) + selfdelim(prehash(m))
        hinput = '\x03' + encodeint(b,16) + encodepoint(R) + pk + m
      if ford:
        hinput = m + encodepoint(R) + pk + 'c'
      h = decodeint(H(hinput))
  
      if brown:
        h = truncate(h)
        h2 = decodeint(encodepoint(R))
        if scalarmult(R,S) == edwards(scalarmult(B,h),scalarmult(A,h2)): return
      if eddsa or ford:
        if scalarmult(B,S) == edwards(R,scalarmult(A,h)): return
      if ladd or liusvaara:
        if R == edwards(scalarmult(B,S),scalarmult(A,h)): return

    raise Exception('signature does not pass verification')

  # random test:
  if ladd or liusvaara:
    sk = encodeint(random.getrandbits(b*2),b/4)
  else:
    sk = encodeint(random.getrandbits(b),b/8)
  pk = publickey(sk)
  m = encodeint(random.getrandbits(472),59)
  s = signature(m,sk,pk)
  print scheme,'skbytes',len(sk),'pkbytes',len(pk),'sbytes',len(s)
  checkvalid(s,m,pk)

  if eddsa:
    # extra test against pk,s generated via ed25519.py as follows:
    # sk = ''.join([chr(random.randrange(256)) for i in range(32)])
    # pk = ed25519.publickey(sk)
    # m = ''.join([chr(random.randrange(256)) for i in range(59)])
    # s = ed25519.signature(sha256(m),sk,pk)
    # ed25519.checkvalid(s,sha256(m),pk)
    import binascii
    sk = binascii.unhexlify('8195ec0cb902363d30a5bfb85fe838f9365b26c99859742bb8e4f34c8fab5ead')
    pk = binascii.unhexlify('5eeb7aabfe0d6f6b5a5bb70c42e63fc8ddc87a0c7efe4abe71be856fa76a5813')
    m = binascii.unhexlify('ce7491b4d33527f2dba3a1d33ee83e164a0cd41056931a5b8d97d55eb2e771b00a8e6dac3442b1fe3d5b31b278d300723a212a9f37a5382ea62196')
    s = binascii.unhexlify('75fdf120a3109ae9008c5d4243f629d0a127c4458ec153eadb50376e636cb237987f3f9b9fcae354123c1ba15cbb6e4c6a8d0f8a8c47021671cc4be8be76d309')
    assert pk == publickey(sk)
    assert s == signature(m,sk,pk)
    checkvalid(s,m,pk)
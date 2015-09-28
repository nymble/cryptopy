#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Walsh Transform of Binary Sequence
    
    
    References:
        https://eprint.iacr.org/2005/299.pdf
        http://www.ii.uib.no/~matthew/SBoxLin.pdf
        http://www.ciphersbyritter.com/ARTS/MEASNONL.HTM

    Copyright (c) 2008 by Paul A. Lambert

"""

def walshTransform(t):
    """ t is a binary list """
    n = log2n(len(t))  # n not used, but asserts if n not a power of 2
    wt = len(t)*[0]
    for w in range( len(t) ):
        for x in range( len(t) ):
            wt[w] = wt[w]+(-1)**(t[x] ^ binaryInnerProduct(w,x) )
    return wt

def binaryInnerProduct(a,b):
    """  """
    ip=0
    ab = a & b
    while ab > 0:
        ip=ip^(ab&1)
        ab = ab>>1
    return ip

def nonLinearity(t):
    """ A measure of the non-linearity of a binary sequence """
    wt = walshTransform(t)
    nl = len(t)/2 - .5*max( [ abs(i) for i in wt ] )
    return nl
    
def log2n(l):
    """ Log2 of an integer only for numbers that are powers of 2 """
    x = l
    n = 0
    while x > 0:
        x=x>>1
        n=n+1
    n = n-1
    assert 2**n == l , "log2n(l) valid only for l=2**n"
    return n

if __name__ == "__main__":
    t = (1,1,0,0,1,1,0,0)
    print 't =              ', t
    print 'walsh transform =', walshTransform(t)
    print 'nonlinearity = ', nonLinearity(t)
    
    t = (1,1,0,1,0,1,1,1)
    print 't =              ', t
    print 'walsh transform =', walshTransform(t)
    print 'nonlinearity = ', nonLinearity(t)
    
    t = (0,0,1,1,1,0,1,1)
    print 't =              ', t
    print 'walsh transform =', walshTransform(t)
    print 'nonlinearity = ', nonLinearity(t)






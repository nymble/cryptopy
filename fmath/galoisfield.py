#! /usr/bin/env python
# -*- coding: utf-8 -*-
""" galoisfield.py

    Support for math operations module prime p, GF(p)
    Overloads Python operators + - / ^  ==
    Note that '^' is used for exponentiation in addition to than Python '**"
    for better maping to math references
    
        Usage example:
            gfp = GFp(2**255 - 19)
            x = gfp(x_value)
            y = x*^2+3*x+1    # math and y result in GF(p)
    
    Paul A. Lambert Copyright 2015
"""

class GFp:
    """ Support for math operations module prime p, GF(p)
    """
    def __init__(self, p):
        """ Galois Field is initialized with a prime p """
        self.p = p
        
    def __call__(self, value):
        """ Factory method to create elements in the field """
        return Element_of_GFp(self, value)
        
    def is_element(self, x):
        return (p > x > 0)
        
    def inverse(self, x):
        return inverse_mod(x, self.p)


class Element_of_GFp:
    """ Elements in a Galois Field that support operator overloading
    """
    def __init__(self, gf, value):
        self.gf = gf 
        self.value = value % self.gf.p
        
    def __add__(self, other):
        return self.gf(self.value + int(other))
    
    def __radd__(self, other):
        return self.gf(self.value + int(other))
        
    def __neg__(self):
        return self.gf(-self.value)
        
    def __sub__(self, other):
        return self.gf(self.value - int(other))
    
    def __rsub__(self, other):
        return self.gf(int(other) - self.value)
        
    def __mul__(self,other):
        return self.gf(self.value * int(other))
        
    def __rmul__(self, other):
        return self * other
    
    def __div__(self, other):
        return self.gf(int(self * self.gf.inverse(int(other))))
    
    def __rdiv__(self, other):
        return self.gf(int(other) * self.gf.inverse(self.value))
    
    def __xor__(self, other):
        return self.gf(self.value ** int(other))
    
    def __rxor__(self, other):
        return self.gf(int(other) ** self.value)
    
    def __cmp__(self, other):
        if self.value == int(other) :
            return 0
        else:
            return 1
        
    def __int__(self):
        return self.value

    def __str__(self):
        return "%d" % ( self.value )
         

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def inverse_mod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


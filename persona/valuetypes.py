#!/usr/bin/env python
""" valuetypes.py

    A collection of 'value types' to support strict type checking
    of scalar atttribute values.
    
    Copyright 2015 (c) Paul A. Lambert
"""
class Value:
    def __init__(self, value):
        pass
    
class UTF8String:
    """ A UTF8 string with explicit size limitations"""
    def __init__(self, min=1, max=32):
        self.min = min
        self.max = max
    
    def is_valid(self, value):
        try:
            value.decode('UTF-8', 'strict')
        except: # catch any error including UnicodeDecodeError
            return False
        
        return self.min < len( value ) <= self.max
        


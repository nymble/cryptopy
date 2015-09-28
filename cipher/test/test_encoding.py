#! /usr/bin/env python
# -*- coding: utf-8 -*-
""" test_encoding.py

    
    test_encoding.py (c) 2013 by Paul A. Lambert

    test_encoding.py is licensed under a
    Creative Commons Attribution 4.0 International License.
"""
import unittest
from hashlib import sha256

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))   
    from encoding import b27encode, b27decode
else:
    from ..encoding import b27encode, b27encode

class TestEncode(unittest.TestCase):
    """ """
    def test_b27(self):
        """  """

        self.assertEqual(  1, 1 )

if __name__ == '__main__':
    # stubbed for now
    # unittest.main()
    service_name = 'service.name.example'
    hash_value   = sha256( service_name  ).digest()
    usid         = hash_value[0:16]
    usib_b27     = b27encode(usid)
    print 'usid b27', usib_b27
    
    service_name = usib_b27
    hash_value   = sha256( service_name  ).digest()
    usid         = hash_value[0:16]
    usib_b27     = b27encode(usid)
    print 'usid b27', usib_b27
    
    service_name = usib_b27
    hash_value   = sha256( service_name  ).digest()
    usid         = hash_value[0:16]
    usib_b27     = b27encode(usid)
    print 'usid b27', usib_b27
    
    service_name = usib_b27
    hash_value   = sha256( service_name  ).digest()
    usid         = hash_value[0:16]
    usib_b27     = b27encode(usid)
    print 'usid b27', usib_b27
    
    service_name = usib_b27
    hash_value   = sha256( service_name  ).digest()
    usid         = hash_value[0:16]
    usib_b27     = b27encode(usid)
    print 'usid b27', usib_b27

    
    service_name = usib_b27
    hash_value   = sha256( service_name  ).digest()
    usid         = hash_value[0:16]
    usib_b27     = b27encode(usid)
    print 'usid b27', usib_b27

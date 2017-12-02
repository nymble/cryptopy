#!/usr/bin/env python
""" encoding.py

    encoding.py (c) 2016 by Paul A. Lambert
    
    licensed under a
    Creative Commons Attribution 4.0 International License.
"""

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.cipher.encoding import b27encode, b27decode, b85encode, b85decode
from cryptopy.cipher.encoding import b94encode, b94decode
  
    
if __name__ == '__main__':
    """ Examples of text encodings for 128 bit and 48 bits (USID and SID)
    """
    # calculate a USID and SID and use to demonstrate encodings
    service_name = 'service.name.example'
    from hashlib import sha256
    hash_value = sha256( service_name  ).digest()
    usid = hash_value[0:16]        # USIDs are 16 octets of the hash value
    service_id = hash_value[0:6]   # SIDs are 6 octets of the hash value
    
    print 'service name:    ', service_name
    print 'hash value:      ', hash_value.encode('hex')
    print 'usid:            ', usid.encode('hex')
    print 'usid b27         ', b27encode(usid)
    assert b27decode(b27encode(usid)) == usid  # test decode b27
    print 'usid b85         ', b85encode(usid)
    print 'usid b94:        ', b94encode(usid)    
    print 'service id:      ', service_id.encode('hex')
    print 'service id b27:  ', b27encode(service_id)
    print 'service id b85:  ', b85encode(service_id)
    print 'service id b94:  ', b94encode(service_id)
 



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
    

    
    

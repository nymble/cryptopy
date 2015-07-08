#!/usr/bin/env python
""" test_taml.py

    taml unit tests
        
    Paul A. Lambert 2015
"""
import unittest
from taml import Says, This, Has, Statement
from attributes import Group

class TestGroup(unittest.TestCase):
    """ Test the 'group' attribute       
    """
    def test_Group(self):
        g = Group( 'foo' )
        self.assertTrue( g.__str__() == 'group: foo\n' )
        
    def test_Group_invalid(self):
        invalid_test_cases = ( '', '\n', 'a\na', 33*'a' )
        

class TestStatement(unittest.TestCase):
    """ """
    def test_Statement(self):
        id1 = Id(0xababab)
        id2 = Id(0xffabab)
        g = Group( 'foo' )
        s = Statement( (Says(id), This(id2), Has((Group('foo'),)) )  )
        

if __name__ == "__main__":

    g1 = Group('home')
    g2 = Group('admin')
    h = Has((g1,g2))
    print h
    
    s = Statement((h,))
    print s
    s = Statement( (Says(id), This(id2), Has((Group('foo'),)) )  )
    
    unittest.main()
    
    
"""
    ip = IP_Address('1.2.3.4')
    print ip
    print type(ip)
    print issubclass(type(ip), EonScalar)
    print issubclass(type(ip), EonScalarRange)
    print issubclass(type(ip), EonNode)
    dns = DNS_Name('foo.bar.com')
    print dns
    
    target = This(dns)
    has = Has(ip)
    s = Statement((target, has))
    
    target = This( id )
    attribute = Group( 'foo' )
    has = Has( attribute )
    s = Statement( This(principal), Has(attribute) )
"""
"""
---
id: &alice 0xeb5fcb010e7ff002d847d0115793eb3b
---
id: &bob   0x4d94b4b92764ff613e06c2b9dfc52777
---
id: &carol 0xcaeae5b268af8b632030bb10bea8dff85
--- 
this: &alice
speaks about:
    - group: home
---
says: &alice
this: &bob
has:
    - group: home
---
says: &alice
this: &carol
speaks about:
    - group: home
"""
    

    








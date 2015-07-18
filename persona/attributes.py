#!/usr/bin/env python
""" attributes.py

    Commonly used attributes for TAML
  
  
  should all value checking be through value_type binding?
  Some attributes are very specific in structure
  ... generally -> yes
  or, perhaps point to type checking of base tag definition
  or as overloading with new tag and encoding
  

    Paul A. Lambert 2015
"""
import re
from eon import EonScalar, EonScalarRange
from valuetypes import UTF8String

class Group(EonScalar):
    """ A UTF8 printable string used to indicate membership in a group.
        ... to do, remove some special characters * , / \ : | ! & {}[]()=<>#@$^."';
        also LF FF, et
        The length of the string shall be between 1 and 32 characters.
    """
    tag = 'group'
    value_type = UTF8String(min=1, max=32)
    tag_encoding = 0x04
    
    
class FriendlyName(EonScalar):
    """ A UTF8 string used to provide a 'friendly name'
        Friendly names shall be 1 to 32 characters in length.
    """
    tag = 'friendly name'
    value_type = UTF8String(min=1, max=32)
    tag_encoding = 0x00
    
    
class DNS_Name_Range(EonScalarRange):
    """ A range of RFC-1123 compliant DNS Names (e.g.  '*.foo.bar' )
    """
    tag = 'dns name range'
    
    def is_valid(self, dns_name_range):
        """ A valid DNS Name Range is:
             - a DNS Name with a wild card prefix, or
             - a valid DNS Name """
        if len(dns_name_range) > 255:
            return False
        if dns_name_range.startswith("*."):   # asterix is wild card
            dns_name = DNS_Name( dns_name[2:] )# strip off the first two chars
        else:
            dns_name = DNS_Name( dns_name )  # single name       
        return dns_name.is_valid() #!!!!!!!!!!!!!!!!! ???????????????????


class DNS_Name(EonScalar):
    """ A RFC-1123 compliant DNS name. """
    tag = 'dns name'
    range_type = DNS_Name_Range
    tag_encoding = 0x00
    
    def is_valid(self, dns_name):
        """ DNS Name validity check compliant with RFC-1123 """
        if len(dns_name) > 255:
            return False
        if dns_name.endswith("."):   # A single trailing dot is legal
            dns_name = dns_name[:-1] # strip exactly one dot from the right
        allowed = re.compile("[a-zA-Z\d-]")
        return all(               # Split by labels and verify individually
            (label and len(label) <= 63   # length is within proper range
            and not label.startswith("-") # no hyphens in front
            and not label.endswith("-")   # no hyphens in back
            and allowed.search(label))    # contains only legal characters
            for label in dns_name.split("."))
    
        
#---------- not yet complete

class Icon():pass
class Icon(EonScalar):
    """ An image suitable for use as an icon.
        Icon type of image/png with an icon size up to 65535
    """
    tag = 'icon'
    value_type = Icon()
    tag_encoding = 0x01
    
class Time_Date_Range(EonScalarRange):pass

class Time_Date(EonScalar):
    tag = 'time date'
    #rangeType = Time__Date_Range
    def is_valid(value): raise 'not implemented'
    
class GeoLocation_Range(EonScalarRange):
    tag = 'geolocation range'
    
class GeoLocation(EonScalar):
    """ Geographic location value based on RFCxxx and W3C xxxx """
    tag = 'geolocation'
    rangeType = GeoLocation_Range   
class IPv4_Address(EonScalar): pass
class IPv4_Address_Range(EonScalarRange): pass
class IPv6_Address(EonScalar): pass
class IPv6_Address_Range(EonScalarRange): pass
class IP_Address(EonScalar): pass
class IP_Address_Range(EonScalarRange): pass
class Temperature(EonScalar): pass
class Temperature_Range(EonScalarRange): pass












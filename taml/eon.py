#!/usr/bin/env python
""" Efficient Object Notation

    Copyright 2012 (c) Paul A. Lambert
"""
#from yaml import load, dump
  
class EonError(Exception): pass

class EonNode(object):
    """ Base type for EonScalar, EonMapping and EonList """
    def __init__(self, value):
        self.indent = 0
        if self.is_valid(value):
            self.value = value
        else:
            raise EonError("Invalid value")
        
    # Following functions must be overloaded by classes based on EonType     
    def to_binary(self):
        raise NotImplementedError('binary encoding must be defined')
        
    def from_binary(self):
        raise NotImplementedError('binary decode must be defined')

    
class EonScalar(EonNode):
    """ Atomic scalar node. Subtype must define tag and value_type"""

    def is_valid(self, value):
        """ determine scalar validity based on type of value """
        return self.value_type.is_valid(value)
        
    def __str__(self):
        return '{}: {}\n'.format(self.tag, self.value)
        
    def __eq__(self, other):
        """ Compare two Scalars for equility  """
        return   self.tag == other.tag and self.value == other.value   

class EonSequence(EonNode):
    """ An ordered list """
    
    def is_valid(self, list):
        for item in list:
            if not item.is_valid(item.value):
                return False
        return True
    
    def __str__(self):
        indent_spaces = 4*self.indent*" "
        s = '{}:\n'.format(self.tag, self.value)
        for item in self.value:
            item.indent = self.indent + 1
            indent_spaces = 4*item.indent*" "
            s = s + indent_spaces + '- ' + item.__str__()
        return s

class EonMapping(EonNode):
    """ An unordered dictionary """

    def is_valid(self, dict):
        for item in dict:
            if not item.is_valid(item.value):
                return False
        raise 'xx'
        return True
        
    def __contains__(self, tag):
        pass #-------------------------------------------
        
class EonStatement(EonMapping):

    def __str__(self):
        s = '---\n'
        for item in self.value:
            s = s + item.__str__()
        return s
               
            
        
class EonScalarRange(EonNode):
    """ Atomic range value. Subtype must define tag """
    def __contains__(self, item):    # may not be useful in super class!!!
        print type(item.rangeType), type(self) #!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if type(item.rangeType) == type(self):   # item must be related
            # return self._contains(item) # subclass must define
            return True #!!!!!!!!!!!    stub ->  item.value in self.value
        else:
            raise EonError('item {} not related to range {}'.format(
                                           type(item), type(self)) )
    def _contains(self, item):
        raise NotImplementedError('Each type must overload function isValid()') 


    
        




""" EonValueTYpe -> Scalar, Mapping, List """


# Scalar Types
class Cipher_Suite(EonScalar):
    tag = 'cipher suite'
    
    def __init__(self, name):
        self.name = name
    """
    Cipher Suites need definitions ...  seems like an indirection
    or macro like mechanism
    cipher suite definition:
        name: suite z
        public key type: ECC-196 #
        etc...
    or
    def signature algorithm(self): etc
    better to have each suite be an object class
    factory-like mechanism ? or just mutate
    """
class Public_Key(EonScalar): pass

class NID(EonScalar): pass

class Time_Date_Range(EonScalarRange):
    pass

class Time_Date(EonScalar):
    tag = 'time date'  
    rangeType = Time_Date_Range
    
    def isValid(value):
        pass
    
class GeoLocation_Range(EonScalarRange):
    tag = 'geolocation range'
    pass
class GeoLocation(EonScalar):
    """ Geographic location value based on RFCxxx and W3C xxxx """
    tag = 'geolocation'
    rangeType = GeoLocation_Range
    pass
    
class IPv4_Address(EonScalar): pass
class IPv4_Address_Range(EonScalarRange): pass
class IPv6_Address(EonScalar): pass
class IPv6_Address_Range(EonScalarRange): pass
class IP_Address(EonScalar):
    tag = 'IP address'
    #valueType = IPAddress
    def isValid(self, value):
        return True
    
class IP_Address_Range(EonScalarRange):
    tag = 'IP address range'
    #valueType = IPNetwork
    def isValid(self, value):
        return True

class DNS_Name_Range(EonScalarRange):
    """ A range of DNS Names (e.g.  '*.foo.bar' )"""
    tag = 'dns name range'
    
    def isValid(self, dns_name_range):
        """ A valid DNS Name Range is:
             - a DNS Name with a wild card prefix, or
             - a valid DNS Name """
        if len(dns_name_range) > 255:
            return False
        if dns_name_range.startswith("*."):   # asterix dot is wild card
            dns_name = DNS_Name( dns_name_range[2:] )# strip off *.
        else:
            dns_name = DNS_Name( dns_name_range )  # range is a single name       
        return dns_name.isValid()

class DNS_Name(EonScalar):
    """ A RFC-1123 compliant DNS name """
    tag = 'dns name'
    rangeType = DNS_Name_Range
    
    def isValid(self, dns_name):
        """ DNS Name validity check compliant with RFC-1123 """
        if len(dns_name) > 255:
            return False
        if dns_name.endswith("."):   # A single trailing dot is legal
            dns_name = dns_name[:-1] # strip exactly one dot from the right
        allowed = re.compile("[a-zA-Z\d-]")
        return all(               # Split by labels and verify individually
            (label and                       # not zero length
             len(label) <= 63 and            # length is within proper range
             not label.startswith("-") and   # no hyphens in front
             not label.endswith("-") and     # no hyphens in back
             allowed.search(label))          # contains only legal characters
            for label in dns_name.split("."))
        

        
class Simple_Name(EonScalar): pass
class Temperature(EonScalar): pass
class Temperature_Range(EonScalarRange): pass



# Sequence Object Types
class Has(EonMapping):
    tag = 'has'
    
class This(EonSequence):
    tag = 'this'
    
class While(EonSequence): pass



class Beliefs():
    def __init__(self):
        self.statementList = []
        
    def addStatement(self, statement):
        if validate(statement):
            self.statementList.append(statement)
        else:
            raise 'invalid statement'
        
    def whoHas(self, queryAttribute):
        """ Return list of Ids that have the attribute """
        idList = []
        for statement in self.statementList:
            if 'has' in statement:
                for attrib in statement['has']:
                    if queryAttribute == attrib:
                        idList.append(statement['this'])               
                return idList                      
            else:
                raise "curently only supports 'has' statements"
           
            
            try:
                attributeList = s['has'] 
            except:
                raise 'error - no has'
            for attrib in attributeList:
                if attribute in attrib:
                    pass
                    
                

class Eonxxxxx(object):
    """ A singleton class to hold the collection of all types """
    __instance = None
    def __new__(cls):
        if Eon.__instance is None:
            Eon.__instance = object.__new__(cls)
            self = Eon.__instance
            self.__typeDict = {}
        return Eon.__instance



    
    








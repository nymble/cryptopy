#!/usr/bin/env python
""" Efficient Object Notation

    Copyright 2012 (c) Paul A. Lambert
"""
#from yaml import load, dump

class UTF8String():
    """ A variable length UTF8 string with explicit size limitations"""
    min = 1
    max = 32
    
    def is_valid(self, value):
        try:
            value.decode('UTF-8', 'strict')
        except: # catch any error including UnicodeDecodeError
            return False
        
        return self.min < len( value ) <= self.max
        
        
  
class EonError(Exception): pass

class EonType(object):
    """ Base type for Eon nodes """
    def __init__(self, value):
        if self.isValid(value):
            self.value = value
        else:
            raise EonError("Invalid value")
            
    # Following functions must be overloaded by classes based on EonType
    def isValid(self, value):
        raise NotImplementedError('Each type must overload function isValid()')
        
    def toBinary(self):
        raise NotImplementedError('binary encoding must be defined')
        
    def fromBinary(self):
        raise NotImplementedError('binary decode must be defined')

    
class EonScalar(EonType):
    """ Atomic value. Subtype must define tag """           
    def __eq__(self, other):
        """ Compare two Scalars for equility """ 
        return   self.tag == other.tag and self.value == other.value   
    
    def __contains__(self, range):
        if type(range) == self.rangeType:   # range must be related to self type
            pass
        else:
            raise
        
class EonScalarRange(EonScalar):
    pass
    
class EonSequence(EonType):
    pass

class EonMapping(EonType):
    pass








""" EonValueTYpe -> Scalar, Mapping, List """

class EonTag(): pass
class EonValue(): pass

class EonNode():
    tag = 'a'
    value = 'a'
    type = 
    
    
class EonNode(EonTagType, EonValueType):
    node_type 
    pass
    


# Scalar Types
class Cipher_Suite(EonScaler):
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
class Public_Key(EonScaler): pass

class NID(EonScaler): pass



# Sequence Object Types
class Has(EonSeqType): pass
class While(EonSeqType): pass


class Beliefs():
    def __init__(self):
        self.statementList = []
        
    def addStatement(self, statement):
        if validate(statement):
            self.statementList.append(statement)
        else:
            raise 'invalide statement'
        
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
                    
                

class Eonxxxxx(object):
    """ A singleton class to hold the collection of all types """
    __instance = None
    def __new__(cls):
        if Eon.__instance is None:
            Eon.__instance = object.__new__(cls)
            self = Eon.__instance
            self.__typeDict = {}
        return Eon.__instance



if __name__ == "__main__":
    main()








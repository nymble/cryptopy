#!/usr/bin/env python
""" taml.py

    The Attribute Management Language

    Example:
    s = Statement( Says(speaker),
                   This(target),
                   Has(attributes),
                   Signature(speaker) )
    
syntax possiblities ...
    Signature:
    sig:
    signature:
    signed: 
    says:
        id:
        signature:
        
     
     Alice says Bob has group foo   


---
says: 0X123123123123123123123
this *bob   # aias to key id made by hash
has:
    - group: foo
    - group: home
signature: 0x12123121121313




    
        
    Paul A. Lambert 2015
"""
from eon import EonScalar, EonSequence, EonStatement
class Id:pass

class Says(EonScalar):
    """ 'Says' identifies the public key acting as the speaker of the statement.
    """
    tag = 'says'
    value_type = Id()
    tag_encoding = 0x01
    
class This(EonScalar):
    """ 'This' is the target of a TAML attribute attestation.
        The target is a 'id' corresponding to the subjects public key.
    """
    tag = 'this'
    value_type = Id()
    tag_encoding = 0x02
    
class Has(EonSequence):
    """ A list of attributes that the speaking public key associates with
        the target of the statement.
    """
    tag = 'has'
    tag_encoding = 0x03

class Signature(EonScalar):
    """ The digital signature of the speaker signing the statement """
    tag = 'signature'
    #value_type = OctetString
    tag_encoding = 0x05
    
    def is_valid(self, hash, signer):
        pass

class SpeakingAs(EonScalar):
    """ """
    tag = 'speaking as'
    value_type = Id()
    tag_encoding = 0x06

class SpeaksAbout(EonSequence):
    """ A list of attribute ranges """
    tag = 'speaks about'
    value_type = Id()
    tag_encoding = 0x07
    
class While(EonSequence):
    """ A list of constraints on the statment """
    tag = 'while'
    tag_encoding = 0x08
    
class Statement(EonStatement):
    """" A map that recognizes a set of templates of tags """
    tag = None # no tag, this is a top level map holding a 'tuple'
    valid_maps = ( ( Says, This, Has, Signature ),
                   ( Says, SpeakingAs, This, Has, Signature ),
                   ( Says, This, SpeaksAbout, Signature ),
                   ( Says, This, Has, While, Signature ),
                   ( Says, SpeakingAs, This, Has, While, Signature ),
                   ( Says, This, SpeaksAbout, While, Signature ) )
    """                                                    , Source ) )
    
    local statements:
        statement: #<list of statements>
        recieved context:
            time:
            location:
            source:
        validity: <True / False>
    &statement: #<map of>
        - *Says.This.Has
        - *...
    &Says.Thas.Has: #<explicit map>
        says
        this
        ...
        
        
        
        
        
    
    """
    def is_valid(self):
        for word in statement_value:
            pass
        return True
    
    def is_v(self, has_statement):
        for statement in beliefs:
            if Has in Statement :
                for attribute in has_statment.value:
                    
            
        pass
    








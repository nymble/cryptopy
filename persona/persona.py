#!/usr/bin/env python
""" persona.py

    Persona class - abstraction of a public key and associated
    policy decision engine
    
        
    Paul A. Lambert 2015
"""
from eon import EonScalar, EonSequence, EonStatement
class Id:pass

class Persona(object):
    """ 
    """
    beliefs = []  # trust roots
    
    def is_statement_valid(self, statement, time=None, location=None, source=None):
        """ Determine if a statement is valid.
        """
        speaker = statement['says']
        for trusted_statement in self.beliefs :
            if statement <= trusted_statement :
                return True   # not quite right ....
            
            # find any statements about the speaker
            if speaker == trusted_statement['this'] :  # ? <= later
                if 'speaks about' in trusted_statement:
                    for attribute_range in statement['speaks about'] :
                        pass
                        
        if 'has' in statement:             # attestation
            pass
        elif 'speaks about' in statement:  # delegation
            pass
        elif 'speaking as' in statement:   # delegated attestation
            pass
        else:
            raise ' not a valid statement'
                        
            
        
        
        
        
        
        
    def validity_proof(self, statement):
        """ Return a validity proof for the statement """
        # Has statement
        assert ( Has in statement )
        proof = [statement,]
        speaker_id = statement[Says]
        if speaker in trusted_list:
            pass
        else:  # find references to speaker
            pass
        """
        # is statement covered by any of the root / axiom statements
        # is statement speaker a target of any statements
        [ s for
        
        statement containment
        a->b h|foo
        
        
        
        
   
        """
    def has_attribute(self, subject_id, attribute):
        """ """
        if subject_id in known_ids :
            for attribute_range in known_ids[subject_id].Has() :
                if attribute in attribute_range:
                    return True
        else:
            self.new_known_id(subject_id)
            return False
    
    def add_attribute(self, subject_id, attribute):
        """ """
        if subject_id in known_ids :
            self.known_id[subject_id].append  #### map or ist of attribute values ?????????
        else:
            self.new_known_id(subject_id)
            return False
    
    def add_belief(self, statement):
        """ """
        assert( Statement.is_valid( statement ) )

        self.beliefs.append( statement )
        
        
        
            
    
            
           
           
           
           
           









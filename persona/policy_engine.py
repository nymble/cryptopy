#!/usr/bin/env python
""" policy_engine.py


    Paul A. Lambert 2015
"""
class PolicyEngine(object):
    def __init__(self):
        pass
        
        
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
        
        
        
            
    
            
           
           
           
           
           









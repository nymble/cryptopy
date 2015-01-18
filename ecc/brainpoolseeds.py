#!/usr/bin/env python
""" brainpoolseeds.py

    Validation of the Brainpool seed value creation
    http://www.ecc-brainpool.org/download/Domain-parameters.pdf
    
    The Brainpool seed values are derived as follows:
        We need seven seeds of 160 bit, each. Therefore we
        compute the hexadecimal representation R of
        pi*2**1120 and divide it into 7 segments of 40 hexadecimal
        symbols, followed by a 'Remainder'
    
    Paul A. Lambert 2015
"""
from fractions import Fraction
   
# The first 1000 decimal digits of pi
pi1k = """    3.14159265358979323846264338327950288419716939937510
                58209749445923078164062862089986280348253421170679
                82148086513282306647093844609550582231725359408128
                48111745028410270193852110555964462294895493038196
                44288109756659334461284756482337867831652712019091
                45648566923460348610454326648213393607260249141273
                72458700660631558817488152092096282925409171536436
                78925903600113305305488204665213841469519415116094
                33057270365759591953092186117381932611793105118548
                07446237996274956735188575272489122793818301194912
                98336733624406566430860213949463952247371907021798
                60943702770539217176293176752384674818467669405132
                00056812714526356082778577134275778960917363717872
                14684409012249534301465495853710507922796892589235
                42019956112129021960864034418159813629774771309960
                51870721134999999837297804995105973173281609631859
                50244594553469083026425223082533446850352619311881
                71010003137838752886587533208381420617177669147303
                59825349042875546873115956286388235378759375195778
                18577805321712268066130019278766111959092164201989 
       """
pi_ascii = ''.join( [ l.strip() for l in pi1k.splitlines()  ] ) # ascii pi

# represent pi as a long fraction to maintain digit accuracy
num_digits = len(pi_ascii) -2  # ignore the '3.' and count other digits
pi = 3 + Fraction( int(pi_ascii[2:]), 10**num_digits)
print pi

def brainpool_seeds():
    """ Return a list of 7 numeric seed values based on pi"""
    pi = ''.join( [ l.strip() for l in pi1k.splitlines()  ] ) # ascii pi
    
    pi_10E1000 = int('3'+pi[2:])  # 1001 digits of pi as an integer * 10E1000
    
    pi_seed = ( pi_10E1000 * 2**(7*160) ) / 10**1000
    hex_seed_string = hex(pi_seed)[2:1002]   # hex ascii string
    
    # There are 40 ascii hex characters for each of the 160 bit values
    seed_list = [ int(hex_seed_string[i*40:i*40+40], 16) for i in range(7) ]
    return seed_list    

if __name__ == '__main__':
    
    for i in brainpool_seeds():
        print hex(i)
    
    
 


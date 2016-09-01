#!/usr/bin/env python
""" test_sec256k1.py
    
    Unit tests for sec256k1
    
"""
import unittest

if __name__ == '__main__' and __package__ is None:
    from os import sys, path
    p = path.abspath(__file__)  # ./cryptopy/persona/test/test_cipher_suite.py
    for i in range(4):  p = path.dirname( p )   # four levels down to project '.'
    sys.path.append( p )
    
from cryptopy.ecc.curves import SECP_256k1


class TestSECP_256k1(unittest.TestCase):
    """ 
    """
    def test_n_times_G(self):
        """ Test that n*G = Identity """
        c = SECP_256k1()
        IDENTITY = c.identity()
        G = c.generator()
        self.assertEqual( c.n * G, IDENTITY )
        
    def test_stackEx_1(self):
        """ from http://crypto.stackexchange.com/questions/784/are-there-any-secp256k1-ecdsa-test-examples-available/787#787 """
        c = SECP_256k1()
        G = c.generator()
        
        m = 0xAA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522
        X = 0x34F9460F0E4F08393D192B3C5133A6BA099AA0AD9FD54EBCCFACDFA239FF49C6
        Y = 0x0B71EA9BD730FD8923F6D25A7A91E7DD7728A960686CB5A901BB419E0F2CA232
        M = m*G
        self.assertEqual( M.x, X )
        self.assertEqual( M.y, Y )
        
        m = 0x7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3
        X = 0xD74BF844B0862475103D96A611CF2D898447E288D34B360BC885CB8CE7C00575
        Y = 0x131C670D414C4546B88AC3FF664611B1C38CEB1C21D76369D7A7A0969D61D97D
        M = m*G
        self.assertEqual( M.x, X )
        self.assertEqual( M.y, Y )
        
        m = 0x6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D
        X = 0xE8AECC370AEDD953483719A116711963CE201AC3EB21D3F3257BB48668C6A72F
        Y = 0xC25CAF2F0EBA1DDB2F0F3F47866299EF907867B7D27E95B3873BF98397B24EE1
        M = m*G
        self.assertEqual( M.x, X )
        self.assertEqual( M.y, Y )
        
        m = 0x376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC
        X = 0x14890E61FCD4B0BD92E5B36C81372CA6FED471EF3AA60A3E415EE4FE987DABA1
        Y = 0x297B858D9F752AB42D3BCA67EE0EB6DCD1C2B7B0DBE23397E66ADC272263F982
        M = m*G
        self.assertEqual( M.x, X )
        self.assertEqual( M.y, Y )
        
        m = 0x1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9
        X = 0xF73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3
        Y = 0xF449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE
        M = m*G
        self.assertEqual( M.x, X )
        self.assertEqual( M.y, Y )

    def test_BIP_0032_01(self):
        """ Test vector from: https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        """
        curve = SECP_256k1()
        secret_key = 0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        #public_key = 0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
        public_key = 0x39a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
        # ! bitcoin encodes using ANSI 1 octet for compresion. leading 0x03 removed manually
        G = curve.generator()
        P = secret_key*G
        self.assertEqual( public_key, P.x )

if __name__ == '__main__':
    unittest.main()
import numpy as np
from math import *

# 1.1
import base64

def hex_to_bytes(h):
    '''Converts hex-encoded string to byte array'''
    return bytearray(h.decode("hex"))

def bytes_to_base64(b):
    '''Converts byte array to base64-encoded string'''
    return base64.b64encode(b)

def hex_to_base64(h):
    '''Converts hex-encoded string to base64-encoded string'''
    return bytes_to_base64(hex_to_bytes(h))

# 1.2
def fixed_xor(b1, b2):
    '''Produces the XOR combination of two equal-length byte arrays'''
    if len(b1) != len(b2):
        raise ValueError('input byte arrays must be of the same length', b1, b2)
    return bytearray([i^j for i,j in zip(b1, b2)])
    
def fixed_xor_hex(h1, h2):
    '''Produces the XOR combination of two equal-length hex-encoded strings'''
    return fixed_xor(hex_to_bytes(h1), hex_to_bytes(h2))

def bytes_to_hex(b):
    '''Converts byte array to hex-encoded string'''
    return ''.join('%02x' % byte for byte in b)
import matplotlib.pyplot as plt
import numpy as np
from math import *
import pandas as pd

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


# 1.3
def single_byte_xor(bs, b):
    '''Produces the XOR combination of a byte array with a single byte'''
    return fixed_xor(bs, bytearray([b]*len(bs)))

df = pd.read_csv('Data/LetterFrequency.tsv', delimiter='\t')
frequencies = {key: value for key, value in zip(df.Letter, df.Frequency)}

def english_score_byte(b):
    '''Scores an ascii-encoded byte, based on English letter frequencies.'''
    c = chr(b)
    if c == ' ':
        return log10(1/5.1) # the average English word is 5.1 letters long
    
    if str.isalpha(c):
        return frequencies[c.lower()]
    
    # nonstandard ascii characters
    if b < 32 or b > 126:
        return log10(1e-10)
    
    # standard non-alpha ascii characters
    return log10(1e-6)

def english_score(bs):
    '''Scores an ascii-encoded byte array, based on English letter frequencies.'''
    return sum([english_score_byte(b) for b in bs])

def bytes_to_ascii(b):
    '''Converts byte array to ascii-encoded string'''
    return b.decode('ascii')

def decrypt_single_byte_xor(bs):
    '''Returns the most-likely key and decrypted text for a byte array encrypted with single byte XOR'''
    return sorted([(key, single_byte_xor(bs, key)) for key in xrange(255)], \
                  key = lambda x: english_score(x[1]), \
                  reverse = 1)[0]


# 1.4
def find_single_byte_xor_encryption(byte_arrays):
    '''Finds the index, original byte array, key, and decrypted string of the 
    byte array most likely to have been encrypted with single byte XOR.'''
    return sorted([(i, bs) + decrypt_single_byte_xor(bs) for i, bs in enumerate(byte_arrays)],
                  key = lambda x: english_score(x[3]),
                  reverse = 1)[0]


# 1.5
def repeating_key_xor(bs, key):
    '''Encrypts a byte array using repeating-key (byte array) XOR'''
    key_multiplier = len(bs) / len(key) + 1
    repeated_key = (key * key_multiplier)[:len(bs)]
    return fixed_xor(bs, repeated_key)
    
def repeating_strkey_xor(bs, strkey):
    '''Encrypts a byte array using repeating-key (string) XOR'''
    return repeating_key_xor(bs, bytearray(strkey))


# 1.6
def hamming_distance(b1, b2):
    '''Finds the bit-wise edit distance / Hamming distance between two byte arrays'''
    return sum(['{0:b}'.format(b).count('1') for b in fixed_xor(b1, b2)])

def hamming_distance_str(s1, s2):
    '''Finds the bit-wise edit distance / Hamming distance between two ascii-encoded strings'''
    return hamming_distance(bytearray(s1), bytearray(s2))

def base64_to_bytes(s):
    '''Converts base64-encoded string to byte array'''
    return bytearray(base64.b64decode(s))

def find_keysize_distances(bytes, keysizes):
    '''Returns the average Hamming distance for a given keysize'''
    return [np.mean([hamming_distance(bytes[i*keysize:(i+1)*keysize],
                                      bytes[(i+1)*keysize:(i+2)*keysize]) / keysize
                     for i in xrange(len(bytes)/keysize - 1)])
            for keysize in keysizes]

def decrypt_vigenere_with_known_keysize(bytes, keysize):
    '''Returns the most likely key and plaintext message, given a bytearray ciphertext and keysize'''
    keys, plaintexts = zip(*[decrypt_single_byte_xor(bytes[block::keysize]) for block in xrange(keysize)])
    return str(bytearray(keys)), str(bytearray(sum(zip(*plaintexts), ())))

def decrypt_vigenere(bytes, keysizes):
    '''Returns the most likely key and plaintext message, given a bytearray ciphertext and list of possible keysizes'''
    optimal_keysize = keysizes[np.argmin(find_keysize_distances(bytes, keysizes))]
    return decrypt_vigenere_with_known_keysize(bytes, optimal_keysize)
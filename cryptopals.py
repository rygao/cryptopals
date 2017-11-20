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


# 1.7
from Crypto.Cipher import AES
def decrypt_AES_128_ECB(ciphertext, key):
    '''Decrypts a ciphertext string from a known key, using AES-128 in ECB mode.'''
    if len(key) != 16:
        raise ValueError('Key for AES-128 must be 16 bytes')
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

def decrypt_AES_128_ECB_base64(ciphertext_base64, key):
    return decrypt_AES_128_ECB(str(base64_to_bytes(ciphertext_base64)), key)


# 1.8
def find_ECB_encryption(ciphertexts, block_size=16):
    '''Finds the ciphertext (in byte array format) most likely to have been encryted using ECB,
       due to low Hamming distance between blocks.'''
    hamming_distances = []
    for ct in ciphertexts:
        n_blocks = len(ct) / block_size
        avg_distance = np.mean([hamming_distance(ct[i*block_size:(i+1)*block_size],
                                                 ct[j*block_size:(j+1)*block_size])
                                for i in xrange(n_blocks)
                                for j in xrange(i)])
        hamming_distances.append(avg_distance)
        
    return ciphertexts[np.argmin(hamming_distances)]


# 2.9
def pad_pkcs7(bytes, block_size=16):
    '''Pad a byte array using the PKCS #7 scheme.'''
    bytes_needed = block_size * int(ceil(len(bytes) / float(block_size))) - len(bytes)
    return bytes + bytearray([bytes_needed])*bytes_needed


# 2.10
def encrypt_AES_128_ECB(plaintext, key):
    BLOCK_SIZE = 16
    '''Encrypts a plaintext string using a given key, using AES-128 in ECB mode.'''
    if len(key) != BLOCK_SIZE:
        raise ValueError('Key for AES-128 must be %d bytes' % BLOCK_SIZE)
    
    padded_plaintext = str(pad_pkcs7(plaintext, BLOCK_SIZE))
    return AES.new(key, AES.MODE_ECB).encrypt(padded_plaintext)

def encrypt_AES_128_ECB_base64(plaintext_base64, key):
    return encrypt_AES_128_ECB(str(base64_to_bytes(plaintext_base64)), key)

def encrypt_AES_128_CBC(plaintext, key, IV):
    BLOCK_SIZE = 16
    '''Encrypts a plaintext string using a given key (str) and IV (str), using AES-128 in CBC mode.'''
    if len(key) != BLOCK_SIZE:
        raise ValueError('Key for AES-128 must be %d bytes' % BLOCK_SIZE)
        
    if len(IV) != BLOCK_SIZE:
        raise ValueError('IV for AES-128 in CBC mode must be %d bytes' % BLOCK_SIZE)
    
    AES_128_ECB = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad_pkcs7(plaintext, BLOCK_SIZE)
    
    ciphertext = b''
    for start_idx in xrange(0, len(padded_plaintext), BLOCK_SIZE):
        block_cipher_input = fixed_xor(bytearray(IV), padded_plaintext[start_idx : start_idx+BLOCK_SIZE])
        block_cipher_output = AES_128_ECB.encrypt(str(block_cipher_input))
        ciphertext += block_cipher_output
        IV = block_cipher_output
    
    return ciphertext

def decrypt_AES_128_CBC(ciphertext, key, IV):
    BLOCK_SIZE = 16
    '''Decrypts a ciphertext string using a given key (str) and IV (str), using AES-128 in CBC mode.'''
    if len(key) != BLOCK_SIZE:
        raise ValueError('Key for AES-128 must be %d bytes' % BLOCK_SIZE)
        
    if len(IV) != BLOCK_SIZE:
        raise ValueError('IV for AES-128 in CBC mode must be %d bytes' % BLOCK_SIZE)
    
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError('Ciphertext for AES-128 in CBC mode must be a multiple of %d bytes' % BLOCK_SIZE)
        
    AES_128_ECB = AES.new(key, AES.MODE_ECB)
    
    plaintext = b''
    for start_idx in xrange(0, len(ciphertext), BLOCK_SIZE):
        block_cipher_input = ciphertext[start_idx : start_idx+BLOCK_SIZE]
        block_cipher_output = AES_128_ECB.decrypt(str(block_cipher_input))
        plaintext += fixed_xor(bytearray(IV), bytearray(block_cipher_output))
        IV = block_cipher_input
    
    return plaintext


# 2.11
def generate_random_bytes(length=16):
    '''Generates a random 16-byte AES key'''
    return ''.join(map(chr, np.random.randint(256, size=length)))

def ECB_CBC_encryption_oracle(plaintext):
    '''Oracle that randomly chooses ECB or CBC mode and encrypts with a random key and IV.'''
    prepended_bytes = generate_random_bytes(np.random.randint(5,11))
    appended_bytes = generate_random_bytes(np.random.randint(5,11))
    plaintext = str(pad_pkcs7(prepended_bytes + plaintext + appended_bytes))
    
    key, IV = generate_random_bytes(), generate_random_bytes()
    cipher = AES.new(key, AES.MODE_ECB) if np.random.randint(2) == 0 else AES.new(key, AES.MODE_CBC, IV=IV)
    return cipher.encrypt(plaintext)

from collections import Counter
def detect_ECB_CBC_oracle(black_box, BLOCK_SIZE=16):
    '''Detector that determines if a black box is encrypting using ECB or CBC.'''
    long_repeating_string = str(hex_to_bytes('0'*128))
    
    ciphertext = black_box(long_repeating_string)
    ciphertext_blocks = Counter([ciphertext[i:i+BLOCK_SIZE] for i in xrange(0,len(ciphertext),BLOCK_SIZE)])
    ct_blocks_are_unique = max(ciphertext_blocks.values()) == 1
    return 'CBC' if ct_blocks_are_unique else 'ECB'


# 2.12
def appending_ECB_oracle(plaintext, key):
    '''Oracle that appends a mystery string to the plaintext input before encrypting via ECB.'''
    unknown_string = base64_to_bytes('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    plaintext = str(pad_pkcs7(plaintext + unknown_string))
    
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)

def find_unknown_string_from_appending_oracle():
    # generate consistent but unknown key
    consistent_unknown_key = generate_random_bytes()
    
    # find block size
    BLOCK_SIZE = 1
    while True:
        ct = appending_ECB_oracle('A'*2*BLOCK_SIZE, consistent_unknown_key)
        if ct[0:BLOCK_SIZE] == ct[BLOCK_SIZE:2*BLOCK_SIZE]:
            break
        BLOCK_SIZE += 1
    assert(BLOCK_SIZE == 16)
        
    # ensure the cipher is ECB
    assert(detect_ECB_CBC_oracle(lambda x: appending_ECB_oracle(x, consistent_unknown_key)) == 'ECB')
    
    # find unknown message, one byte at a time
    hidden_string = ''
    
    while True:
        idx_next_letter = len(hidden_string)
        idx_start_of_block = idx_next_letter - idx_next_letter%BLOCK_SIZE
        short_pt = chr(0)*(BLOCK_SIZE-1-idx_next_letter%BLOCK_SIZE)

        ct_block_to_char_map = {}
        for i in xrange(256):
            pt = short_pt + hidden_string + chr(i)
            ct = appending_ECB_oracle(pt, consistent_unknown_key)
            unknown_block = ct[idx_start_of_block:idx_start_of_block+BLOCK_SIZE]
            ct_block_to_char_map[unknown_block] = chr(i)

        ct = appending_ECB_oracle(short_pt, consistent_unknown_key)
        unknown_block = ct[idx_start_of_block:idx_start_of_block+BLOCK_SIZE]
        if unknown_block not in ct_block_to_char_map:
            # signals end of message because padding bytes don't match any possible
            return hidden_string[:-1]
        hidden_string += ct_block_to_char_map[unknown_block]


# 2.13
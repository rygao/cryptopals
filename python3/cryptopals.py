import matplotlib.pyplot as plt
import numpy as np
from math import *
import pandas as pd

# 1.1
import base64

def hex_to_bytes(h):
    '''Converts hex-encoded string to byte array'''
    return bytes.fromhex(h)

def bytes_to_base64(b):
    '''Converts byte array to base64-encoded string'''
    return base64.b64encode(b)

def hex_to_base64(h):
    '''Converts hex-encoded string to base64-encoded string'''
    return bytes_to_base64(hex_to_bytes(h)).decode()


# 1.2
def fixed_xor(b1, b2):
    '''Produces the XOR combination of two equal-length byte arrays'''
    if len(b1) != len(b2):
        raise ValueError('input byte arrays must be of the same length', b1, b2)
    return bytes([i^j for i,j in zip(b1, b2)])
    
def fixed_xor_hex(h1, h2):
    '''Produces the XOR combination of two equal-length hex-encoded strings'''
    return fixed_xor(hex_to_bytes(h1), hex_to_bytes(h2))

def bytes_to_hex(b):
    '''Converts byte array to hex-encoded string'''
    return ''.join('%02x' % byte for byte in b)


# 1.3
def single_byte_xor(bs, b):
    '''Produces the XOR combination of a byte array with a single byte'''
    return fixed_xor(bs, bytes([b]*len(bs)))

df = pd.read_csv('../Data/LetterFrequency.tsv', delimiter='\t')
frequencies = {key: value for key, value in zip(df.Letter, df.Frequency)}

def english_score_byte(b):
    '''Scores an ascii-encoded byte, based on English letter frequencies.'''
    c = chr(b)
    if c == ' ':
        return log10(1/5.1) # the average English word is 5.1 letters long
    
    if c.lower() in frequencies:
        return log10(frequencies[c.lower()])
    
    # nonstandard ascii characters
    if b < 32 or b > 126:
        return log10(1e-10)
    
    # standard non-alpha ascii characters
    return log10(1e-4)

def english_score(bs):
    '''Scores an ascii-encoded byte array, based on English letter frequencies.'''
    return sum([english_score_byte(b) for b in bs])

def bytes_to_ascii(b):
    '''Converts byte array to ascii-encoded string'''
    return b.decode('ascii')

def decrypt_single_byte_xor(bs):
    '''Returns the most-likely key and decrypted text for a byte array encrypted with single byte XOR'''
    return sorted([(key, single_byte_xor(bs, key)) for key in range(255)],
                  key = lambda x: english_score(x[1]),
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
    key_multiplier = len(bs) // len(key) + 1
    repeated_key = (key * key_multiplier)[:len(bs)]
    return fixed_xor(bs, repeated_key)
    
def repeating_strkey_xor(bs, strkey):
    '''Encrypts a byte array using repeating-key (string) XOR'''
    return repeating_key_xor(bs, strkey.encode())


# 1.6
def hamming_distance(b1, b2):
    '''Finds the bit-wise edit distance / Hamming distance between two byte arrays'''
    return sum(['{0:b}'.format(b).count('1') for b in fixed_xor(b1, b2)])

def hamming_distance_str(s1, s2):
    '''Finds the bit-wise edit distance / Hamming distance between two ascii-encoded strings'''
    return hamming_distance(s1.encode(), s2.encode())

def base64_to_bytes(s):
    '''Converts base64-encoded string to byte array'''
    return base64.b64decode(s)

def find_keysize_distances(bs, keysizes):
    '''Returns the average Hamming distance for a given keysize'''
    return [np.mean([hamming_distance(bs[i*keysize:(i+1)*keysize],
                                      bs[(i+1)*keysize:(i+2)*keysize]) // keysize
                     for i in range(len(bs)//keysize - 1)])
            for keysize in keysizes]

def decrypt_vigenere_with_known_keysize(ciphertext, keysize):
    '''Returns the most likely key and plaintext message, given a bytearray ciphertext and known keysize'''
    keys, plaintexts = zip(*[decrypt_single_byte_xor(ciphertext[block::keysize]) for block in range(keysize)])
    return bytes(keys).decode(), bytes(sum(zip(*plaintexts), ())).decode()

def decrypt_vigenere(ciphertext, keysizes):
    '''Returns the most likely key and plaintext message, given a bytearray ciphertext and list of possible keysizes'''
    optimal_keysize = keysizes[np.argmin(find_keysize_distances(ciphertext, keysizes))]
    return decrypt_vigenere_with_known_keysize(ciphertext, optimal_keysize)


# 1.7
from Crypto.Cipher import AES
def decrypt_AES_128_ECB(ciphertext, key):
    '''Decrypts a ciphertext byte array with a known key, using AES-128 in ECB mode.'''
    if len(key) != 16:
        raise ValueError('Key for AES-128 must be 16 bytes')
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext).decode()

def decrypt_AES_128_ECB_base64(ciphertext_base64, key):
    '''Decrypts a ciphertext base64-encoded string with a known key, using AES-128 in ECB mode.'''
    return decrypt_AES_128_ECB(base64_to_bytes(ciphertext_base64), key)


# 1.8
def find_ECB_encryption(ciphertexts, block_size=16):
    '''Finds the ciphertext (in byte array format) most likely to have been encryted using ECB,
       due to low Hamming distance between blocks.'''
    hamming_distances = []
    for ct in ciphertexts:
        n_blocks = len(ct) // block_size
        avg_distance = np.mean([hamming_distance(ct[i*block_size:(i+1)*block_size],
                                                 ct[j*block_size:(j+1)*block_size])
                                for i in range(n_blocks)
                                for j in range(i)])
        hamming_distances.append(avg_distance)
        
    return ciphertexts[np.argmin(hamming_distances)]


# 2.9
def to_bytes(s):
    '''Converts a string or bytearray to bytes.'''
    if type(s) is str:
        return s.encode()
    return bytes(s)

def pad_pkcs7(b, block_size=16):
    '''Pad a bytearray or string using the PKCS #7 scheme.'''
    b = to_bytes(b)
    bytes_needed = block_size - len(b) % block_size
    return b + bytes([bytes_needed])*bytes_needed


# 2.10
def encrypt_AES_128_ECB(plaintext, key):
    BLOCK_SIZE = 16
    '''Encrypts a plaintext string using a given key, using AES-128 in ECB mode.'''
    if len(key) != BLOCK_SIZE:
        raise ValueError('Key for AES-128 must be %d bytes' % BLOCK_SIZE)
    
    padded_plaintext = pad_pkcs7(plaintext, BLOCK_SIZE)
    return AES.new(key, AES.MODE_ECB).encrypt(padded_plaintext)


def encrypt_AES_128_ECB_base64(plaintext_base64, key):
    return encrypt_AES_128_ECB(base64_to_bytes(plaintext_base64), key)


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
    for start_idx in range(0, len(padded_plaintext), BLOCK_SIZE):
        block_cipher_input = fixed_xor(bytes(IV), padded_plaintext[start_idx : start_idx+BLOCK_SIZE])
        block_cipher_output = AES_128_ECB.encrypt(bytes(block_cipher_input))
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
    for start_idx in range(0, len(ciphertext), BLOCK_SIZE):
        block_cipher_input = ciphertext[start_idx : start_idx+BLOCK_SIZE]
        block_cipher_output = AES_128_ECB.decrypt(bytes(block_cipher_input))
        plaintext += fixed_xor(bytes(IV), bytes(block_cipher_output))
        IV = block_cipher_input
    
    return plaintext.decode()


# 2.11
def generate_random_bytes(length=16):
    '''Generates a random 16-byte AES key'''
    return bytes(list(np.random.randint(256, size=length)))

def ECB_CBC_encryption_oracle(plaintext, print_cipher_mode=False):
    '''Oracle that randomly chooses ECB or CBC mode and encrypts the plaintext string with a random key and IV.'''
    prepended_bytes = generate_random_bytes(np.random.randint(5,11))
    appended_bytes = generate_random_bytes(np.random.randint(5,11))
    plaintext = pad_pkcs7(prepended_bytes + to_bytes(plaintext) + appended_bytes)
    
    key, IV = generate_random_bytes(), generate_random_bytes()
    cipher = AES.new(key, AES.MODE_ECB) if np.random.randint(2) == 0 else AES.new(key, AES.MODE_CBC, IV=IV)
    if print_cipher_mode:
        print('MODE_ECB' if cipher.mode == 1 else 'MODE_CBC' if cipher.mode == 2 else 'Other')
    return cipher.encrypt(plaintext)

from collections import Counter
def detect_ECB_CBC_oracle(black_box, BLOCK_SIZE=16):
    '''Detector that determines if a black box is encrypting using ECB or CBC.'''
    long_repeating_string = hex_to_bytes('0'*128)
    
    ciphertext = black_box(long_repeating_string)
    ciphertext_blocks = Counter([ciphertext[i:i+BLOCK_SIZE] for i in range(0,len(ciphertext),BLOCK_SIZE)])
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
def kv_parser(s):
    return {i[:i.find('=')] : i[i.find('=')+1:] for i in s.strip().split('&') if i.find('=') > 0}

import uuid
def profile_for(useremail):
    return f'email={useremail.replace("&", "").replace("=", "")}&uid={uuid.uuid4()}&role=user'

def unpad_pkcs7(b, block_size=16):
    '''Unpad a bytearray or string using the PKCS #7 scheme.'''
    last_byte = ord(to_bytes(b[-1:]))
    return b[:-last_byte]

def encrypt_user_profile(useremail, key):
    return encrypt_AES_128_ECB(profile_for(useremail), key)

def decrypt_user_profile(ciphertext, key):
    return kv_parser(unpad_pkcs7(decrypt_AES_128_ECB(ciphertext, key)))

def construct_admin_ciphertext():
    def oracle(useremail):
        return encrypt_user_profile(useremail, consistent_unknown_key)

    # probe for last block containing 'admin' and padding
    probe_email = (AES.block_size - len('email=')) * chr(0) + pad_pkcs7('admin').decode()
    admin_last_block = oracle(probe_email)[AES.block_size : 2*AES.block_size]

    # probe block length
    malicious_email = 'm@licio.us'
    base_len = len(oracle(malicious_email))
    while True:
        malicious_email = 'x'+malicious_email
        if len(oracle(malicious_email)) > base_len:
            break
    malicious_email = 'x'*len('user') + malicious_email

    # copy-and-paste admin block
    ct = oracle(malicious_email)
    malicious_ct = ct[:-16] + admin_last_block

    return malicious_ct


# 2.14
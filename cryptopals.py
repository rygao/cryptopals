import numpy as np
from math import *

# 1.1
import base64

def hex_to_bytes(h):
    return bytearray(h.decode("hex"))

def bytes_to_base64(b):
    return base64.b64encode(b)

def hex_to_base64(h):
    return bytes_to_base64(hex_to_bytes(h))
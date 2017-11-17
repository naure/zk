
import sys
from hashlib import sha3_256

if sys.version[0] == '2':
    safe_ord = ord
else:
    safe_ord = lambda x: x

def to_bytes(obj):
    return bytes(str(obj), "utf8")

def bytes_to_int(x):
    o = 0
    for b in x:
        o = (o << 8) + safe_ord(b)
    return o

def str_to_int(x):
    return bytes_to_int(to_bytes(x))

def hashBytes(data):
    return sha3_256(data).hexdigest()

def hashObject(obj):
    return sha3_256(to_bytes(obj)).hexdigest()

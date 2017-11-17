""" Prove that some items are a subset of a committed set.

TODO: Somehow limit the set size, for instance with a min-hash scheme.
"""

#%% Hash and bytes utilities
import sys
import math
from hashlib import sha3_256
import gmpy2

HASH_BYTES = 16

safe_ord = ord if sys.version[0] == '2' else lambda x: x

def to_bytes(obj):
    return bytes(str(obj), "utf8")

def bytes_to_int(x):
    o = 0
    for b in x:
        o = (o << 8) + safe_ord(b)
    return o


def intHash(data):
    h = sha3_256(data).digest()
    i = bytes_to_int(h[:HASH_BYTES])
    return i

def primeHash(data):
    " Derive a prime from the data. "
    i = intHash(data)
    p = int(gmpy2.next_prime(i))
    return p


def bits(n):
    return math.ceil(math.log2(n))


def pows(g, exponents, mod):
    " Successive exponentiations in a group of unknown order. "
    y = g
    for e in exponents:
        y = pow(y, int(e), mod)
    return y


class SubsetProverRsa(object):
    " Same as plain, but pass the commit through the group. Verifier needs an extra subset-dependent proof. "

    # Using the RSA-2048 challenge modulus.
    # The factors and group order, equivalent to the private key, are believed to be unknown!
    # https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
    MOD = RSA2048 = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357;
    # Any prime or coprime is a generator.
    G = 2**256 - 2**32 - 977
    assert gmpy2.is_prime(G)
    assert MOD % G != 0

    def __init__(self, items):
        self.intHashes = self.hashItems(items)
        assert len(items) == len(set(self.intHashes)), "Duplicates are not supported yet."

    def hashItems(self, items):
        return [primeHash(to_bytes(o)) for o in items]

    def commit(self):
        return pows(self.G, self.intHashes, self.MOD)

    def proveSubset(self, subset):
        # hash(items not in subset)
        # Equivalent to commit / hash(subset)
        # TODO: Support duplicates
        subsetHashes = self.hashItems(subset)
        otherExponents = set(self.intHashes).difference(subsetHashes)
        return pows(self.G, otherExponents, self.MOD)

    def verifySubset(self, subset, proof, commit):
        subsetHashes = self.hashItems(subset)
        actual = pows(proof, subsetHashes, self.MOD)
        return actual == commit


SubsetProver = SubsetProverRsa


#%% Example of using SubsetProver
if __name__ == "__main__":
    import math
    import numpy as np

    fullSet    = np.array([3, 12, 17, 23, 35, 99] + list(range(100,200)))
    subset     = np.array([   12,     23        ])
    complement = np.array([3,     17,     35, 99] + list(range(100,200)))
    # Equivalent: set(fullSet).difference(subset)

    sp = SubsetProver(fullSet)
    commit = sp.commit(); print("Commitment:", bits(commit), "bits")
    proof = sp.proveSubset(subset); print("Proof:", bits(proof), "bits")
    assert sp.verifySubset(subset, proof, commit)
    print("Accepted correct proof!")

    proofWrong = sp.proveSubset(["5"])
    assert not sp.verifySubset(["5"], proofWrong, commit)
    print("Rejected incorrect proof!")

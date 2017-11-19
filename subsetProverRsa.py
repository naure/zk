"""
Cryptographic accumulator.
Prove that some items are a subset of a committed set.

TODO: Somehow limit the set size, for instance with a min-hash scheme.
"""

#%% Hash and bytes utilities
import sys
import math
from hashlib import sha3_256
import numpy as np
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


def prod(xs):
    y = 1
    for x in xs:
        y *= x
    return y

def pows(g, exponents, mod):
    " Successive exponentiations in a group of unknown order. "
    y = g
    for e in exponents:
        y = pow(y, int(e), mod)
    return y

def extended_euclidean_algorithm(a, b):
    """
    Returns a three-tuple (gcd, x, y) such that
    a * x + b * y == gcd, where gcd is the greatest
    common divisor of a and b.

    This function implements the extended Euclidean
    algorithm and runs in O(log b) in the worst case.
    """
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


class MaxHash(object):
    # 5 buckets of 6 bytes / 262144 values.
    def __init__(self):
        self.maxs = [0] * 5

    def add(self, h):
        for i in range(5):
            v = bytes_to_int(h[6*i : 6*(i+1)])
            if v > self.maxs[i]:
                self.maxs[i] = v
        return h


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
        self.intHashes, self.maxs = self.hashItems(items)
        assert len(items) == len(set(self.intHashes)), "Duplicates are not supported yet."

    def hashItems(self, items):
        primes = []
        maxHash = MaxHash()

        for o in items:
            h = sha3_256(to_bytes(o)).digest()

            # Derive a prime from the data.
            i = bytes_to_int(h[:HASH_BYTES])
            p = int(gmpy2.next_prime(i))
            primes.append(p)

            # Track maxs
            maxHash.add(h)

        return primes, maxHash.maxs

    def commit(self):
        return [pows(self.G, self.intHashes, self.MOD), self.maxs]

    def proveSubset(self, subset):
        # hash(items not in subset)
        # Equivalent to commit / hash(subset)
        # TODO: Support duplicates
        subsetHashes, maxs = self.hashItems(subset)
        otherExponents = set(self.intHashes).difference(subsetHashes)
        return pows(self.G, otherExponents, self.MOD)

    def verifySubset(self, subset, proof, commit):
        subsetHashes, subsetMaxs = self.hashItems(subset)
        actual = pows(proof, subsetHashes, self.MOD)

        commitNum, commitMaxs = commit
        maxOk = np.all(np.array(subsetMaxs) <= np.array(commitMaxs))
        # TODO: Verify estimated cardinality

        return actual == commitNum and maxOk

    def proveDisjoint(self, disjoint):
        # From https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf

        u = prod(self.intHashes)
        # commit == pow(G, u, MOD)
        x = prod(self.hashItems(disjoint)[0])

        gcd, a, b = extended_euclidean_algorithm(u, x); gcd
        if gcd != 1:
            print("Warning: Some members of X are in the commited set, we cannot prove that they are disjoint!")
            return [0, 0]

        # TODO: Bring the value of a under a maximum size:
        # k=?; a = a + k * x; b = b - k * u

        d = pow(sp.G, -b, sp.MOD)
        return [a, d]

    def verifyDisjoint(self, disjoint, proof, commit):
        # TODO: validate proof values explicitely
        disjointHashes, _ = self.hashItems(disjoint)
        a, d = proof
        d_x = (pows(d, disjointHashes, self.MOD) * self.G) % self.MOD
        c_a = pow(commit[0], a, self.MOD)
        return d_x == c_a


SubsetProver = SubsetProverRsa


#%% Example of using SubsetProver
if __name__ == "__main__":
    import math
    import numpy as np

    fullSet    = np.array([3, 12, 17, 23, 35, 99]) # + list(range(100,200)))
    subset     = np.array([   12,     23        ])
    complement = np.array([3,     17,     35, 99]) # + list(range(100,200)))
    disjoint   = np.array([                        5, 6])
    mixed      = np.array([           23,          5, 6])

    sp = SubsetProver(fullSet)
    commit = sp.commit(); print("Commitment:", bits(commit[0]), "bits")

    proofSubset = sp.proveSubset(subset); print("Proof:", bits(proofSubset), "bits")
    assert sp.verifySubset(subset, proofSubset, commit)
    print("Accepted correct proof of subset!")

    cheatDisjoint = sp.proveSubset(disjoint)
    assert not sp.verifySubset(disjoint, cheatDisjoint, commit)
    print("Rejected incorrect proof for a disjoint set!")

    cheatMixed = sp.proveSubset(mixed)
    assert not sp.verifySubset(mixed, cheatMixed, commit)
    print("Rejected incorrect proof for an overlapping set!")

    proofNonSubset = sp.proveDisjoint(disjoint)
    assert sp.verifyDisjoint(disjoint, proofNonSubset, commit)
    print("Accepted correct proof of non-subset!")

    cheatNotSubset = sp.proveDisjoint(subset)
    assert not sp.verifyDisjoint(subset, cheatNotSubset, commit)
    print("Rejected incorrect proof of non-subset (subset)!")

    cheatNotMixed = sp.proveDisjoint(mixed)
    assert not sp.verifyDisjoint(mixed, cheatNotMixed, commit)
    print("Rejected incorrect proof of non-subset (mixed)!")

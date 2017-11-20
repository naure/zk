"""
Cryptographic accumulator.
Prove that some items are a subset of a committed set.

Commit to an array of values, based on the sets of zeros and ones in binary representations of values.

Treat each prime p as a slot holding a binary number:
0 = Do not include p it and prove non-membership.
1 = Include p and prove membership.

To encode an array of values, use several consecutive slots to
include/exclude the bits of each value.

Alternative for small values v, or to prove range (a <= v < b):
Let each slot p store a value v. Include p^v in the set and:
Prove that p^a is a member, so v >= a.
Prove that p^(a+1) is not a member, so v < a+1 and v = a.

TODO: Add random decoy value to prevent an attacker from testing set values.
TODO: Merge memberships and non-memberships proofs:
        In the "disjoint" check, replace the `g` by `g^x`.
        If it passes, `gcd(c, x) == x`, meaning that all x belong and no others.
TODO: Optimize the a,b coefficients in proveDisjoint().
TODO: Decide which is more performant: to include zeros or ones in the set.
TODO: Implement as a map using primeHash as starting points for successive bits.
TODO: Consider an implementation with elliptic curve pairing.

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
        y *= int(x)
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


# Prime helpers

def primesfrom2to(n):
    # https://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    """ Input n>=6, Returns a array of primes, 2 <= p < n """
    sieve = np.ones(n//3 + (n%6==2), dtype=np.bool)
    sieve[0] = False
    for i in range(int(n**0.5)//3+1):
        if sieve[i]:
            k=3*i+1|1
            sieve[      ((k*k)//3)      ::2*k] = False
            sieve[(k*k+4*k-2*k*(i&1))//3::2*k] = False
    return np.r_[2,3,((3*np.nonzero(sieve)[0]+1)|1)]


firstPrimes = []

def initPrimes(maxPrime):
    # TODO: Ensure numbers of primes instead of maximum.
    global firstPrimes
    firstPrimes = primesfrom2to(maxPrime)
    print("Precomputed %i primes < %i" % (len(firstPrimes), maxPrime))

def toPrimes(indices):
    " Map a list of indices to a list of primes. "
    maxi = np.max(indices)
    if maxi >= len(firstPrimes):
        initPrimes(maxi * 20)
    return firstPrimes[ indices ]


def toBitPositions(ids, values, nbits):
    assert len(ids) == len(values)
    zeros = []
    ones = []

    for iVal, val in zip(ids, values):
        for iBit in range(iVal * nbits, (iVal+1) * nbits):
            if val % 2:
                ones.append(iBit)
            else:
                zeros.append(iBit)
            val >>= 1
        if val != 0:
            print("Warning: values[%i] is too big for %i bits!" % (iVal, nbits))

    return zeros, ones

assert toBitPositions([0, 1, 2], [5, 2, 15], nbits=4) == (
    [1, 3, 4, 6, 7], [0, 2, 5, 8, 9, 10, 11])


#%%

class RSACommitment(object):
    """
    Commit to an array values.
    Reveal parts
    """

    # Using the RSA-2048 challenge modulus.
    # The factors and group order, equivalent to the private key, are believed to be unknown!
    # https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
    MOD = RSA2048 = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357;
    # Any prime or coprime is a generator.
    G = 2**256 - 2**32 - 977
    assert gmpy2.is_prime(G)
    assert MOD % G != 0


    def commit(self, indices):
        self.committedPrimes = toPrimes(indices)
        return pows(self.G, self.committedPrimes, self.MOD)

    def proveMembers(self, claimedIndices):
        # hash(items not in subset)
        claimedPrimes = toPrimes(claimedIndices)
        otherPrimes = set(self.committedPrimes).difference(claimedPrimes)
        return pows(self.G, otherPrimes, self.MOD)

    def verifyMembers(self, claimedIndices, proof, commit):
        claimedPrimes = toPrimes(claimedIndices)
        actual = pows(proof, claimedPrimes, self.MOD)
        return actual == commit

    def proveDisjoint(self, disjointIndices):
        # From https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf

        u = prod(self.committedPrimes)
        # commit == pow(G, u, MOD)
        x = prod(toPrimes(disjointIndices))

        gcd, a, b = extended_euclidean_algorithm(u, x); gcd
        if gcd != 1:
            print("Warning: Some members of X are in the commited set, we cannot prove that they are disjoint!")
            return [0, 0]

        # Bring the coefficients into the right range.
        # Find k such that a=a+k*x > 0, and b=b-k*u < 0.
        if a < 0 or b > 0:
            k = max(-a // x, b // u) + 1
            a = a + k * x
            b = b - k * u

        d = pow(self.G, -b, self.MOD)
        return [a, d]

    def verifyDisjoint(self, disjointIndices, proof, commit):
        # TODO: validate proof values explicitely
        disjointPrimes = toPrimes(disjointIndices)
        a, d = proof
        d_x = (pows(d, disjointPrimes, self.MOD) * self.G) % self.MOD
        c_a = pow(commit, a, self.MOD)
        return d_x == c_a


class RSACommitmentValues(RSACommitment):
    " Commitment of numerical values. "

    def __init__(self, nbits):
        self.nbits = nbits

    def commitValues(self, values):
        # Commit to indices where value bits are 0
        valueIds = np.arange(len(values))
        self.zeros, self.ones = toBitPositions(valueIds, values, self.nbits)
        return self.commit(self.zeros)

    def proveValues(self, valueIds):
        # Find indices of binary 0s and 1s of the values to prove.
        valueIds = set(valueIds)
        zeros = [i for i in self.zeros if i//self.nbits in valueIds]
        ones  = [i for i in self.ones  if i//self.nbits in valueIds]

        # Prove the zeros are members.
        proofOfZeros = self.proveMembers(zeros)

        # Prove the ones are not members.
        proofOfOnes = self.proveDisjoint(ones)

        return [proofOfZeros, proofOfOnes]

    def verifyValues(self, valueIds, values, proof, commit):
        proofOfZeros, proofOfOnes = proof
        # Find indices of binary 1s and 0s of the values to check.
        zeros, ones = toBitPositions(valueIds, values, self.nbits)
        # Verify the ones are members.
        zerosOk = self.verifyMembers(zeros, proofOfZeros, commit)
        # Verify the zeros are not members.
        onesOk = self.verifyDisjoint(ones, proofOfOnes, commit)
        return zerosOk and onesOk


#%% Example of using SubsetProver
if __name__ == "__main__":
    import math
    import numpy as np

    fullSet    = np.array([3, 12, 17, 23, 35, 99]) # + list(range(50000,50100)))
    subset     = np.array([   12,     23        ])
    complement = np.array([3,     17,     35, 99])
    disjoint   = np.array([                        5, 6]) # + list(range(50100,50200)))
    mixed      = np.array([           23,          5, 6])

    sp = RSACommitment()
    commit = sp.commit(fullSet)
    print("Commitment:", bits(commit)//8, "bytes\n")

    proofSubset = sp.proveMembers(subset)
    assert sp.verifyMembers(subset, proofSubset, commit)
    print("Proof of memberships:", bits(proofSubset)//8, "bytes")
    print("Accepted correct proof of subset!\n")

    cheatDisjoint = sp.proveMembers(disjoint)
    assert not sp.verifyMembers(disjoint, cheatDisjoint, commit)
    print("Rejected incorrect proof for a disjoint set!\n")

    cheatMixed = sp.proveMembers(mixed)
    assert not sp.verifyMembers(mixed, cheatMixed, commit)
    print("Rejected incorrect proof for an overlapping set!\n")

    proofDisjoint = sp.proveDisjoint(disjoint)
    assert sp.verifyDisjoint(disjoint, proofDisjoint, commit)
    print("Proof of non-memberships:",
        (bits(proofDisjoint[0]) + bits(proofDisjoint[1])) // 8, "bytes")
    print("Accepted correct proof of non-subset!\n")

    cheatNotSubset = sp.proveDisjoint(subset)
    assert not sp.verifyDisjoint(subset, cheatNotSubset, commit)
    print("Rejected incorrect proof of non-subset (subset)!\n")

    cheatNotMixed = sp.proveDisjoint(mixed)
    assert not sp.verifyDisjoint(mixed, cheatNotMixed, commit)
    print("Rejected incorrect proof of non-subset (mixed)!\n")


    # Example with values
    values    = np.array([3, 12, 17, 23, 35, 99])
    revealIds = [1, 3]

    spv = RSACommitmentValues(8)
    commit = spv.commitValues(values)
    proof = spv.proveValues(revealIds)
    print("Proof of an array of values:",
        (bits(proof[0]) + bits(proof[1][0]) + bits(proof[1][1])) // 8, "bytes")

    assert spv.verifyValues(revealIds, values[revealIds], proof, commit)
    print("Accepted correct proof of an array of values!\n")

    assert not spv.verifyValues(revealIds, [12, 42], proof, commit)
    print("Rejected incorrect proof of an array of values!\n")

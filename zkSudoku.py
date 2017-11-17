""" Crypto-based non-interactive proof
"""

#%% Settings
challengeMax = 9 * 3 + 1    # Possible choices: 9 per "type", plus 1 for "constraints"
nChallenges = 256           # Security factor of the interactive protocol
difficulty4bits = 16//4     # Extra security factor with proof-of-work (in 4 bits increments)
print("False-positive rate", ((challengeMax - 1) / challengeMax)**nChallenges)

# Reasonnable values: 512 challenges and 28 bits proof-of-work.


#%% Phase 1: proof commitment, ultra compact.

import numpy as np
from hashUtils import hashObject, str_to_int
from subsetProverRsa import SubsetProver
from interactiveSudoku import secretGrid, puzzleIndices, makeManyHiddenSudokus, checkDigits

keys, grids = makeManyHiddenSudokus(secretGrid, nChallenges)

items = []

for gridI in range(nChallenges):
    # Commit to each value
    for value in grids[gridI].flat:
        items.append((len(items), value))

subsetProver = SubsetProver(items); len(items)
commitsRoot = subsetProver.commit(); commitsRoot


#%% Phase 2: proof-of-work
# Increase the security factor by requiring some work per proof attempt.
# TODO: Support extra fields like blockchain hashes to prove recency (harder to brute-force).
# Alternative: retrieve some public randomness like blockchain hashes.

difficulty = "f" * difficulty4bits
print("Proof-of-work difficulty:", len(difficulty) * 4, "bits")

def makeProofOfWork(commitsRoot, nonce):
    return hashObject(str(commitsRoot) + str(nonce))

def searchProofOfWork(commitsRoot):
    nonce = 0
    while makeProofOfWork(commitsRoot, nonce) < difficulty:
        nonce += 1
    return nonce

nonce = searchProofOfWork(commitsRoot)


#%% Phase 3: Fiat–Shamir transformation.
# Derive pseudo-random challenges from the commitment and proof-of-work.

# Sudoku: encoding a test as a number: n = type*9 + choice_within_type
# Test types: 0=Row, 1=column, 2=block, 3=constraints (then choice=0)

PoW = makeProofOfWork(commitsRoot, nonce)
assert PoW >= difficulty

def makeChallenges(commitsRoot, PoW):
    seed = str_to_int(hashObject(str(commitsRoot) + PoW)) % 2**32
    rd = np.random.RandomState(seed)

    # For each grid, pick a line, a column, and a block to challenge
    return rd.randint(challengeMax, size=nChallenges)

# Derive challenges from random data
challenges = makeChallenges(commitsRoot, PoW)


#%% Phase 4: reveal

responses = np.zeros((
    nChallenges,    # Grids
    9),             # Values per set
    dtype=int)


def getResponse(grid, challenge):
    " Interpret an integer challenge as a set of digits (rows, ...). "
    cType = challenge // 9
    cChoice = challenge % 9
    if cType == 0: return grid[cChoice, :]  # Row
    if cType == 1: return grid[:, cChoice]  # Column
    if cType == 2:                          # Block
        y = (cChoice // 3) * 3
        x = (cChoice % 3) * 3
        return grid[y:y+3, x:x+3].flatten()
    # Otherwise return the puzzle constraints
    return grid.flat[puzzleIndices]


# Map of grid positions to flat indices
idGrid = np.arange(9 * 9).reshape(9, 9)

def getSquareIds(gridI, challenge):
    " Convert the challenge into flat indices of the Merkle tree. "
    gridOffset = gridI * idGrid.size
    idsInGrid = getResponse(idGrid, challenges[gridI])
    return idsInGrid + gridOffset


subset = []

# Collect the responses and the Merkle paths for all challenges
for gridI in range(len(challenges)):
    challenge = challenges[gridI]
    response = getResponse(grids[gridI], challenge)
    responses[gridI] = response
    ids = getSquareIds(gridI, challenge)
    subset.extend(zip(ids, response))

assert len(set(subset).intersection(items)) == responses.size

proofOfSubset = subsetProver.proveSubset(subset)


#%% Phase 5: Pack the proof into a single message
import json
import gzip

# Simple format with JSON
proof = {
    "commitment to set": commitsRoot,
    "proof-of-work nonce": nonce,
    "responses to challenges": responses.tolist(),
    "proof of subset": proofOfSubset,
    }

# GZIP will remove most inefficiencies of encodings, duplicate values, etc.
serializedProof = gzip.compress(json.dumps(proof).encode("utf8"))
print("Proof size: %.0fK for %i challenges." % (len(serializedProof) / 1024, nChallenges))

v_proof = json.loads(gzip.decompress(serializedProof).decode("utf8"))
assert v_proof == proof


#%% Phase 6: Verify

# commitsRoot and noonce must be a proof-of-work.
v_commitsRoot = v_proof["commitment to set"]
v_PoW = makeProofOfWork(v_commitsRoot, v_proof["proof-of-work nonce"])
assert v_PoW >= difficulty, "Too little difficulty."

# Recompute challenges from PoW data
v_challenges = makeChallenges(v_commitsRoot, v_PoW)
assert len(v_challenges) >= nChallenges, "Too few challenges."

v_responses = v_proof["responses to challenges"]
assert len(v_challenges) == len(v_responses)

v_subset = []

for gridI in range(len(v_challenges)):
    challenge = v_challenges[gridI]
    response = v_responses[gridI]
    responseIds = getSquareIds(gridI, challenge)
    v_subset.extend(zip(responseIds, response))

    # Verify that the solution is from a valid Sudoku:
    # * Each set must be all 1-9 digits.
    # * Or, check the puzzle constraints (in that case, it's also 1-9 digits).
    assert checkDigits(np.array(response) - 1), "The response is not a valid solution."

v_proofOfSubsets = v_proof["proof of subset"]
v_isSubset = subsetProver.verifySubset(v_subset, v_proofOfSubsets, v_commitsRoot)
assert v_isSubset, "The responses are not all included in the commitment."

print("Proof verified!")

# This is Zero-knowledge where the verifier is anyone who trusts the proof-of-work randomness.

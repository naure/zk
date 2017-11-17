# ZK Sudoku intro: http://blog.computationalcomplexity.org/2006/08/zero-knowledge-sudoku.html

#%% Generate a secret Sudoku secretGrid

import numpy as np

secretGrid = np.zeros((9,9), dtype=int)
r = np.arange(9)

# Puzzle constraints. Simply 9 squares that contain 1 to 9, to be easy to check.
puzzleIndices = np.array([0, 7, 5, 2, 0, 7, 4, 2, 0]) + np.arange(9) * 9

# First group of 3 rows
secretGrid[0] = np.roll(r, 0)
secretGrid[1] = np.roll(r, -3)
secretGrid[2] = np.roll(r, -6)
# Second group of 3 rows
secretGrid[3:6] = np.roll(secretGrid[0:3], -1, axis=1)
# Third group of 3 rows
secretGrid[6:9] = np.roll(secretGrid[0:3], -2, axis=1)


def checkDigits(block):
    return np.all(np.sort(block.flatten()) == r)

def assertIsSudoku(grid):
    for i in range(9):
        assert checkDigits(grid[i,:])
        assert checkDigits(grid[:,i])
    for i in range(3):
        for j in range(3):
            assert checkDigits(grid[3*i:3*i+3, 3*j:3*j+3])

assertIsSudoku(secretGrid)
checkDigits(secretGrid.flat[puzzleIndices])
print(secretGrid+1)


#%% Transform into some encrypted grids

import os
import struct
import numpy as np

# Reseed at each round to mitigate the weakness of numpy random.
# TODO: Switch to crypto-grade PRNG.
def reseed():
    np.random.seed(struct.unpack("I", os.urandom(4))[0])


def makeHiddenSudoku(grid):
    reseed()
    # Pick a random mapping of digits
    key = np.random.permutation(r)
    # Encrypt the grid
    encrypted = key[grid]
    assertIsSudoku(encrypted)
    return key, encrypted


def makeManyHiddenSudokus(grid, nChallenges):
    keys  = np.zeros((nChallenges, 9), dtype=int)
    grids = np.zeros((nChallenges, 9,9), dtype=int)

    for i in range(nChallenges):
        key, encrypted = makeHiddenSudoku(grid)
        # Store with digits between 1-9
        keys[i] = key + 1
        grids[i] = encrypted + 1

    return keys, grids


#%% Format for paper

def printPaperSudoku():
    keys, grids = makeManyHiddenSudokus(secretGrid, 9)

    # Keep trivial original as demo
    keys[0] = r + 1
    grids[0] = secretGrid + 1

    put = lambda *args: print(*args, sep="", end="")

    put("""
                                    Zero-knowledge proof of Sudoku
                                    ——————————————————————————————








    """)

    # Display 3 groups of 3 grids, line-by-line
    for gridI in range(3):
        for gridJ in range(3):
            put("Key: ", keys[gridI*3 + gridJ], " "*10)
        put("\n\n")
        for blockI in range(0,9,3):
            for line in range(blockI, blockI+3):
                for gridJ in range(3):
                    grid = grids[gridI*3 + gridJ]
                    for triple in range(0,9,3):
                        put(grid[line, triple:triple+3], "  ")
                    if gridJ<2: put(" "*7)
                put("\n")
            put("\n")
        put("\n\n")

    # Print mask cutouts
    put("\n"*25)    # New page
    put("\n"*20)    # Middle of the page
    # Shape of the mask
    put("""Masks to cut out:
                                      XXXXXXXXXXXXXXXXXXXXXXXXX




















                                                    XXXXXXX
                                                    XXXXXXX
                                                    XXXXXXX

    """)


if __name__ == "__main__":
    printPaperSudoku()

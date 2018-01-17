# Zero-knowledge non-interactive proofs

This is an experimental framework to build Zero-knowledge non-interactive proofs,
based on the Fiat-Shamir heuristic, a proof-of-work, and a constant-size commitment scheme.

It turns an interactive system with many challenges into a compact static proof.

The proof-of-work sets the minimum effort required from an attacker to try a
commitment, if looking for favorable challenges.

## Concise commitment scheme

The commitment scheme turns the list of hidden responses into a single number.
After the responses to reveal are chosen, it produces a proof that those were
indeed parts of the commitment.

See https://medium.com/@aurelcode/cryptographic-accumulators-da3aa4561d77.

## Demo with Sudokus

A demonstration with the obligatory Sudoku interactive proof.

See the file `zkSudoku.py`.

### The underlying interactive protocol

1. Find a secret Sudoku grid.

2. Prover generates many encrypted versions of the grid, and keeps them hidden.

3. Verifier picks a row, file or block to reveal from each grid, and
checks that they do contain the numbers from 1 to 9.

See `ZK Sudoku.pdf` and print it on paper to try it out by hand.


### Make it non-interactive

3. Commit to the encrypted values.

4. Execute a proof-of-work.

5. Pick pseudo-random challenges from the commitment and p-o-w.

6. Collect responses and prove that they were committed to.

7. Serialize / deserialize and measure the proof size.

8. Verify the proof.

# Zero-knowledge non-interactive proofs

This is an experimental framework to build Zero-knowledge non-interactive proofs,
based on the Fiat-Shamir heuristic, a proof-of-work, and a constant-size commitment scheme.

It turns an interactive system with many challenges into a compact static proof.

The proof-of-work sets the minimum effort required from an attacker to try a
commitment, if looking for favorable challenges.

## Constant-size proof of subset

The commitment scheme turns the set of hidden responses into a single number.
After the responses to reveal are chosen, it produces a proof that they belong
to the commited set.

It is based on RSA, in a setting where the private key is known to no one.
Hopefully, a good trusted setup is available, see https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048.

1. Hash values of the set into prime numbers.

We'll use set values as factors, and we don't want to introduce many small factors.
We simply use SHA3, and search for the next prime. This search removes a few bits
of hash security only, because there are primes about everywhere (the density is around 1% at 128 bits).

2. Modular exponentiation using all hashes.

Multiply all prime hashes into a very large number, which has equivalent content and size.
We run it through a modular exponentation, which gives a constant-size
number (2048bits), and hides the content. The result is the set commitment.

3. Prove that a subset belongs to the set.

Compute the same as above, but excluding the values from the subset. This is the proof.

4. Verify.

Raise the proof to the power of the subset hashes, which yields the commitment
if all values were parts of the commited set.

Finding a proof for an invalid subset is equivalent to decrypting an
RSA-encrypted message.

One issue is that this commitment scheme is for a set and not an array, so more values can be
included. It is addressed by commiting to the size of the set with a LogLog
count-distinct scheme, however it is very rudimentary at the moment.

It turns out that it is possible to prove non-membership of values. We can prove
that none of the values that are not part of the solution were over-commited.
WiP in subsetProverRsa.


## Demo with Sudokus

1. Find a secret Sudoku grid.

2. Generate many encrypted versions of the grid.

3. Commit to the encrypted values.

4. Execute a proof-of-work.

5. Pick pseudo-random challenges from the commitment and p-o-w.

6. Collect responses and prove that they were commited to.

7. Serialize / deserialize and measure the proof size.

8. Verify the proof.

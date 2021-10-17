# Cryptographic Shuffle ala. Bayer and Groth.

This is a simple implementation of the shuffle presented by Stephanie Bayer and
Jens Groth in their paper [Efficient Zero-Knowledge Argument for Correctness of
a Shuffle](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf).

The implementation uses [Relic](https://github.com/relic-toolkit/relic/) for
elliptic curve operations.

To build, simple run `cmake . -B build && cd build && make && make tests`.

## Disclaimer

This code was taken from a previous project of mine, and it's free to use
(without warranty and all that jazz).

The hash used is Keccak and its implementation is based the available reference
implementation.

The PRG is simply AES in counter mode.

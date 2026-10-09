# Low-rank Hankel methods and degrees of freedom (paper, Sections 4.2 and 4.3)

`low_rank.py` (run from the repository root; output in `low_rank.txt`):

- For five public keys of the KEM, H_m(a) has rank 640 modulo 2, and a mod 2 and b mod 2 have linear
  complexity 703-704 of 1,407 and 383-385 of 768 over GF(2) (Berlekamp-Massey), about half their
  lengths, as for random sequences. Prony-type methods, Berlekamp-Massey and the spectral learning of
  weighted automata need a Hankel matrix of low rank, which these sequences do not provide.
- Contrast: a sequence from a 64-cell linear-feedback shift register has linear complexity 63 and makes
  H_m(a) of rank 63.
- Secret entropy per coefficient: CBD_2 2.031 bits, CBD_3 2.333 bits, discrete Gaussian of standard
  deviation 2.8 about 3.533 bits (the FrodoKEM-640 distribution is a table approximating it). Totals:
  Windowed Hankel 1,300 bits, ML-KEM-512 1,195 bits, one column of the FrodoKEM-640 secret about 2,261 bits.
- Values defining the public matrix: Windowed Hankel 1,407 (768 x 640), ML-KEM-512 1,024 (512 x 512),
  FrodoKEM-640 409,600.

# Kung's realization and ERA with modal coherence (paper, Section 4.3)

`era.py` (run from the repository root; output in `era.txt`, about 15 s) applies the real-valued Hankel
methods of system identification and modal analysis, Kung's SVD realization algorithm and the
Eigensystem Realization Algorithm (ERA) with the Modal Amplitude Coherence (MAC) test, to 20 public keys
of the KEM, with every residue lifted to a centered integer in [-q/2, q/2).

- **The lift adds unknowns.** Over the integers the equation is b = H_m(a) s + e - q k. The wrap counts
  k have standard deviation 6.8-7.9, extremes -29 to 28, and 4.77-4.97 bits of entropy per equation:
  3,665-3,820 bits over the 768 equations, against 1,300 bits for the secret.
- **No model order in b.** ERA on b (order 20, 384 x 384 Hankel matrix) finds no gap in the singular
  values (largest consecutive ratio 1.026-1.290, uniform sequence 1.023-1.152, Mann-Whitney p = 0.44),
  and as many modes pass MAC > 0.9 as for a uniform sequence (mean 6.9 against 8.2 of 20, p = 0.28;
  median MAC p = 0.16). The positive control, five damped real modes with 10% noise, gives a gap of 10.8
  after the tenth singular value and passes all ten modes. The Modal Phase Collinearity (MPC) test
  measures the collinearity of a mode shape across several sensors and does not apply to one sequence.
- **The lift hides finite-field structure.** A sequence from an order-64 linear recurrence modulo q
  makes H_m(a) of rank 64 modulo 2, which Berlekamp-Massey finds at once (`../hankel_low_rank/`), but of
  full rank 640 over the reals, with no ERA gap.
- **One real-valued difference, recorded for completeness.** The lifted H_m(a) has full real rank, but its
  leading singular values stand out more than those of a uniform 768 x 640 matrix: the largest ratio of
  consecutive singular values among the first 600 is 1.027-1.395, at positions 2-30, against 1.018-1.030
  for uniform matrices (p < 0.001), and the top ten hold 5.8-8.2% of the squared norm against 5.3-5.4%.
  This is far from low rank, describes the integer lift of public data rather than the problem modulo q,
  and the reduced-dimension lattice experiments (`../hankel_reduced_lattices/`), which measure the attack
  itself, show Hankel and uniform matrices alike.

Kung, "A new identification and model reduction algorithm via singular value decompositions", 12th
Asilomar Conference, 1978; Juang and Pappa, "An eigensystem realization algorithm for modal parameter
identification and model reduction", J. Guidance, Control, and Dynamics 8(5), 1985.

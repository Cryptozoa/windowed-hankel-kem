# Open attack directions (paper, Sections 4.3, 4.4 and 5.3)

Work on the attack directions listed as open in Table 2 of the paper. Run each script from this
directory with SageMath 10.9 (conda-forge); the estimator script also needs
[malb/lattice-estimator](https://github.com/malb/lattice-estimator) at commit
`53da5982597709ba0fdf94ea37a84d822310fd84`.

| Script | Output | Direction | Result |
| :--- | :--- | :--- | :--- |
| `subrings.sage` | `subrings.txt` | Subring BDD with the withheld coefficients as unknowns (Proposition 2) | X^1407 - 1 has 27 irreducible factors over Z/2^12 (degrees 1, 2, 3, 3, 6, 6 and 21 of degree 66); for each, u -> u mod g is onto, so the 639 withheld coefficients mask the subring equation completely. The embedding identity is checked on random instances. |
| `decryption_equations.sage` | `decryption_equations.txt` | Public key and ciphertexts jointly (Section 5.3) | Each ciphertext gives 128 LWE samples in s modulo q/4 = 1024 with noise sigma = 35.8. With unlimited samples the cheapest lattice attack is the dual hybrid at 2^301.6 (Core-SVP) / 2^315.8 (MATZOV); coded-BKW costs 2^254.1 but needs about 2^242 samples. |

Commands:

```
sage subrings.sage
LATTICE_ESTIMATOR=/path/to/lattice-estimator sage decryption_equations.sage
```

The joint direction is closed by the hybrid argument of Section 5.3, not by the estimate: the estimator
treats the decryption-equation samples as independent, while their noise depends on s and e.

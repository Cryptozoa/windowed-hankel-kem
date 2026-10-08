# Noisy Pade decoding (paper, Section 4.3, Table 2 and Appendix E)

Without noise, b = H_m(a) s is a Hankel linear system (a Pade-type problem) that the extended Euclidean
algorithm solves in O(n^2). With noise, every exact solver returns the same solution s + H^{-1} e of a
square subsystem, which is uniform; a decoder must use the noise. Two ways to do so:

| Script | Output | Result |
| :--- | :--- | :--- |
| `hamming.py` | `hamming.txt` | Counting errors: CBD_2 makes about 480 of 768 coordinates wrong (62.5%), against a unique-decoding radius of 64 (8.3%), a Johnson radius of 66.9 (8.7%) and a list-decoding capacity radius of 12.2% for rate 640/768 over an alphabet of 4096, beyond which every code has exponentially large lists. A random [768, 640] code has about 2^4951.8 codewords within distance 480 of a word. |
| `xl.sage` | `xl.txt` (every m around each threshold, with kernel dimensions), `xl_coarse.txt` (first scan) | Using the small size of the errors: XL on Arora-Ge systems over GF(4093), secret and noise CBD_1, 24 instances per kind and point. For (n, D) = (5,4), (5,5), (6,4), (6,5), (7,5), (8,5), (8,6), Hankel and uniform systems fail below and succeed from the same m (16, 7, 24, 11, 15, 21, 12), and every instance at a given point has the same Macaulay kernel dimension for both kinds. |

`xl.sage` uses the "fork" start method for its worker pool: the macOS default, "spawn", cannot re-import
a Sage script and deadlocks. Run with `sage xl.sage` (conda-forge SageMath 10.9, 14 workers) and
`python3 hamming.py`.

GF(4093) stands in for Z/2^12, which is not a field; the experiment compares Hankel with uniform systems
and does not model Arora-Ge over the scheme's ring.

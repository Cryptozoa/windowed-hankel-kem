# Windowed Hankel KEM -- build, test, KAT and paper targets
# Platform: macOS on Apple Silicon (arm64). The Python layer loads libhankel_kem_neon.dylib
# from the repository root and falls back to the pure-Python backends without it.

CC     ?= /usr/bin/clang
CFLAGS  = -O3 -Wall -Wextra -std=c99
ARCH    = -arch arm64
PYTHON ?= python3

LIB    = libhankel_kem_neon.dylib
SRC    = hankel_kem_neon.c hankel_kem_native.c hankel_hash.c
HDRS   = hankel_kem_neon.h hankel_kem_native.h hankel_hash.h
NATIVE = hankel_kem_native.c hankel_hash.c

.PHONY: all test kat bench paper clean

all: $(LIB)

$(LIB): $(SRC) $(HDRS)
	$(CC) $(CFLAGS) $(ARCH) -dynamiclib -o $@ $(SRC)

# Standalone C test of the native KEM (KATs, rejection, hashes); no Python required
test_hankel_native: test_hankel_native.c $(NATIVE) hankel_kem_native.h hankel_hash.h
	$(CC) $(CFLAGS) $(ARCH) -o $@ test_hankel_native.c $(NATIVE)

bench_hankel_native: bench_hankel_native.c $(NATIVE) hankel_kem_native.h
	$(CC) $(CFLAGS) $(ARCH) -o $@ bench_hankel_native.c $(NATIVE)

# Native KEM (C and Python-level), unit, edge-case, NEON-equivalence and stress tests, then the KATs
test: $(LIB) test_hankel_native
	./test_hankel_native
	$(PYTHON) test_hankel_native_kem.py
	$(PYTHON) test_hankel_refactor.py
	$(PYTHON) test_hankel_kem_edge_cases.py
	$(PYTHON) test_hankel_neon.py
	$(PYTHON) test_hankel_kem_gauntlet.py
	$(PYTHON) nist_analysis_kit/kat/PQCvalidateKAT_hankel.py

# Validate the current KAT file (RESEARCH_v2). The historical NIST1 file predates the e2
# term and is expected to fail; see the note in the validator.
kat: $(LIB)
	$(PYTHON) nist_analysis_kit/kat/PQCvalidateKAT_hankel.py

# Native KEM latency (median and p90 over 5,000 calls)
bench: bench_hankel_native
	./bench_hankel_native 5000

paper:
	cd paper && pdflatex -interaction=nonstopmode hankel_kem_eprint.tex && \
	bibtex hankel_kem_eprint && \
	pdflatex -interaction=nonstopmode hankel_kem_eprint.tex && \
	pdflatex -interaction=nonstopmode hankel_kem_eprint.tex

clean:
	rm -f $(LIB) test_hankel_native bench_hankel_native
	cd paper && rm -f *.aux *.bbl *.blg *.log *.out

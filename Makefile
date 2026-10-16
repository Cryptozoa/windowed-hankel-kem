# Windowed Hankel KEM -- build, test, KAT and paper targets
# Platforms: macOS (Apple Silicon or Intel) and Linux (arm64 or x86-64). The library is built as
# libhankel_kem_neon.dylib on macOS and libhankel_kem_neon.so elsewhere; the Python layer loads it
# from the repository root and falls back to the pure-Python backends without it. NEON kernels are
# used on ARM64 and portable C elsewhere. The static constant-time audit needs macOS on ARM64.

CFLAGS  = -O3 -Wall -Wextra -std=c99
PYTHON ?= python3

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  LIBEXT = dylib
  SHARED = -dynamiclib
  ARCH   = $(if $(filter arm64,$(UNAME_M)),-arch arm64,)
else
  LIBEXT = so
  SHARED = -shared -fPIC
  ARCH   =
endif

LIB    = libhankel_kem_neon.$(LIBEXT)
SRC    = hankel_kem_neon.c hankel_kem_native.c hankel_hash.c
HDRS   = hankel_kem_neon.h hankel_kem_native.h hankel_hash.h
NATIVE = hankel_kem_native.c hankel_hash.c

.PHONY: all test kat bench paper clean

all: $(LIB)

$(LIB): $(SRC) $(HDRS) hankel_kem_native_impl.h
	$(CC) $(CFLAGS) $(ARCH) $(SHARED) -o $@ $(SRC)

# Standalone C test of the native KEM (KATs, rejection, hashes); no Python required
test_hankel_native: test_hankel_native.c $(NATIVE) hankel_kem_native.h hankel_kem_native_impl.h hankel_hash.h
	$(CC) $(CFLAGS) $(ARCH) -o $@ test_hankel_native.c $(NATIVE)

bench_hankel_native: bench_hankel_native.c $(NATIVE) hankel_kem_native.h hankel_kem_native_impl.h
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
	$(PYTHON) nist_analysis_kit/kat/PQCgenKAT_hankel_sets.py validate

# Validate the current KAT files (RESEARCH_v3, WINDOWED_HANKEL_936_v2 and _1208_v2). The historical
# NIST1 and RESEARCH_v2 files predate the e2 term and the exact FO transform; see the validator.
kat: $(LIB)
	$(PYTHON) nist_analysis_kit/kat/PQCvalidateKAT_hankel.py
	$(PYTHON) nist_analysis_kit/kat/PQCgenKAT_hankel_sets.py validate

# Native KEM latency for every parameter set (median and p90 over 5,000 calls)
bench: bench_hankel_native
	./bench_hankel_native 5000

paper:
	cd paper && pdflatex -interaction=nonstopmode hankel_kem_eprint.tex && \
	bibtex hankel_kem_eprint && \
	pdflatex -interaction=nonstopmode hankel_kem_eprint.tex && \
	pdflatex -interaction=nonstopmode hankel_kem_eprint.tex

clean:
	rm -f libhankel_kem_neon.dylib libhankel_kem_neon.so test_hankel_native bench_hankel_native
	cd paper && rm -f *.aux *.bbl *.blg *.log *.out

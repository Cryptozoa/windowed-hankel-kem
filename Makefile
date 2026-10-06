# Windowed Hankel KEM -- build, test, KAT and paper targets
# Platform: macOS on Apple Silicon (arm64). The Python layer loads libhankel_kem_neon.dylib
# from the repository root and falls back to the pure-Python backends without it.

CC     ?= /usr/bin/clang
CFLAGS  = -O3 -Wall -Wextra -std=c99
ARCH    = -arch arm64
PYTHON ?= python3

LIB = libhankel_kem_neon.dylib

.PHONY: all test kat paper clean

all: $(LIB)

$(LIB): hankel_kem_neon.c hankel_kem_neon.h
	$(CC) $(CFLAGS) $(ARCH) -dynamiclib -o $@ hankel_kem_neon.c

# Unit, edge-case, NEON-equivalence and stress tests, then the KAT check
test: $(LIB)
	$(PYTHON) test_hankel_refactor.py
	$(PYTHON) test_hankel_kem_edge_cases.py
	$(PYTHON) test_hankel_neon.py
	$(PYTHON) test_hankel_kem_gauntlet.py
	$(PYTHON) nist_analysis_kit/kat/PQCvalidateKAT_hankel.py

# Validate the current KAT file (RESEARCH_v2). The historical NIST1 file predates the e2
# term and is expected to fail; see the note in the validator.
kat: $(LIB)
	$(PYTHON) nist_analysis_kit/kat/PQCvalidateKAT_hankel.py

paper:
	cd paper && pdflatex -interaction=nonstopmode hankel_kem_eprint.tex && \
	bibtex hankel_kem_eprint && \
	pdflatex -interaction=nonstopmode hankel_kem_eprint.tex && \
	pdflatex -interaction=nonstopmode hankel_kem_eprint.tex

clean:
	rm -f $(LIB)
	cd paper && rm -f *.aux *.bbl *.blg *.log *.out

#!/usr/bin/env python3
"""Static-audit totals for the Category 1 code and for all sets (paper, Section 8.3).
Run from the repository root on macOS with Apple Silicon: python3 review_evidence/hankel_fo_v03_20261016/audit_totals.py"""
import os
import sys

sys.path.insert(0, os.getcwd())
import test_hankel_native_kem as t  # noqa: E402
from ct_branch_audit import audit  # noqa: E402

tot = {"Category 1 (WH-640)": [0, 0, 0], "all sets": [0, 0, 0]}
for sym, args in t.AUDIT_TARGETS:
    n, counts, findings = audit(str(t.NATIVE_LIBRARY_PATH), sym, args, ())
    assert not findings, (sym, findings)
    keys = ["all sets"] + (["Category 1 (WH-640)"] if "936" not in sym and "1208" not in sym else [])
    for k in keys:
        tot[k][0] += 1
        tot[k][1] += n
        tot[k][2] += counts["public_branch"]
for k, (fns, n, b) in tot.items():
    print(f"{k}: {fns} functions, {n} instructions, {b} conditional branches, all on public values")

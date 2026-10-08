#!/bin/bash
# Target-free geometry: BKZ-30 (at most 8 tours), m = 1.2 n, 32 trials per kind.
PY=/Library/anaconda3/envs/sage/bin/python
for spec in "$@"; do
  set -- $spec
  $PY geometry.py $1 $2 $3 30 32 14 > geometry_$1_n$2.txt 2>&1
done

#!/bin/bash
# Full primal run: 48 trials per kind at n = 100, 110, 120; 24 at n = 130. 14 worker processes.
PY=/Library/anaconda3/envs/sage/bin/python
for spec in "100 48" "110 48" "120 48" "130 24"; do
  set -- $spec
  $PY primal.py $1 $2 14 > primal_n$1.txt 2>&1
done
echo done > primal_done.flag

#!/usr/bin/env python3
import sys
import re

lines = sys.stdin.readlines()

l1 = []
l2 = []
l3 = []
l4 = []
lemma = sys.argv[1]

for line in lines:
  num = line.split(':')[0]

  if lemma == "attacker_does_not_know_symmetric_keys":
    
    if ": !KU( ~dh_" in line \
        or ": !KU( common_key" in line:
      l1.append(num)
    elif ": !KU(" in line and not ("sign" in line) and (
          re.search(r".*\^.*inv", line) or # x ^ ( inv(y) )
          re.search(r".*\^\(.*(priv.*\*|\*.*priv)", line) # x ^ ( priv * ... )
        ):
      l2.append(num)
    elif not ( ": !KU( " in line and "sign" in line ):
      l3.append(num)
    else:
      l4.append(num)
  else:
    exit(0)

ranked = l1 + l2 + l3 + l4

for i in ranked:
  print(i)
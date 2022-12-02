#!/usr/bin/env python3
import sys
import re
import itertools

lines = sys.stdin.readlines()

MAX_LEVELS = 10
levels = [ [] for _ in range(10) ]

lemma = sys.argv[1]

for line in lines:
    num = line.split(':')[0]

    if lemma == "attacker_does_not_know_symmetric_keys":

        if ": !KU( ~dh_" in line \
                or ": !KU( common_key" in line:
            levels[0].append(num)
        elif ": !KU(" in line and not ("sign" in line) and (
            re.search(r".*\^.*inv", line) or  # x ^ ( inv(y) )
            re.search(r".*\^\(.*(priv.*\*|\*.*priv)",
                      line)  # x ^ ( priv * ... )
        ):
            levels[1].append(num)
        elif not (": !KU( " in line and "sign" in line):
            levels[2].append(num)
        else:
            levels[3].append(num)

    elif lemma in ["kernel_trust_means_icu_done", "icu_trust_means_kernel_done"]:
        priv_rx = r"~?\w*_priv\.?\d*"

        matchers = [
            [
                fr"!KU\( {priv_rx} \)",
            ], [
                fr"last",
            ], [
                fr"!KU\( 'g'\^\({priv_rx}\*{priv_rx}\) \)"
            ], [
                fr"!KU\( senc\('ICU_Ok', common_key\) \)",
                fr"KernelConnection\( \$Kernel, icu, common_key \)",
            ], [ 
                fr"!KU\( 'g'\^\({priv_rx}\*{priv_rx}\*.*"
            ]
        ]
        
        assert(len(matchers) <= MAX_LEVELS)

        for lvl, regexes in enumerate(matchers):

            if any([re.search(regex, line) for regex in regexes]):
                levels[lvl].append(num)

    else:
        exit(0)

ranked = itertools.chain(*levels)

for i in ranked:
    print(i)

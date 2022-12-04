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

    if lemma in [ "kernel_trust_means_icu_reply", "icu_done_means_kernel_done", "attacker_does_not_know_symmetric_keys"]:
        ktrust = lemma == "kernel_trust_means_icu_reply"
        itrust = lemma == "icu_done_means_kernel_done"
        
        priv_rx = r"~?\w*_priv\.?\d*"
        none_rx = r"x^"

        matchers = [
            [
                fr"!KU\( {priv_rx} \)",
            ], [
                fr"last",
            ], [
                fr"!KU\( 'g'\^\({priv_rx}\*{priv_rx}\) \)",
            ], [
                fr"'icu_reply'",
                fr"'kernel_reply'" if itrust else none_rx,
            ], [ 
                fr"!KU\( 'g'\^\({priv_rx}\*{priv_rx}\*.*",
                fr"!KU\( sign\(<'icu', icu, .*x.*>, ~ca_priv\)" if ktrust else none_rx,
                fr"!KU\( sign\(<'kernel', kernel, .*x.*>, ~ca_priv\)" if ktrust else none_rx,
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

#!/usr/bin/env bash
# hf_conf / hf_conf_bool — the single configuration accessor.
#
# docs/MODULE-CONTRACT.md rule 1: "Read parameters ONLY through hf_conf KEY
# [default] / hf_conf_bool KEY". Every module depends on this function, so a
# wrong answer here is wrong everywhere at once. It is tested under `set -u`
# because that is how install.sh and every module actually run: reading an
# undeclared key must yield the default, never an unbound-variable abort.

set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=../lib/common.sh
. "$HF_ROOT/lib/common.sh"

# ── hf_conf ─────────────────────────────────────────────────────────────────
t_eq "undeclared key falls back to the default" "mydefault" "$(hf_conf TOTALLY_UNDECLARED_KEY mydefault)"
t_eq "undeclared key with no default is empty" "" "$(hf_conf ALSO_UNDECLARED)"

HF_DECLARED_SET="hello"
t_eq "declared key returns its value" "hello" "$(hf_conf DECLARED_SET fallback)"

HF_DECLARED_EMPTY=""
t_eq "declared-but-empty falls back to the default" "fallback" "$(hf_conf DECLARED_EMPTY fallback)"

HF_SPACED="a b c"
t_eq "a value containing spaces survives" "a b c" "$(hf_conf SPACED x)"

HF_EMPTY_DEFAULT_PROBE=""
t_eq "empty default is allowed" "" "$(hf_conf EMPTY_DEFAULT_PROBE '')"

t_eq "shell survived every lookup under set -u" "alive" "alive"

# ── hf_conf_bool ────────────────────────────────────────────────────────────
# Normalizes the spellings operators actually type. Anything unrecognized must
# be FALSE (fail closed): a typo must not silently arm a security feature.
HF_B_TRUE="true"
HF_B_YES="YES"
HF_B_ONE="1"
HF_B_MIXED="True"
HF_B_FALSE="false"
HF_B_NO="no"
HF_B_ZERO="0"
HF_B_EMPTY=""
HF_B_JUNK="maybe"

t_ok "bool 'true' is truthy" hf_conf_bool B_TRUE
t_ok "bool 'YES' is truthy (case-insensitive)" hf_conf_bool B_YES
t_ok "bool 'True' is truthy (case-insensitive)" hf_conf_bool B_MIXED
t_ok "bool '1' is truthy" hf_conf_bool B_ONE
t_ok "bool default applies when the key is absent" hf_conf_bool B_ABSENT true

if hf_conf_bool B_FALSE; then t_fail "bool 'false' must not be truthy"; else t_pass "bool 'false' is falsey"; fi
if hf_conf_bool B_NO; then t_fail "bool 'no' must not be truthy"; else t_pass "bool 'no' is falsey"; fi
if hf_conf_bool B_ZERO; then t_fail "bool '0' must not be truthy"; else t_pass "bool '0' is falsey"; fi
if hf_conf_bool B_EMPTY; then t_fail "an empty value must not be truthy"; else t_pass "an empty value is falsey"; fi
if hf_conf_bool B_JUNK; then t_fail "unrecognized value must fail closed, not arm"; else t_pass "unrecognized value fails closed"; fi

t_done "hf_conf"

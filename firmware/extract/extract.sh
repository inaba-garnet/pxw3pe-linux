#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# extract.sh - build + run the PX-W3PE (ASV5220/ASIE5606) key-extraction harness
#              against a real driver .ko, printing the 4 derived fields in a
#              STABLE, parseable contract:
#
#                seed=<32 hex chars>
#                even=<16 hex chars>
#                odd=<16 hex chars>
#                xor=<8 hex chars>
#                auth=Fuwawa Abyssgard
#
# The key material comes OUT of the .ko (nothing is hardcoded except the
# .ko-derived driver constants in harness.c needed to drive it).
#
# Usage:
#   extract.sh /path/to/asv5220_dtv.ko
#
# Steps:
#   1. objcopy --weaken-symbol=des_setkey_dec  (so harness's strong des_setkey_dec
#      wins and can capture the raw DES even/odd keys KeyTransfer2 passes in)
#   2. gcc -no-pie -fno-pie -O0 harness.c <weakened.ko> -o harness
#   3. run harness, emit the 4 fields on stdout

set -euo pipefail

KO="${1:?usage: extract.sh /path/to/driver.ko}"

if [ ! -f "$KO" ]; then
	echo "extract.sh: no such .ko: $KO" >&2
	exit 1
fi

# The harness links a REL x86-64 .ko and uses -no-pie + ARCH_SET_GS; bail early
# with a clear message rather than a confusing link error / SIGSEGV later.
command -v objcopy >/dev/null 2>&1 || { echo "extract.sh: objcopy (binutils) not found" >&2; exit 1; }
command -v gcc     >/dev/null 2>&1 || { echo "extract.sh: gcc not found" >&2; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo "extract.sh: x86-64 host required (got $(uname -m))" >&2; exit 1; }

# Resolve this script's own directory so harness.c is found regardless of cwd.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HARNESS_C="$HERE/harness.c"

if [ ! -f "$HARNESS_C" ]; then
	echo "extract.sh: harness source not found: $HARNESS_C" >&2
	exit 1
fi

# Work in a per-run temp dir so concurrent/parallel invocations don't collide
# on asv_w.ko / harness, and so we never clobber a checked-in build.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/asvextract.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

WEAK_KO="$WORK/asv_w.ko"
BIN="$WORK/harness"

# 1. weaken des_setkey_dec in the driver .ko
objcopy --weaken-symbol=des_setkey_dec "$KO" "$WEAK_KO"

# 2. link the harness against the weakened .ko
gcc -no-pie -fno-pie -O0 "$HARNESS_C" "$WEAK_KO" -o "$BIN"

# 3. run; harness prints seed=/even=/odd=/xor=/auth= on stdout
"$BIN"

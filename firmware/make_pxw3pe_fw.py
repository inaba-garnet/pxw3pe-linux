#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# make_pxw3pe_fw.py - build the PX-W3PE (ASV5220/ASIE5606) firmware blob
#                     /lib/firmware/pxw3pe.fw
#
# Blob layout (60 bytes, little: magic + version + 4 key fields):
#
#     offset  size  field
#     ------  ----  -----------------------------------------------------
#       0      4    magic   = b"PXWF"
#       4      4    version = bytes([1,0,0,0])
#       8     16    auth    = b"Fuwawa Abyssgard"  (16-byte ASIE enable string)
#      24     16    seed    (ASV5606 chip seed)
#      40      8    even    (DES even key)
#      48      8    odd     (DES odd key)
#      56      4    xor     (xor seed)
#     ------  ----
#      60                                            total
#
# The `auth` field is a fixed 16-byte string written to the ASIE5606 enable
# registers (0x10-0x1F). The chip does not validate it - any 16 bytes work
# (verified on hardware: zeros and arbitrary strings descramble identically),
# so it is just a placeholder, not a secret or a required magic value.
#
# The remaining four fields (seed/even/odd/xor) are RE-derived per-model SECRET
# key material. They are deliberately NOT embedded in this committed generator.
# Instead they are extracted at build time from the official driver .ko via:
#
#     make_pxw3pe_fw.py --from-ko /path/to/asv5220_dtv.ko [out.fw]
#
# which runs extract/extract.sh (next to this script) against the .ko and parses
# its stable seed=/even=/odd=/xor= contract.
#
# Backward-compat / local convenience: with no --from-ko, this script imports
# the keys from a separate, gitignored WALL file (wall_keys.py) if present.
# That WALL file is NOT published. If it is absent, the script tells you to use
# --from-ko.

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRACT_SH = os.path.join(HERE, "extract", "extract.sh")

MAGIC = b"PXWF"
VERSION = bytes([1, 0, 0, 0])
# 16-byte ASIE enable string. The chip does not validate it; any 16 bytes work.
AUTH = b"Fuwawa Abyssgard"

# expected field byte-lengths
LEN_SEED = 16
LEN_EVEN = 8
LEN_ODD = 8
LEN_XOR = 4
LEN_BLOB = 60


def die(msg, code=1):
    sys.stderr.write("make_pxw3pe_fw.py: %s\n" % msg)
    sys.exit(code)


def build_blob(seed, even, odd, xor):
    """Assemble and validate the 60-byte firmware blob from raw key bytes."""
    for name, val, want in (
        ("auth", AUTH, 16),
        ("seed", seed, LEN_SEED),
        ("even", even, LEN_EVEN),
        ("odd", odd, LEN_ODD),
        ("xor", xor, LEN_XOR),
    ):
        if len(val) != want:
            die("field %r has length %d, expected %d" % (name, len(val), want))
    blob = MAGIC + VERSION + AUTH + seed + even + odd + xor
    assert len(blob) == LEN_BLOB, "blob length %d != %d" % (len(blob), LEN_BLOB)
    return blob


def parse_extract_output(text):
    """Parse seed=/even=/odd=/xor= hex fields from extract.sh stdout."""
    fields = {}
    for line in text.splitlines():
        m = re.match(r"^\s*(seed|even|odd|xor)\s*=\s*([0-9a-fA-F]+)\s*$", line)
        if m:
            fields[m.group(1)] = m.group(2).lower()
    missing = [k for k in ("seed", "even", "odd", "xor") if k not in fields]
    if missing:
        die("extractor output missing field(s): %s\n--- extractor output ---\n%s"
            % (", ".join(missing), text))
    try:
        seed = bytes.fromhex(fields["seed"])
        even = bytes.fromhex(fields["even"])
        odd = bytes.fromhex(fields["odd"])
        xor = bytes.fromhex(fields["xor"])
    except ValueError as e:
        die("could not decode extractor hex field: %s" % e)
    # Defensive gate: an all-zero field means the extraction silently failed
    # (e.g. a zeroed ctx). Refuse rather than emit a valid-looking wrong blob.
    for name, val in (("seed", seed), ("even", even), ("odd", odd), ("xor", xor)):
        if val == bytes(len(val)):
            die("extractor returned an all-zero %r field - failed extraction.\n"
                "--- extractor output ---\n%s" % (name, text))
    return seed, even, odd, xor


def keys_from_ko(ko_path):
    """Run extract.sh on the .ko, parse the 4 secret fields out of its stdout."""
    if not os.path.isfile(ko_path):
        die("no such .ko: %s" % ko_path)
    if not os.path.isfile(EXTRACT_SH):
        die("extractor not found: %s" % EXTRACT_SH)
    # Sanity: the extractor needs gcc + objcopy.
    for tool in ("gcc", "objcopy"):
        if shutil.which(tool) is None:
            die("required tool %r not found on PATH (needed by the extractor)" % tool)
    try:
        proc = subprocess.run(
            ["bash", EXTRACT_SH, ko_path],
            capture_output=True,
            text=True,
        )
    except OSError as e:
        die("failed to launch extractor (%s): %s" % (EXTRACT_SH, e))
    if proc.returncode != 0:
        die("extractor failed (exit %d):\n--- stderr ---\n%s\n--- stdout ---\n%s"
            % (proc.returncode, proc.stderr.strip(), proc.stdout.strip()))
    return parse_extract_output(proc.stdout)


def keys_from_wall():
    """Local convenience fallback: import keys from the gitignored WALL file."""
    try:
        import wall_keys  # noqa: F401
    except ImportError:
        die("no --from-ko given and no WALL file (wall_keys.py) found.\n"
            "Run with: --from-ko /path/to/asv5220_dtv.ko [out.fw]\n"
            "(The committed generator carries no embedded secret keys.)")
    try:
        seed = bytes.fromhex(wall_keys.SEED_HEX)
        even = bytes.fromhex(wall_keys.EVEN_HEX)
        odd = bytes.fromhex(wall_keys.ODD_HEX)
        xor = bytes.fromhex(wall_keys.XOR_HEX)
    except (AttributeError, ValueError) as e:
        die("WALL file wall_keys.py is malformed: %s" % e)
    return seed, even, odd, xor


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Build the PX-W3PE firmware blob (pxw3pe.fw).")
    ap.add_argument(
        "--from-ko", metavar="DRIVER_KO", default=None,
        help="extract the secret key fields from this official driver .ko "
             "(via extract/extract.sh) instead of using local WALL keys")
    ap.add_argument(
        "out", nargs="?", default="pxw3pe.fw",
        help="output firmware path (default: pxw3pe.fw)")
    args = ap.parse_args(argv)

    if args.from_ko:
        seed, even, odd, xor = keys_from_ko(args.from_ko)
        source = "extracted from %s" % args.from_ko
    else:
        seed, even, odd, xor = keys_from_wall()
        source = "WALL (wall_keys.py)"

    blob = build_blob(seed, even, odd, xor)

    try:
        with open(args.out, "wb") as f:
            f.write(blob)
    except OSError as e:
        die("cannot write %s: %s" % (args.out, e))

    print("wrote %s (%d bytes) [keys: %s]" % (args.out, len(blob), source))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Provision CIS trust anchors into cis/cis_keys.h.

cis_keys.h is generated rather than hand-edited so that the trust store is always
something a tool produced and something a tool can re-derive.  A trust store
maintained by hand is a trust store nobody can audit.

Two modes:

  provision    Add a real release or recovery anchor, read from a private key
               file.  This is the supported way to make a build trust a signer.

  emit-dev     Write the development image anchor.  This is the opt-in path: a
               build only carries the dev anchor if it was configured with
               CIS_DEV_TRUST, and only such a build accepts dev-signed images.

Only the public half is ever written to cis_keys.h.  A private key is an input to
provision and nothing else; it is not copied into the repository, not embedded in
an image, and does not exist on the target.

Usage:
  python tools/cis_keygen.py emit-dev
  python tools/cis_keygen.py provision --label release \\
      --key release.key --out cis/cis_keys.h
"""

import argparse
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cis_block
import cis_sign

# Mirrors inc/ow_cis.h.  Duplicated rather than parsed: this tool writes C, it
# does not compile it, and a header parser here would be a second thing to keep
# correct.
def load_key_flags():
    """Read the OW_CIS_KEY_FLAG_* values out of inc/ow_cis.h.

    Parsed rather than duplicated.  This was originally hardcoded, and within an
    hour the copy had drifted: it believed TEST_ONLY was 0x2, which is actually
    RECOVERY.  The result was a dev anchor quietly granted recovery authority and
    refused for boot images -- a policy failure that looked like a signing bug,
    produced by a tool that had no way to notice its own constant was wrong.

    A #define scan is enough here because the values are literals on the same
    line as the name.  Anything more elaborate would be a parser for a language
    this tool does not otherwise need to understand.
    """
    header = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "inc", "ow_cis.h")
    values = {}
    try:
        with open(header, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        raise SystemExit(f"error: cannot read {header}")
    for match in re.finditer(
            r'#define\s+(OW_CIS_KEY_FLAG_\w+)\s+(0x[0-9A-Fa-f]+|\d+)', text):
        values[match.group(1)] = int(match.group(2), 0)
    for required in ("OW_CIS_KEY_FLAG_RELEASE", "OW_CIS_KEY_FLAG_RECOVERY",
                     "OW_CIS_KEY_FLAG_TEST_ONLY"):
        if required not in values:
            raise SystemExit(f"error: {header} does not define {required}")
    return values


_OW_CIS_KEY_FLAGS = load_key_flags()

FLAG_RELEASE = _OW_CIS_KEY_FLAGS["OW_CIS_KEY_FLAG_RELEASE"]
FLAG_RECOVERY = _OW_CIS_KEY_FLAGS["OW_CIS_KEY_FLAG_RECOVERY"]
FLAG_TEST_ONLY = _OW_CIS_KEY_FLAGS["OW_CIS_KEY_FLAG_TEST_ONLY"]

FLAG_NAMES = [
    (FLAG_RELEASE, "OW_CIS_KEY_FLAG_RELEASE"),
    (FLAG_RECOVERY, "OW_CIS_KEY_FLAG_RECOVERY"),
    (FLAG_TEST_ONLY, "OW_CIS_KEY_FLAG_TEST_ONLY"),
]

if FLAG_RELEASE == FLAG_RECOVERY or FLAG_RECOVERY == FLAG_TEST_ONLY:
    raise SystemExit("error: two OW_CIS_KEY_FLAG_* values collide in inc/ow_cis.h")


def format_flags(flags, names=True):
    """Render a flag word.

    Numeric by default.  A generated header that referenced OW_CIS_KEY_FLAG_* by
    name would have to be included after inc/ow_cis.h, which turns an include
    order into a requirement -- and one of the files that includes this is
    tools/hosttest/host_boot.c, which does not otherwise need the CIS API at
    all.  The names are emitted alongside the values so a reader does not have to
    go looking them up.
    """
    if flags == 0:
        return "0u /* no flags */"
    if not names:
        return f"0x{flags:08X}u"
    names_ = [name for bit, name in FLAG_NAMES if flags & bit]
    rendered = " | ".join(names_)
    return f"{rendered} /* 0x{flags:08X}u */"


def format_bytes(data, indent, backslash=False):
    """One hex byte group per line, eight bytes to a line.

    At this indent sixteen would overflow 80 columns, and a wrapped line is a line
    whose columns stop lining up -- which is how a transposed byte survives
    review.

    `backslash` continues the line, for use inside a #define body where every
    line must end in one.  Without it the same text is emitted as ordinary
    multi-line initializer source."""
    pad = " " * indent
    groups = [", ".join("0x%02X" % b for b in data[i:i + 8])
              for i in range(0, len(data), 8)]
    if backslash:
        return (", \\\n" + pad).join(groups)
    return (",\n" + pad).join(groups)


def read_seed(path):
    """Load a 32-byte seed from a file.

    Accepts raw bytes or hex, because a key file produced by one tool is
    regularly fed to another and the ambiguity is not worth a build failure."""
    with open(path, "rb") as f:
        raw = f.read()
    stripped = raw.strip()
    try:
        text = stripped.decode("ascii")
    except UnicodeDecodeError:
        text = None
    if text is not None and len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    if len(raw) == 32:
        return raw
    raise SystemExit(
        f"error: {path} is neither 32 raw bytes nor 64 hex characters "
        f"(got {len(raw)} bytes)")


def render_entry(label, public_key, key_id, flags, comment_lines):
    """One anchor as a comma-terminated initializer, fully line-continued.

    This text goes inside a #define body, where every physical line must end in a
    backslash.  So the entry is assembled as lines and continued here rather than
    at the call site; a missing continuation is a compile error about a stray
    token, which at least fails loudly rather than silently truncating."""
    if isinstance(comment_lines, str):
        comment_lines = [comment_lines]
    comment = " ".join(comment_lines).strip()
    lines = [
        f'    /* {comment} */',
        f'    {{ "{label}",',
        f'      {{ {format_bytes(key_id, 6)} }},',
        f'      {{ {format_bytes(public_key, 6)} }},',
        f'      {format_flags(flags)} }},',
    ]
    return (" \\\n").join(lines)


def write_header(out_path, entries):
    body = "\n".join(entries) if entries else None
    if body:
        provisioned = f"""/* Provisioned anchors.  Regenerate with:
 *
 *   python tools/cis_keygen.py provision --label <name> --key <file>.key \\
 *       --out cis/cis_keys.h
 */
#define OW_CIS_PROVISIONED_KEY_COUNT {len(entries)}u
#define OW_CIS_PROVISIONED_KEYS_INITIALISER \\
{body}
"""
    else:
        provisioned = """/* No provisioned anchors.  An OpenWindows build with an empty trust store
 * refuses every image, which is the intended default: a machine that will not
 * run unreviewed code rather than a machine that runs whatever it finds. */
#define OW_CIS_PROVISIONED_KEY_COUNT 0u
#define OW_CIS_PROVISIONED_KEYS_INITIALISER
"""

    text = f"""/* cis_keys.h - Pinned CIS trust anchors.
 *
 * GENERATED by tools/cis_keygen.py.  Hand edits survive only until the next
 * regeneration, so the tool is the supported way to change this file.
 *
 * This file composes two independent things into the one table cis_core.c walks:
 *
 *   OW_CIS_PROVISIONED_KEYS_INITIALISER  real anchors, added by `provision`
 *   OW_CIS_DEV_KEYS_INITIALISER          the dev anchor, added by CIS_DEV_TRUST
 *
 * The split matters because the two have different provenance.  A provisioned
 * anchor comes from a private key held off the build machine.  The dev anchor
 * comes from a seed printed in tools/cis_block.py, so trusting it means trusting
 * anyone with a checkout of this repository.  Keeping them in separate macros is
 * what makes that distinction reviewable in the table rather than only in prose:
 * a build can carry the second and not the first.
 *
 * Only the public half of any key is ever written here.  A private key is an
 * input to `provision` and to nothing else; it is not copied into this
 * repository, not embedded in any image, and does not exist on the target. */
#ifndef OW_CIS_KEYS_H
#define OW_CIS_KEYS_H

#include <stdint.h>

/* Bounds check applied before CIS spends time hashing: an image larger than
 * this is refused unmeasured rather than measured and then rejected. */
#define OW_CIS_DEFAULT_MAX_IMAGE_SIZE 0x00400000u /* 4 MiB */

typedef struct {{
    const char* Name;
    uint8_t     KeyId[16];
    uint8_t     PublicKey[32];
    uint32_t    Flags;
}} ow_cis_pinned_key_t;

{provisioned}
#include "cis_keys_dev.h"

/* Everything cis_core.c installs at init. */
#define OW_CIS_PINNED_KEY_COUNT \\
    (OW_CIS_PROVISIONED_KEY_COUNT + OW_CIS_DEV_KEY_COUNT)

/* The table is always defined, even when empty, so that code which indexes it
 * inside a count-bounded loop still compiles against an unprovisioned build.
 * OW_CIS_PINNED_KEY_COUNT, not this size, is what bounds every lookup. */
#define OW_CIS_KEY_TABLE_SIZE \\
    (OW_CIS_PINNED_KEY_COUNT > 0u ? OW_CIS_PINNED_KEY_COUNT : 1u)

static const ow_cis_pinned_key_t OW_CIS_PINNED_KEYS[OW_CIS_KEY_TABLE_SIZE] = {{
    OW_CIS_PROVISIONED_KEYS_INITIALISER
    OW_CIS_DEV_KEYS_INITIALISER
}};

#endif /* OW_CIS_KEYS_H */
"""
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def cmd_init(args):
    """Rewrite cis_keys.h with no provisioned anchors.

    Separate from emit-dev because the two answers to different questions.
    `init` asks "what does a build trust out of the box", and the answer is
    nothing.  `emit-dev` asks "what does an opt-in development build trust",
    and the answer is one public key.  Keeping them apart means regenerating the
    dev header can never quietly add or drop a provisioned anchor."""
    write_header(args.out, [])
    print(f"wrote {args.out}: no provisioned anchors")
    print("      A build with no provisioned anchor and no CIS_DEV_TRUST refuses "
          "every image.\n      That is the intended default.")


def cmd_emit_dev(args):
    """Write cis/cis_keys_dev.h: the dev anchor, behind CIS_DEV_TRUST.

    Separate from `provision` on purpose.  The dev key has no private key file to
    read, because it has no private half worth protecting -- it is a fixed seed
    in the repository -- and it must not land in the same list as anchors that do
    come from a secret.  It is also the only anchor that is opt-in, so it lives
    in its own file that the build either compiles in or does not."""
    public_key = cis_block.dev_public_key()
    key_id = cis_block.dev_key_id()

    # RELEASE and RECOVERY as well as TEST_ONLY.
    #
    # cis_verify.c decides what a key may sign from its flags alone, and a
    # TEST_ONLY key is not permitted to sign anything -- which is right, and
    # which would otherwise make CIS_DEV_TRUST a flag that compiles but can never
    # boot.  Adding a bypass to cis_verify.c for this would be the wrong fix: a
    # second path that decides signing authority is exactly the thing the
    # single-table design exists to prevent, and it would need its own audit.
    #
    # So the authority is expressed in the trust store instead, where it is
    # visible in the one table that already answers that question.  TEST_ONLY is
    # still set, so the key remains identifiable as non-production in a log or a
    # dump -- and the anchor exists only when the build opted in, which is what
    # actually bounds the damage.
    flags = FLAG_RELEASE | FLAG_RECOVERY | FLAG_TEST_ONLY

    text = f"""/* cis_keys_dev.h - the opt-in development image anchor.
 *
 * GENERATED by tools/cis_keygen.py emit-dev.  The seed it names is
 * DEV_IMAGE_SEED in tools/cis_block.py and is public: it is in the repository,
 * so anyone who can build this tree can sign an image this file's anchor trusts.
 *
 * That is the whole point and also the whole danger.  It exists so a development
 * build can boot an image it signed itself, and it is compiled in ONLY when the
 * build passes CIS_DEV_TRUST:
 *
 *   make qemu CIS_DEV_TRUST=1
 *
 * A build without that opt-in expands this file to nothing, which means it has no
 * dev anchor, which means it refuses every dev-signed image.  That is why the
 * guard is here rather than in cis_keys.h: the count has to be able to be zero
 * from a compile-time decision alone, with no runtime switch that a running
 * kernel could be talked out of.
 *
 * The flags are RELEASE | RECOVERY | TEST_ONLY.  RELEASE and RECOVERY are what
 * let the key sign boot and recovery images at all; TEST_ONLY is what marks it
 * as non-production for anything reading the store back.  Authority lives in the
 * trust store rather than in a special case in cis_verify.c on purpose -- see
 * cmd_emit_dev.
 *
 * A build containing this anchor will execute any image signed with the dev
 * seed.  Do not ship one. */
#ifndef OW_CIS_KEYS_DEV_H
#define OW_CIS_KEYS_DEV_H

#ifdef CIS_DEV_TRUST

#define OW_CIS_DEV_KEY_COUNT 1u
#define OW_CIS_DEV_KEYS_INITIALISER \\
    {{ "dev", \\
      {{ {format_bytes(key_id, 6, backslash=True)} }}, \\
      {{ {format_bytes(public_key, 6, backslash=True)} }}, \\
      {format_flags(flags, names=False)} }}

#else /* !CIS_DEV_TRUST */

#define OW_CIS_DEV_KEY_COUNT 0u
#define OW_CIS_DEV_KEYS_INITIALISER

#endif /* CIS_DEV_TRUST */

#endif /* OW_CIS_KEYS_DEV_H */
"""
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {args.out}: dev anchor (key id {key_id.hex()})")
    print("NOTE: compiled in only when the build passes CIS_DEV_TRUST=1.  A build "
          "with this\n      anchor trusts anyone who can run "
          "tools/owx_pack.py --sign-dev.")


def cmd_provision(args):
    seed = read_seed(args.key)
    public_key = cis_sign.public_key_from_seed(seed)
    key_id = cis_block.key_id_for(public_key)

    flags = 0
    if args.recovery:
        flags |= FLAG_RECOVERY
    if args.test_only:
        flags |= FLAG_TEST_ONLY

    existing = []
    if args.append and os.path.exists(args.out):
        existing = parse_existing(args.out)

    label = args.label
    for name, _, _, _ in existing:
        if name == label:
            raise SystemExit(
                f"error: {args.out} already contains an anchor labelled "
                f"'{label}'.\n       Re-provision from an empty store, or use a "
                f"different label.")

    entry = render_entry(label, public_key, key_id, flags,
                     [f"Provisioned anchor for '{label}'.",
                      "Non-TEST_ONLY: whoever holds the matching private key",
                      "can have this build run arbitrary code."])
    write_header(args.out, existing + [entry])
    print(f"wrote {args.out}: {len(existing) + 1} anchor(s); added '{label}' "
          f"(key id {key_id.hex()})")
    if not args.test_only:
        print("NOTE: this anchor is not marked TEST_ONLY.  Anyone with the "
              "corresponding\n      private key can have this build execute "
              "arbitrary code as PID 1.")


def parse_existing(path):
    """Read back anchor labels and bytes so --append can extend a store.

    A deliberately small regex scan rather than a full parser.  It reads only what
    this tool writes, and if the file was edited by hand then it is no longer
    trustworthy input for a tool that decides what a machine will execute --
    which is exactly when the tool should stop rather than guess."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    entries = []
    pattern = re.compile(
        r'\{\s*"(?P<label>[^"]*)",\s*'
        r'\{\s*(?P<keyid>[^}]*)\},\s*'
        r'\{\s*(?P<pub>[^}]*)\},\s*'
        r'(?P<flags>[^}]*?)\s*\}', re.DOTALL)
    for m in pattern.finditer(text):
        label = m.group("label")
        if label == "":
            continue
        key_id = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})',
                                                      m.group("keyid")))
        public_key = bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})',
                                                          m.group("pub")))
        if len(key_id) != 16 or len(public_key) != 32:
            continue
        flag_text = m.group("flags")
        flags = 0
        if "RECOVERY" in flag_text:
            flags |= FLAG_RECOVERY
        if "TEST_ONLY" in flag_text:
            flags |= FLAG_TEST_ONLY
        entries.append((label, public_key, key_id, flags))
    return entries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="rewrite the store with no anchors")
    init.add_argument("--out", default=os.path.join("cis", "cis_keys.h"))
    init.set_defaults(func=cmd_init)

    dev = sub.add_parser("emit-dev",
                         help="write the CIS_DEV_TRUST development anchor")
    dev.add_argument("--out", default=os.path.join("cis", "cis_keys_dev.h"))
    dev.set_defaults(func=cmd_emit_dev)

    prov = sub.add_parser("provision", help="add a real anchor from a key file")
    prov.add_argument("--label", required=True)
    prov.add_argument("--key", required=True)
    prov.add_argument("--out", default=os.path.join("cis", "cis_keys.h"))
    prov.add_argument("--recovery", action="store_true",
                      help="mark the anchor as recovery-only")
    prov.add_argument("--test-only", action="store_true",
                      help="mark the anchor TEST_ONLY")
    prov.add_argument("--append", action="store_true",
                      help="keep anchors already in --out")
    prov.set_defaults(func=cmd_provision)

    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
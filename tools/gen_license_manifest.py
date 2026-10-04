#!/usr/bin/env python3
"""gen_license_manifest.py - Generate canonical source & license manifest for OpenWindows

Inspects OpenWindows kernel source files and license declarations to produce a
deterministic, canonical, length-delimited license manifest.

Computes a cryptographic SHA-256 digest of the canonical manifest, which is then
bound into the CIS release metadata (OW_CIS_TAG_SOURCE_DIGEST) of openwinkrnl.owx.

Rules for canonicalization:
  - Normalized relative POSIX paths (e.g. 'core/main.c')
  - Strict lexicographical ordering (LC_ALL=C equivalent)
  - Explicit SHA-256 per source file
  - Component license mapping based on LICENSE and THIRD-PARTY-NOTICES.md
  - Explicit target and effective policy class ('CORE_KERNEL')
  - Linux LF (\n) newlines and UTF-8 encoding
  - Deterministic JSON formatting

Usage:
  python tools/gen_license_manifest.py [--target openwinkrnl] [--output manifest.json]
                                       [--digest-out manifest.digest] [--digest-only]
                                       [--self-test]
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

KERNEL_SOURCE_DIRS = [
    "bancode",
    "cis",
    "core",
    "diag",
    "dpc",
    "hal",
    "inc",
    "kapi",
    "lib",
    "net",
    "ps",
    "rc",
    "sentinel",
    "shell",
    "storage",
    "sucs",
    "sync",
    "syscall",
    "usermode",
    "vfs",
    "vip",
]

ROOT_DOC_FILES = [
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
]


def get_git_revision(repo_root):
    """Retrieve git HEAD revision if available, else return fixed fallback."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        if len(out) == 40:
            return out
    except Exception:
        pass
    return "0000000000000000000000000000000000000000"


def determine_file_license(rel_path):
    """Map a kernel source path to its applicable license declaration."""
    p = rel_path.replace("\\", "/")
    if p == "LICENSE":
        return "GPL-3.0-or-later"
    if p == "THIRD-PARTY-NOTICES.md":
        return "Notice"
    if p.startswith("sucs/"):
        return "MIT OR Apache-2.0"
    if p.startswith("storage/") and not p.startswith("storage/owdisk."):
        # OpenWindows-Storage filesystem & common sources are dual-licensed
        return "MIT OR Apache-2.0"
    if p.startswith("vip/"):
        return "LicenseRef-UniVIP"
    # Core OpenWindows kernel files
    return "GPL-3.0-or-later"


def collect_kernel_files(repo_root):
    """Discover all kernel source files in deterministic order."""
    collected = []
    for doc in ROOT_DOC_FILES:
        full_path = os.path.join(repo_root, doc)
        if os.path.isfile(full_path):
            collected.append(doc)

    for d in KERNEL_SOURCE_DIRS:
        dir_path = os.path.join(repo_root, d)
        if not os.path.isdir(dir_path):
            continue
        for root, _, files in os.walk(dir_path):
            for f in files:
                if f.endswith((".c", ".h", ".S")):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, repo_root).replace("\\", "/")
                    collected.append(rel)

    collected.sort()
    return collected


def generate_manifest(repo_root, target="openwinkrnl", revision=None):
    """Generate the canonical manifest dictionary."""
    if revision is None:
        revision = get_git_revision(repo_root)

    file_paths = collect_kernel_files(repo_root)
    components = []

    for rel in file_paths:
        full = os.path.join(repo_root, rel)
        with open(full, "rb") as fh:
            data = fh.read()
        sha256 = hashlib.sha256(data).hexdigest()
        lic = determine_file_license(rel)
        components.append({
            "license": lic,
            "path": rel,
            "sha256": sha256,
        })

    # Components list is already sorted by path because file_paths was sorted.
    manifest = {
        "components": components,
        "effective_license": "GPL-3.0-or-later",
        "manifest_version": 1,
        "policy_class": "CORE_KERNEL",
        "source_revision": revision,
        "target": target,
    }
    return manifest


def serialize_canonical_manifest(manifest_dict):
    """Serialize dictionary to canonical UTF-8 bytes with LF newlines and sorted keys."""
    text = json.dumps(
        manifest_dict,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    # Ensure standard UNIX line endings
    text = text.replace("\r\n", "\n").rstrip("\n") + "\n"
    return text.encode("utf-8")


def compute_manifest_digest(canonical_bytes):
    """Compute 32-byte SHA-256 digest of canonical manifest bytes."""
    return hashlib.sha256(canonical_bytes).digest()


def selftest():
    """Verify determinism and consistency of manifest generation."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    fixed_rev = "f9ebe72ec515cbba250f96fc88d8947688b8d0f7"
    m1 = generate_manifest(repo_root, revision=fixed_rev)
    b1 = serialize_canonical_manifest(m1)
    d1 = compute_manifest_digest(b1)

    m2 = generate_manifest(repo_root, revision=fixed_rev)
    b2 = serialize_canonical_manifest(m2)
    d2 = compute_manifest_digest(b2)

    assert b1 == b2, "Manifest serialization is not deterministic!"
    assert d1 == d2, "Manifest digest is not deterministic!"
    assert len(d1) == 32, "Manifest digest must be 32 bytes!"
    assert m1["policy_class"] == "CORE_KERNEL"
    assert m1["effective_license"] == "GPL-3.0-or-later"
    assert len(m1["components"]) > 50, f"Unexpectedly few components: {len(m1['components'])}"
    print(f"gen_license_manifest self-test passed: {len(m1['components'])} components, digest: {d1.hex()[:16]}...")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate OpenWindows CIS License Manifest")
    parser.add_argument("--repo-root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
                        help="Root directory of OpenWindows repository")
    parser.add_argument("--target", default="openwinkrnl", help="Target component name")
    parser.add_argument("--revision", default=None, help="Explicit source revision commit hash")
    parser.add_argument("--output", default=None, help="File to write canonical JSON manifest to")
    parser.add_argument("--digest-out", default=None, help="File to write hex digest to")
    parser.add_argument("--digest-only", action="store_true", help="Print only the hex digest to stdout")
    parser.add_argument("--self-test", action="store_true", help="Run internal reproducibility self-test")

    args = parser.parse_args(argv)

    if args.self_test:
        return selftest()

    manifest_dict = generate_manifest(args.repo_root, target=args.target, revision=args.revision)
    canonical_bytes = serialize_canonical_manifest(manifest_dict)
    digest = compute_manifest_digest(canonical_bytes)
    digest_hex = digest.hex()

    if args.output:
        with open(args.output, "wb") as f:
            f.write(canonical_bytes)

    if args.digest_out:
        with open(args.digest_out, "w", encoding="utf-8") as f:
            f.write(digest_hex + "\n")

    if args.digest_only:
        print(digest_hex)
    elif not args.output:
        sys.stdout.buffer.write(canonical_bytes)
    else:
        print(f"Generated manifest: {args.output} ({len(canonical_bytes)} bytes)")
        print(f"Manifest SHA-256:  {digest_hex}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

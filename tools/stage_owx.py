#!/usr/bin/env python3
"""Keep the kernel's staged .owx artifacts in step with the Essentials build.

The kernel Makefile embeds images from $(ESSENTIALS_ARTIFACTS)/<name>.owx, but
those files are produced by the OpenWindows-Essentials CMake build in a separate
tree.  Copying between the two by hand lets a rebuild of the Essentials target
leave the staged artifact stale, so the kernel silently embeds and boots the old
image.

This helper closes that gap with a digest comparison rather than a guess:

    stage_owx.py <source.owx> <staged.owx>
        copy source over staged when their SHA-256 differ, else no-op.

    stage_owx.py --verify <source.owx> <staged.owx>
        copy nothing; fail when they differ (or either file is absent).

Both modes exit non-zero with an actionable message when the source does not
exist.  Copy mode never leaves the staged file untouched-but-different, and
--verify is the pre-flight gate the QEMU regression runs so the image that is
booted is provably the one the Essentials build just produced.
"""
import hashlib
import os
import shutil
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv):
    args = argv[1:]
    verify = False
    if args and args[0] == "--verify":
        verify = True
        args = args[1:]

    if len(args) != 2:
        sys.stderr.write("usage: stage_owx.py [--verify] <source.owx> <staged.owx>\n")
        return 2

    source, staged = args

    if not os.path.isfile(source):
        sys.stderr.write(
            "error: Essentials build output not found: %s\n"
            "       build it first, for example:\n"
            "         cmake --build <essentials-build-dir> --target <name>.owx\n"
            "       then re-run, or point ESSENTIALS_BUILD at that build directory.\n"
            % source)
        return 1

    source_hash = sha256(source)
    staged_hash = sha256(staged) if os.path.isfile(staged) else None

    if source_hash == staged_hash:
        print("up to date: %s (%s)" % (staged, source_hash))
        return 0

    if staged is None or not os.path.isfile(staged):
        if verify:
            sys.stderr.write(
                "error: staged artifact is missing: %s\n"
                "       it must be staged from %s before this check\n"
                % (staged, source))
            return 1
        shutil.copyfile(source, staged)
        print("staged: %s <- %s (%s)" % (staged, source, source_hash))
        return 0

    if verify:
        sys.stderr.write(
            "error: staged artifact does not match the Essentials build output\n"
            "       source: %s  %s\n"
            "       staged: %s  %s\n"
            "       re-stage it, for example: make stage-bancat\n"
            % (source, sha256(source), staged, sha256(staged)))
        return 1

    shutil.copyfile(source, staged)
    print("staged: %s <- %s (%s)" % (staged, source, source_hash))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

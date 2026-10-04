# Copyleft Integrity Safeguard (CIS)

## Architecture

- CIS Kernel Core runs in Ring 0 and has no process ID; it is the mandatory security authority for executable image verification.
- cis.owx is the Ring 3 CIS service (reporting/management surface). It is not consulted before a load is allowed; killing it does not change CIS behavior.
- PID 1 is owinit.owx.
- CIS enforcement does not depend on PID 2 (cis.owx) remaining alive.
- The kernel remains the mandatory security authority; CIS cannot be disabled by any recovery runlevel.

CIS separates three properties and never collapses them into a single generic "verified" boolean:
- integrity: bytes hash to the digest stamped by the packer
- authenticity: those bytes were signed by a pinned key
- compliance: signed metadata satisfies the active policy

## Verification pipeline

```
OWX image
  → parse/format validation
  → SHA-256 integrity measurement
  → Ed25519 signature verification
  → trusted-key/provenance validation
  → authenticated license metadata
  → CIS license policy
  → LOAD / QUARANTINE / RECOVERY
```

Signature coverage includes the canonical authenticated metadata and image digest as implemented by the CIS format. Only fields present in the actual implementation are used.

## License policy

Authenticated license metadata (not raw text scanning) is the sole source of license claims evaluated by policy.

### Why CIS Does Not Scan Raw Binaries for "GPL"
CIS explicitly rejects scanning raw compiled binary images for literal strings such as `"GPL"` or `"General Public License"`. A text scan over binary bytes is fundamentally insecure and ineffective:
1. **Trivial Evasion & Spoofing**: An unauthenticated, proprietary, or modified binary can embed a dummy `"GPL"` string literal anywhere in its data sections to trick a naive scanner.
2. **False Negatives**: Legitimate GPL code might compress strings, link them dynamically, or strip text sections, causing spurious boot refusals.
3. **Absence of Provenance**: A raw string scan provides zero cryptographic evidence connecting the executable binary to an actual, authentic OpenWindows source code release.

Instead, CIS enforces license compliance through **cryptographically authenticated provenance metadata**:
- Authenticity is established via Ed25519 signatures from trusted, pinned release keys over the canonical CIS trailer block (`CICB`).
- Policy compliance is verified by comparing the authenticated metadata tags (`OW_CIS_TAG_POLICY_CLASS`, `OW_CIS_TAG_LICENSE`, `OW_CIS_TAG_SOURCE_DIGEST`) against active policy invariants.

### CORE_KERNEL Policy Architecture
For components operating under the `CORE_KERNEL` policy (such as `openwinkrnl.owx` and images mapped with `OWX_SUBSYSTEM_NATIVE`):
- **Mandatory Policy Class**: The image must declare and authenticate `OW_CIS_TAG_POLICY_CLASS` as `"CORE_KERNEL"`.
- **Strict Copyleft License**: The authenticated license expression (`OW_CIS_TAG_LICENSE`) must be `"GPL-3.0-or-later"`. Non-GPL licenses (such as `"MIT"`, `"Apache-2.0"`, or `"BSD"`) are unconditionally rejected with `OW_CIS_VERDICT_REJECT_POLICY`.
- **Source-to-Binary Binding**: The image must carry an authenticated 32-byte source manifest digest (`OW_CIS_TAG_SOURCE_DIGEST`) binding the exact source code release that produced the kernel image. Missing or malformed source digests result in immediate policy rejection.

### Userspace Policy
Components in userspace (such as `owinit.owx`, GUI programs, or system utilities) evaluate against permissive licenses accepted for userspace execution (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `BSD-2-Clause`), preserving flexibility while enforcing ring-0 gating.

## Source-to-Binary Cryptographic Binding

To prevent substitution attacks and ensure reproducible, audited builds, OpenWindows implements deterministic source manifest generation via `tools/gen_license_manifest.py`:
1. **Deterministic Discovery**: Normalizes relative POSIX paths (`foo/bar.c`) and sorts them lexicographically under `LC_ALL=C`.
2. **Component & License Attribution**: Evaluates each repository component against `LICENSE` and `THIRD-PARTY-NOTICES.md`.
3. **Content Digesting**: Hashes each identified source file with SHA-256.
4. **Canonical Serialization**: Emits a deterministic, line-terminated JSON manifest (`openwinkrnl_manifest.cislm`).
5. **Release Binding**: The SHA-256 digest of this canonical manifest is embedded into the kernel's signed CIS block under tag `0x0008` (`OW_CIS_TAG_SOURCE_DIGEST`).

Any modification to kernel source files alters the manifest digest, breaking the cryptographic binding unless officially signed by an authorized release key.

## Offline Recovery Architecture

```
Invalid / Tampered Kernel on Storage
                ↓
Sentinel detects policy or checksum failure
                ↓
Quarantine invalid kernel (record BANcode telemetry)
                ↓
Scan local offline recovery partition / volume
                ↓
Execute complete CIS 7-stage verification on recovery image:
  1. OWX format & loadability check
  2. SHA-256 image content digest
  3. Ed25519 cryptographic signature check
  4. Trust store validation (accepts OW_CIS_KEY_FLAG_RECOVERY)
  5. Policy class check (CORE_KERNEL)
  6. License check (GPL-3.0-or-later)
  7. Source manifest digest binding
                ↓
Passes? ─── YES ──> Stage recovery kernel as next boot image & reboot
        ─── NO  ──> Drop BanHammer (fatal halt / SMP freeze)
```

No network or remote downloads are attempted during recovery; recovery is fully self-contained, offline, and fail-closed.

## Development trust

- Default/production behavior is fail-closed.
- `CIS_DEV_TRUST=1` is an explicit, opt-in build configuration.
- Dev trust provisions only the development public trust anchor (`DEV_IMAGE_KEY`).
- Dev signing is strictly for development and testing; the private signing seed (`DEV_IMAGE_SEED`) is never embedded into shipping target binaries.
- A dev-signed image is never accepted by a production build without `CIS_DEV_TRUST`.
- Both Make and CMake build systems support this mode via the same flags (`make hosttest/all CIS_DEV_TRUST=1` or `cmake -DCIS_DEV_TRUST=ON`).

## Failure behavior

Distinct rejection verdicts are preserved:
- `OW_CIS_VERDICT_REJECT_MALFORMED`: Malformed OWX or corrupted CIS block.
- `OW_CIS_VERDICT_REJECT_UNSIGNED`: Unsigned image (no CIS block present).
- `OW_CIS_VERDICT_REJECT_BAD_SIGNATURE`: Cryptographic signature does not verify under the key.
- `OW_CIS_VERDICT_REJECT_UNKNOWN_KEY`: Signer key ID not found in pinned trust store.
- `OW_CIS_VERDICT_REJECT_KEY_REVOKED`: Pinned key is marked revoked.
- `OW_CIS_VERDICT_REJECT_DIGEST_MISMATCH`: Mapped image bytes do not match signed content digest.
- `OW_CIS_VERDICT_REJECT_POLICY`: Policy violation (non-GPL license for CORE_KERNEL, missing source digest, or unauthorized subsystem).
- `OW_CIS_VERDICT_ERROR`: Subsystem unarmed or invalid execution arguments.

The loader maps every rejection to a corresponding `OW_ERR_CIS_*` error code and never treats non-trusted verdicts as authorization. Failed verification cannot leave an executable mapping, VAD, thread, or entry point published.

## Security invariants

- CIS cannot be disabled by a recovery runlevel.
- Mandatory verification occurs before any executable image is mapped or executed.
- Failed verification cannot leave an executable mapping, process, or thread published.
- An empty production trust store is intentionally fail-closed.
- The kernel does not trust arbitrary user-provided keys.


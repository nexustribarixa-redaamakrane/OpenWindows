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

For components governed by a GPL-only policy:
- authenticated GPL license metadata → allow
- non-GPL / unknown / missing / invalid metadata → reject

CIS does not determine legal validity or copyright ownership from a string; it enforces machine policy against authenticated metadata. Policy classes may differ; not all components are automatically subject to GPL unless the active policy requires it.

## Development trust

- Default/production behavior is fail-closed.
- CIS_DEV_TRUST=1 is explicitly opt-in.
- Dev trust provisions only the development public trust anchor.
- Dev signing is for development/testing only.
- The private development signing seed/key must not be embedded in the target.
- A dev-signed image is not automatically trusted under production configuration.
- Both Make and CMake support this mode via the same mechanism (make hosttest/all with CIS_DEV_TRUST=1).

## Failure behavior

Distinct rejection verdicts are preserved:
- malformed OWX
- unsigned image
- bad signature
- unknown key
- revoked key
- digest mismatch
- license-policy violation
- storage/truncation problems
- verification could not run (error)

The loader maps OW_CIS_VERDICT_NONE to refusal (error) and never treats it as authorization. Failed verification cannot leave an executable mapping, VAD, thread, or entry point published.

## Security invariants

- CIS cannot be disabled by a recovery runlevel.
- Mandatory verification occurs before executable image use.
- Failed verification cannot leave an executable mapping/process/thread published.
- An empty production trust store is intentionally fail-closed.
- The kernel does not trust arbitrary user-provided keys.

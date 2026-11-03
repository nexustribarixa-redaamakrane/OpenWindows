# OpenWindows SuperUnicode Adoption Matrix

This matrix is the implementation record for the OpenWindows reference
kernel. “Partial” means that the SuperUnicode reference implementation is
compiled and at least one OpenWindows path uses the relevant API, but the
document's complete data corpus, userspace surface, or runtime evidence is
not yet complete. It is not a compliance claim.

## SUAS standards

| ID | Title | OpenWindows implementation and integration | Evidence | Status | Remaining work |
|---|---|---|---|---|---|
| SUAS-001 | Structural Directional Framing (SDF) | `superunicode/src/suas/suas_sdf.c`; kernel text build | SuperUnicode SDF tests | Partial | Integrate directional scopes into console/rendering |
| SUAS-002 | System Glyph Width (SGW) | `suas_sgw.c`; SCTS plane width path | SGW and SCTS tests | Partial | Full font/grid profile |
| SUAS-003 | System Boundary and Line Break Rules (SBR) | `suas_sbr.c`; SCTS wrapping | SBR and SCTS tests | Partial | End-to-end shell line editor |
| SUAS-004 | SuperUnicode Canonical Forms (SUCF) | `suas_sucf.c`; compiled into kernel | SUCF tests | Partial | Apply normalization at all text ingress points |
| SUAS-005 | System Script Property (SSP) | `suas_ssp.c`; compiled into kernel | SSP tests | Partial | Userspace script routing |
| SUAS-006 | System Text Segmentation (STS) | `suas_sts.c`; STX/SCTS path | STS tests | Partial | Cluster evidence for all console operations |
| SUAS-007 | System Identifiers and Syntax (SIS) | `suas_sis.c`; SKTO/SFS admission | SIS and SKTO tests | Partial | Configuration and shell identifier policy |
| SUAS-008 | System Named Character Sequences (SNCS) | `suas_sncs.c`; compiled into kernel | SNCS tests | Partial | Public userspace lookup API |
| SUAS-009 | System Ideographic Properties (SIP) | `suas_sip.c`; compiled into kernel | SIP tests | Partial | Rendering/property consumers |
| SUAS-010 | Specification Registry (SSRE) | `suas_ssre.c`; build and registry surfaces | SSRE tests and doc verifier | Partial | Kernel boot gate for registry validity |
| SUAS-011 | Character Manifest and Schema (SCMS) | `suas_scms.c`; compiled into kernel | SCMS tests | Partial | Kernel image/data manifest admission |
| SUAS-012 | SuperUnicode Character Database (SUCD) | `suas_sucd.c`; SUCHA authority adapter | SUCD tests | Partial | Mount and verify production character image |
| SUAS-013 | Ideographic Source Registry (SISR) | `suas_sisr.c`; compiled into kernel | SISR tests | Partial | Rendering fallback consumer |
| SUAS-014 | Vertical Text Layout (SUVTL) | `suas_suvtl.c`; STRS dependency | SUVTL tests | Partial | Console vertical mode |
| SUAS-015 | Arabic Mark Rendering (SUAMR) | `suas_suamr.c`; compiled into kernel | SUAMR tests | Partial | Renderer shaping integration |
| SUAS-016 | Egyptian Hieroglyph Database (SUKEMET) | `suas_sukemet.c`; compiled into kernel | SUKEMET tests | Partial | Renderer/property consumer |
| SUAS-017 | East Asian Script Data (SUEASD) | `suas_sueasd.c`; compiled into kernel | SUEASD tests | Partial | East Asian spacing integration |
| SUAS-018 | System Kernel Text Objects (SKTO) | `ow_skto_name.c` and `suas_skto.c`; VFS boundary | SKTO and host boundary tests | Partial | Generalize descriptors beyond names |
| SUAS-019 | System Text Input Model (STIM) | `suas_stim.c`; reference compiled | STIM tests | Partial | Route HAL keyboard events through STIM |
| SUAS-020 | SuperUnicode Character Authority (SUCHA) | `suas_sucha.c`; OpenWindows authority adapter | subsystem tests | Partial | Production SUCD image lifecycle |
| SUAS-021 | System Text Services (STX) | `suas_stx.c`; host text pipeline | subsystem tests | Partial | Shell/editor integration |
| SUAS-022 | System Kernel Test and Conformance (SKTC) | `suas_sktc.c`; host gate | subsystem tests | Partial | Boot-time mandatory conformance gate |

## SUTS specifications

| ID | Title | Implementation and integration | Evidence | Status | Remaining work |
|---|---|---|---|---|---|
| SUTS-001 | SuperUnicode Collation Algorithm (SUCA) | `suts_suca.c`; compiled into OS | SUCA tests | Partial | Filesystem/search/configuration collation |
| SUTS-002 | SuperUnicode Regular Expressions (SRE) | `suts_sre.c`; compiled into OS | SRE tests | Partial | Shell/developer utility consumer |
| SUTS-003 | System Locale Data and Formatting (SLDF) | `suts_sldf.c`; compiled into OS | SLDF tests | Partial | Locale service and formatting APIs |
| SUTS-004 | System Ideographic Variation Database (SIVD) | `suts_sivd.c`; compiled into OS | SIVD tests | Partial | Renderer variation selection |
| SUTS-005 | System Character Security (SCSS) | `suts_scss.c`; compiled into OS | SCSS tests | Partial | Identifier/security policy wiring |
| SUTS-006 | Internationalized Domain and Identifier Network (SIDN) | `suts_sidn.c`; compiled into OS | SIDN tests | Partial | Network/name consumers |
| SUTS-007 | Emoji and Presentation (SUEPS) | `suts_sueps.c`; STRS dependency | SUEPS tests | Partial | Renderer presentation selection |
| SUTS-008 | Source Code Handling (SUSCH) | `suts_susch.c`; compiled into OS | SUSCH tests | Partial | Build/developer tools |
| SUTS-009 | Link Detection and Formatting (SULDF) | `suts_suldf.c`; compiled into OS | SULDF tests | Partial | Shell/terminal link consumer |
| SUTS-011 | Set Notation (SUSN) | `suts_susn.c`; compiled into OS | SUSN tests | Partial | Query and tooling consumer |
| SUTS-012 | System Console Text Service (SCTS) | SCTS plane and `OwSuperUnicodeConsoleWrite()` in `lib/ow_superunicode.c`; kernel formatter path | OpenWindows hosttest; `openwinkrnl_pe` build | Partial | VGA glyph sink/font integration |
| SUTS-013 | System Console Terminal Emulation (SCTE) | SCTE terminal and incremental kernel output in `lib/ow_superunicode.c`/`lib/kprintf.c` | OpenWindows hosttest; `openwinkrnl_pe` build | Partial | Route physical console input and rendering sink fully |
| SUTS-014 | Identifier and Collation Layer (SUICL) | `suts_suicl.c`; compiled into OS | subsystem tests | Partial | VFS and shell collation |
| SUTS-015 | Locale and Presentation (SULP) | `suts_sulp.c`; compiled into OS | subsystem tests | Partial | Userspace locale service |
| SUTS-016 | Text Rendering Subsystem (STRS) | `suts_strs.c`; compiled into OS | subsystem tests | Partial | Hardware/font backend |

SUTS-010 remains the deliberate specification gap and is not implemented.

## SUTR technical reports

| ID | Title | Implementation/evidence | Status |
|---|---|---|---|
| SUTR-0 | SUCS Core | `sutr_sucem.c`, SUCS boot mode | Partial |
| SUTR-1 | SUTF Encoding Forms | `sutf` sources, CIS and VFS SUTF paths | Partial |
| SUTR-2 | SUCA | SUTS-001 implementation | Partial |
| SUTR-3 | SuperUnicode Storage | OpenWindows-Storage plus SFS boundary | Partial |
| SUTR-4 | ExtSUCS Transport | reference sources compiled | Partial |
| SUTR-5 | Plugin Lifecycle and Blob Format | reference sources compiled | Partial |
| SUTR-6 | Compatibility Bridge | SUTF/SUCS bridge paths | Partial |
| SUTR-7 | SUCEM | `sutr_sucem.c` and tests | Partial |
| SUTR-8 | SUCPM | `sutr_sucpm.c` and tests | Partial |
| SUTR-9 | SUMNLS | `sutr_sumnls.c` and tests | Partial |
| SUTR-10 | SUCM Conformance Model | `sutr_sucm.c`, SKTC | Partial |
| SUTR-11 | SUMS Mongolian Shaping | `sutr_sums.c` and tests | Partial |
| SUTR-012 | SUCSL Cuneiform Sign Lists | `sutr_sucsl.c` and tests | Partial |
| SUTR-013 | SUEAS East Asian Spacing | `sutr_sueas.c` and tests | Partial |
| SUTR-014 | OKTP OpenWindows Integration Profile | `sutr_oktp.c`; this matrix | Partial |
| SUTR-015 | System Input Events | `sutr_sie.c`; input adapter | Partial |
| SUTR-016 | System Filesystem | `sutr_sfs.c`; VFS admission | Partial |
| SUTR-017 | System IPC and Messaging | `sutr_sim.c`; IPC adapter | Partial |
| SUTR-018 | System Kernel Console | `sutr_skc.c`; `OwSuperUnicodeConsoleWrite()`; kernel formatter path | Partial |

## SUTN technical notes

| ID | Title | Applied evidence | Status |
|---|---|---|---|
| SUTN-001 | Implementation Checklist | This matrix and host/build gates | Applied |
| SUTN-002 | Unicode Analog Crosswalk | Used to identify complete family coverage | Applied |
| SUTN-003 | Document Selection Guide | Used to preserve SUTS-010 gap | Applied |
| SUTN-004 | Character Data Provenance | SUCD remains an explicit runtime gap | Applied |
| SUTN-005 | Release Evidence Pack | Build and hosttest evidence recorded | Applied |
| SUTN-006 | Zero-Allocation Integration Patterns | Freestanding reference sources and fixed buffers | Applied |

## Current conclusion

The complete available SUAS, SUTS, and SUTR reference source surface is now
compiled into the OpenWindows kernel/host build, and the SCTS/SCTE text
pipeline is exercised by the OpenWindows host test. This is substantial
adoption evidence, but it is **not yet full SuperUnicode compliance**: the
matrix deliberately records partial status where runtime data, renderer
backends, userspace consumers, or end-to-end evidence are still absent.

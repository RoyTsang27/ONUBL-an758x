# Security review — 2026-11-17

This update retains U-Boot v2026.10 (`5508406582f6f7120dce0c4b3059819a41788db2`), the latest stable release at review time. The next release is v2027.01; rc2 is a development release, not a new stable base. See the [upstream release schedule](https://docs.u-boot.org/en/latest/develop/release_cycle.html).

Review baseline: ONUBL-an758x `9e03f3cf621d349413617f2a08ff5ae44dfc9783`. Upstream reference: `83b1ec64ede9998566e6a82b22848c20a33f4aff` (2026-11-16 UTC). Recent upstream commit subjects, relevant diffs and the enabled AN758x paths were checked. This is a targeted review, not a guarantee that the entire project is free of vulnerabilities.

## Applied fixes

The [upstream UBI hardening series](https://github.com/u-boot/u-boot/commit/b3af4c333a507baf5a2d651be09da2ac68041193) rejects corrupt on-flash metadata before it can control memory reads or array/bitmap indices. UBI fastmap is enabled in this project.

| Upstream commit | Check added |
| --- | --- |
| [fc4faedf18cd](https://github.com/u-boot/u-boot/commit/fc4faedf18cdb8980af7a0f0b6efd7052a28bd5b) | VID data size cannot exceed the logical eraseblock. |
| [b98041160e4a](https://github.com/u-boot/u-boot/commit/b98041160e4af4a76cf7744aa0fd3355968509d6) | SPL rejects oversized LEB payloads before reading or computing the CRC. |
| [e309778ba841](https://github.com/u-boot/u-boot/commit/e309778ba841256f419b377d6118109a934271d6) | SPL validates physical eraseblock numbers from fastmap before bitmap access. |
| [7f4594e63709](https://github.com/u-boot/u-boot/commit/7f4594e637092ccdf679593b187f0c690380e1c5) | Core fastmap validates PEB numbers in pools, lists and superblocks. |
| [59d449d2b4e9](https://github.com/u-boot/u-boot/commit/59d449d2b4e9f02e59aa2bb452c3ee823e2a2b49) | Bound EBA entry counts before multiplication and check the EBA header fits. |
| [fa836529140b](https://github.com/u-boot/u-boot/commit/fa836529140bc41e0c50412ee89320f6d54301db) | The last static-volume LEB must fit the usable data area, including padding. |

The three SPL fixes are also ported into `tf-a/drivers/io/ubi/ubispl.c`. This vendor derivative is used by the preloader and has different endian helpers and a cached LEB read path. Its payload bound is checked before both length-only queries and the cache read. Updating only the U-Boot copy would leave the preloader exposed.

The host-side [mkimage fix f8b5bfc60d16](https://github.com/u-boot/u-boot/commit/f8b5bfc60d16cae86dd2fe49deb1bcd146d24f10) bounds nonempty external FIT data against the input file length before forming a pointer. Both relative data offsets and absolute data positions remain supported. Empty external payloads used by `mkimage -E -p` remain supported. No new CVE identifier was verified for these fixes; they are tracked here by upstream commit.

## Compatibility and validation

Valid UBI volumes, normal boot, full manual Web Recovery, restricted automatic recovery, persistent boot settings, unsigned development builds and fail-closed tagged signing retain their existing policy. These checks reject malformed metadata and use the existing error/fallback paths. No mandatory FIT signatures or anti-rollback policy is introduced.

`test/airoha/cve_regressions.py` compiles production parser functions with AddressSanitizer and UndefinedBehaviorSanitizer. New cases cover valid and oversized VID payloads, PEB boundary values, oversized/truncated EBA tables, the final static LEB size, the vendor preloader cache, replacement-block fallback, and real FIT files with valid/invalid external ranges and malformed property lengths. Existing FIP/FIT/BMP regressions remain enabled.

The GitHub Actions matrix runs the existing recovery, persistence, UBI compatibility and TF-A crypto checks and cross-builds all 14 devices. The source-artifact job checks reverse application of the patch and produces `ONUBL-2026-11-17.patch`, a replacements ZIP preserving repository paths, individual replacement files, and a SHA-256 manifest. Build/test results must be checked on the associated run before using binaries. These are software checks; XG-140G-TF and TF-S hardware boot behavior is not certified by this review.

## Other recent upstream changes

- The optional FIT configuration signature policy is not enabled: it would require a separate key and deployment policy review.
- Squashfs, RAUC bootmethod, OP-TEE/RPMB and legacy non-lwIP TCP fixes do not affect the enabled AN758x configurations reviewed here. Reassess if those features are enabled.
- [lwIP 2.2.1 synchronization](https://github.com/u-boot/u-boot/commit/e37860c563ac50708240d63ece09c350b0eb4f90) changes 103 library files. It includes TCP reordering and HTTP-server fixes in addition to fixes for disabled SNMP, PPP, HTTP-client file I/O and IPv6 paths. It is not included in this targeted patch: the custom Web Recovery server needs separate integration and runtime network testing before that library replacement.
- Airoha pinmux changes affect device-tree group selection. They are kept separate from this security update pending board-specific verification.

Existing v2026.10 and earlier project security backports remain in place. The upstream development tip is not merged wholesale.

# U-Boot v2026.10 upgrade

The U-Boot source base is the official v2026.10 release, commit
`5508406582f6f7120dce0c4b3059819a41788db2`:
<https://github.com/u-boot/u-boot/releases/tag/v2026.10>.
The source archive SHA-256 is
`9af5655e09851ece729f4bcdf36ab0c3617dbbbd2ea9f54afa3e1b01b1d589d9`.

The upgrade starts from ONUBL main
`23231c9a54f24340101280b1d86dbe14a6c2cd95`. A three-way comparison with the
original upstream v2026.07 (`ece349ade2973e220f524ce59e59711cc919263f`)
preserves the project's additions and intentional removals while importing
the upstream changes. This is a source upgrade, including upstream drivers,
libraries, device-tree bindings and build infrastructure.

## Preserved behavior

All 12 build targets retain their board device trees, flash partition and UBI
layouts, Ethernet/PHY configuration, board-data volumes, reset-button entry,
and bilingual Web recovery interface. The bundled TF-A sources and LZMA SDK
remain unchanged.

Manual recovery (`httpd`, `httpd dhcp`, Reset, or the boot menu) retains full
privileges. Automatic failed-system boot invokes `boot_recovery_auto`, which
starts `httpd dhcp safe`. Protected HTTP operations return 403 in safe mode;
`/api/info` continues to report recovery privilege state. Serial and TFTP
recovery remain available.

Unsigned development builds remain supported. Tagged Actions releases still
set `AIROHA_REQUIRE_SIGNING=1` and fail if no usable RSA-4096 signing key is
provided or signing fails. FIT signatures and anti-rollback are not made
mandatory by this upgrade.

## Compatibility adaptations

- AN7581/AN7583 DRAM bank initialization uses `gd->dram`, matching the new
  upstream memory API, while retaining the original memory-size detection,
  addresses and bank split.
- The shared pinctrl driver uses the new upstream GPIO state API. The
  downstream SoC pin groups and pull/drive tables are retained because they
  describe the supported boards' wiring.
- The lwIP transmit path uses upstream's aligned buffer and chained-pbuf
  handling.
- UBI uses upstream's public, const-correct API and negative error convention.
  The existing recovery helper entry points remain available. Streamed
  backup reads retain bounds checking, positive recovery error values and
  suppression of `filesize` and activity-LED changes. Normal UBI reads keep
  their normal metadata updates.
- The Nokia MD defconfig's duplicate PCS selection is removed. Its selected
  value is unchanged.

## Validation

Local validation covers compiled HTTP recovery behavior, real OpenSSL key
validation with mocked TF-A packaging tools, all board environment expansions,
and preservation of the recovery operation handlers. Actual changed U-Boot C
files are cross-compiled to AArch64 objects against the generated v2026.10
headers. All 12 defconfigs and board DTBs are checked.

These local macOS object checks skip the Linux/GNU local-export check and do
not link complete firmware. The existing Ubuntu Actions matrix performs the
complete U-Boot, TF-A preloader and FIP builds with the original toolchains.
Hardware boot and flash tests are not part of these checks.

The repository includes a memory-backed regression test of the actual UBI
recovery helpers; the Actions matrix runs it before packaging:

```sh
python3 test/airoha/ubi_compat.py
```

## Existing saved environments

An environment already saved in NAND can override compiled defaults. To
restore the automatic recovery defaults after upgrading, use the serial
console:

```text
env default boot_ubi boot_recovery_auto
saveenv
```

This restores only the listed variables. Keep board data and other custom
environment settings as needed.

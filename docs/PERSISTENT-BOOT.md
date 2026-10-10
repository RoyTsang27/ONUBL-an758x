# Persistent U-Boot installation

A complete installation boots from NAND after reboot or power loss. It has two
components: the board's BL2 preloader in the raw `bl2` partition, and its
`*-bl31-u-boot.fip` in the static UBI volume `fip`. The system image lives in
`fit`; its writable overlay lives in `rootfs_data`.

## Install once

1. Select artifacts for the exact device/SoC and back up all MTD partitions and
   UBI volumes, including board data.
2. Install BL2 using the existing stock-to-UBI or manual installation procedure
   in [README.md](../README.md). A `*-firstblock.bin` is written at NAND offset
   `0x0`. A bare `*-preloader.bin` belongs at `0x800` in an erased first block.
   Keep the board's NAND geometry and bad-block handling from that procedure.
3. XMODEM or TFTP can start U-Boot in RAM for installation. Once there, enter
   manual Web Recovery, prepare the UBI layout if this is the first conversion,
   then use **Flash U-Boot** to write the matching `*-bl31-u-boot.fip` to `fip`.
   Rebuilding UBI must happen before this FIP write. Existing installations do
   not need a UBI rebuild for a normal system upgrade.
4. Restore the board-data volumes required by the device and install its
   compatible OpenWrt/ImmortalWrt UBI FIT system image.
5. Wait for the flash/readback operation to finish. Disconnect the temporary
   serial transfer/TFTP server and power-cycle the device. Verify the installed
   U-Boot version banner and that the device boots without sending another FIP.
   This distinguishes a resident installation from a temporary RAM session.

The Web BL2 and U-Boot flash handlers verify readback before reporting success.
The TFTP flash commands also perform their existing size/readback checks.

## Later OpenWrt/ImmortalWrt upgrades

Use a sysupgrade image for the exact board **and the UBI boot layout**. For
example, the Nokia XG-040G-MD UBI variant uses `sysupgrade.itb`; the original
stock-layout variant is a different installation target. Other devices need
firmware built for their board's matching layout.

Normal Web **Install system** and TFTP **Flash system** only replace the system
volumes. They preserve `bl2`, `fip`, the environment volumes and board data.
The supported OpenWrt/ImmortalWrt UBI FIT sysupgrade path selects the system
volume from the running device tree and updates it through UBI. It does not
normally reinstall the bootloader.

A raw factory/UBI image, stock-layout conversion, explicit UBI rebuild, NAND
scrub or whole-partition reformat is outside that normal upgrade path. A
whole-UBI reformat deletes `fip`. OpenWrt's generic NAND helper can reformat
UBI when attachment fails, so a damaged UBI needs recovery rather than a
routine sysupgrade. U-Boot cannot enforce Linux-side writes after Linux starts.
If a custom firmware changes that behavior, its upgrade scripts must also be
reviewed; changing only this repository cannot guarantee preservation under an
arbitrary Linux flasher.

Manual bootloader flashing, raw recovery operations and UBI rebuild remain
available in full/manual recovery. Automatic boot-failure recovery keeps its
restricted privileges. This change does not introduce mandatory FIT signing or
anti-rollback.

## Verify preservation

Before and after a normal system upgrade, record the U-Boot version from the
serial console and compare hashes of the same installed BL2 bytes and the
used FIP bytes. NAND padding, bad-block handling and volume capacity mean that
hashes of an entire raw partition need not equal hashes of a downloaded file.
Then cold-boot without any temporary boot transfer and verify both the U-Boot
version and the new system version.

Actions runs `test/airoha/persistent_boot.py`. It compiles the actual Web
firmware update handler with a memory-backed UBI fixture and verifies protected
contents during a successful update and nine failure cases. It also walks the
actual TFTP system-update command graph and checks its write targets. These
checks cover the source's storage behavior; the final power-cycle and Linux
sysupgrade checks require the device.

## Upgrade implementation references

- [OpenWrt AN7581 platform selection](https://github.com/openwrt/openwrt/blob/main/target/linux/airoha/an7581/base-files/lib/upgrade/platform.sh)
- [OpenWrt FIT upgrade dispatch](https://github.com/openwrt/openwrt/blob/main/package/utils/fitblk/files/fit.sh)
- [OpenWrt NAND volume updates and reformat fallback](https://github.com/openwrt/openwrt/blob/main/package/base-files/files/lib/upgrade/nand.sh)
- [ImmortalWrt FIT upgrade dispatch](https://github.com/immortalwrt/immortalwrt/blob/master/package/utils/fitblk/files/fit.sh)

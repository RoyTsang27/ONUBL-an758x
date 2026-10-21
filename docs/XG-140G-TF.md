# XG-140G-TF and XG-140G-TF-S (experimental)

These are two separate targets. Neither has been boot-tested with this fork.
A successful build establishes compile compatibility, not safe installation or
working Ethernet, GPIOs, NAND writes, or acceptance by a provisioned boot ROM.
Do not interchange the two artifacts or select an XG-040G target as an alias.

## Hardware evidence

| Detail | XG-140G-TF | XG-140G-TF-S |
| --- | --- | --- |
| Source | User's configuration export; public board-support contribution | User's historical stock TTL boot log |
| Identity | Model/ProductClass XG-140G-TF, hardware V01.00.X140TF, hardware part 3TN00509BAAA | Stock board ID XG140GTF-S |
| CPU | AN7581DT in configuration export | AN7581DT explicitly printed at boot |
| RAM | 512 MiB DDR3-1866 in public reference; XML memory fields are zero | 512 MiB; PCDDR3, data_rate 1866 in log |
| NAND | Public reference: SkyHigh S35ML02G300, 256 MiB | S35ML02G3, ID 01:25, 256 MiB; 2 KiB pages, 128-byte OOB, 128 KiB eraseblocks |
| LAN | Public reference: EN8811H 2.5G on LAN1, internal GbE LAN2/3/4 | Log reports four Ethernet ports and three 1G ports; external PHY identity is not established |
| Reset / power | Public common-board DTS uses GPIO0 / GPIO17, active low | Log prints power_gpio_2:11 (consistent with hex GPIO17); reset GPIO and polarity are not established |
| Stock secure provisioning | Not established by the XML export | Log says Secure key exist; enforcement/key acceptance is not established |

The public reference is [OpenWrt PR #20486](https://github.com/openwrt/openwrt/pull/20486),
a closed, unmerged contribution, not a certification for either target. It
reports shared PCB artwork and differing component populations for several
models. It does not establish TF-S compatibility. The TF-S log independently
confirms CPU, memory and NAND; it does not prove every component matches TF.
The raw configuration and TTL log are deliberately not included in this repo:
they can contain credentials, device identifiers and optical registration data.

Both initial profiles use the existing AN7581 SPI-NAND UBI recovery design,
512 MiB memory, UART1 at 115200n8, GPIO0 reset and GPIO17 status LED. For TF-S,
the GPIO choices and LED polarity are explicit, unverified board assumptions.
The generic LED name status:power avoids claiming a confirmed LED color.
USB and Wi-Fi are not enabled. The existing SkyHigh NAND driver already covers
ID 01:25, its geometry, on-die ECC status and protected-register initialization;
no ID-only NAND substitute or disabling of ECC is added.

Recovery uses the existing gdm1 switch path. Start Ethernet qualification with
the 1G LAN ports; operation of LAN1 at 2.5G, PHY reset wiring, and port labels
still require testing. PON/voice operation belongs to the system firmware and
is not provided by this bootloader.

## Building and artifacts

With the toolchains and Mbed TLS configured as in the main README:

~~~sh
sh scripts/build-an758x.sh xg-140g-tf
sh scripts/build-an758x.sh xg-140g-tf-s
~~~

Outputs are isolated in output/xg-140g-tf/ and output/xg-140g-tf-s/. The named
preloader and FIP files use these distinct prefixes:

- an7581-nokia-xg-140g-tf-experimental
- an7581-nokia-xg-140g-tf-s-experimental

Each has its own defconfig, device tree, U-Boot DTS additions, environment,
model string and UBI-compatible identity. Default system/recovery filenames
also identify the exact model. They are naming defaults for suitably built
firmware, not a claim that official OpenWrt images already exist for this layout.
CI builds all 14 targets and validates the compiled new-board DTBs and default
environments. Each download includes a board-prefixed SHA256SUMS file generated
by the builder. These SPI-NAND targets do not use the parallel-NAND firstblock
wrapper.

## Installation and persistence limits

**Do not apply the generic README stock conversion instructions to these
experimental boards without qualifying the exact unit first.** This fork uses
BL2 at 0x0 (0x20000 bytes) and UBI at 0x20000 (0xffe0000 bytes), with FIP in UBI.
The TF-S stock log instead shows a 0x80000-byte bootloader partition, kernel
starting at 0xc0000, bosa at 0x51c0000 and ri at 0x5200000. Its stock BMT/BBT
mapping is not the new UBI layout. Copying stock offsets or writing a generic
sysupgrade into stock NAND is not a supported conversion.

Before any permanent write, obtain and verify a restorable full NAND backup
(including the information needed by the actual stock NAND/ECC interface),
stock bootloader, RI/BOSA/calibration, environment and optical provisioning.
Qualify the boot chain on the exact hardware using a recoverable boot method
available on that unit, then check NAND identity/geometry/ECC, non-destructive
reads, reset/LED behavior and Ethernet. A TTL log is not a flash backup.
The TF-S Secure key exist message cannot be used to infer that an unsigned or
newly signed image will be accepted. This work does not change OTP/eFuses,
bypass ROM authentication, or promise that a different key will work.

The normal manual/physical recovery policy and safe automatic recovery are
inherited unchanged. Compatible UBI FIT system updates preserve the stored FIP
and board-data volumes; see [persistent boot](PERSISTENT-BOOT.md). A UBI rebuild,
raw all-flash write, or system updater that reformats the entire NAND can erase
them. OpenWrt/ImmortalWrt must support this exact board identity and UBI layout;
that firmware work and a hardware conversion procedure are separate validation.

中文：TF 与 TF-S 分开构建，均为实验性支持，尚未真机验证。TF-S 日志已确认
AN7581DT、512 MiB DDR3-1866、256 MiB S35ML02G3；Reset 引脚、LED 极性、
外置 PHY 与安全启动接受条件仍需核实。原厂分区不同于本项目 UBI 布局，日志不能
代替 NAND/RI/BOSA/光学注册数据备份；完成可恢复启动验证前不要永久刷写。

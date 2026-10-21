#!/usr/bin/env python3
"""Check the actual built DTB/config/environment for each experimental model."""
from pathlib import Path
import subprocess
import sys


def main():
    target = sys.argv[1]
    if target not in ('xg-140g-tf', 'xg-140g-tf-s'):
        return
    root = Path(__file__).resolve().parents[2]
    build = root / 'build' / target / 'u-boot'
    dtb = root / 'output' / target / 'u-boot.dtb'
    config = (build / '.config').read_text()
    def prop(node, name, kind='s'):
        return subprocess.check_output(['fdtget', '-t', kind, str(dtb), node, name],
                                       text=True).strip()
    model = target.upper()
    assert prop('/', 'model') == 'Nokia ' + model
    assert prop('/', 'compatible').split()[0] == 'nokia,' + target + '-ubi'
    assert prop('/memory@80000000', 'reg', 'x') == '0 80000000 0 20000000'
    assert prop('/chosen', 'stdout-path') == 'serial0:115200n8'
    assert prop('/keys/key-reset', 'gpios', 'x').split()[1:] == ['0', '1']
    assert prop('/leds/led-power', 'gpios', 'x').split()[1:] == ['11', '1']
    assert 'CONFIG_DEFAULT_DEVICE_TREE="airoha/an7581-nokia-' + target + '"' in config
    assert 'CONFIG_ENV_SOURCE_FILE="an7581_nokia_' + target + '"' in config
    assert 'CONFIG_MTD_SPI_NAND=y' in config and 'CONFIG_AIROHA_UBI_ENV=y' in config
    assert '# CONFIG_MBEDTLS_LIB is not set' in config
    environment = subprocess.check_output(
        ['aarch64-linux-gnu-objcopy', '-O', 'binary',
         '--only-section=.rodata.default_environment',
         str(build / 'env/common.o'), '/dev/stdout']).decode()
    assert environment, 'compiled default environment section missing'
    for text in ('bootmenu_title=U-Boot ' + model + ' (experimental)',
                 'an7581-nokia-' + target + '-experimental-preloader.bin',
                 'an7581-nokia-' + target + '-experimental-bl31-u-boot.fip',
                 'nokia_' + target + '-ubi-squashfs-sysupgrade.itb',
                 'boot_recovery_auto=', 'httpd safe'):
        assert text in environment, text
    other = 'xg-140g-tf' if target.endswith('-s') else 'xg-140g-tf-s'
    assert ('nokia,' + other + '-ubi') not in prop('/', 'compatible').split()
    prefix = 'an7581-nokia-' + target + '-experimental'
    for suffix in ('-preloader.bin', '-firstblock.bin', '-bl31-u-boot.fip'):
        assert (dtb.parent / (prefix + suffix)).stat().st_size > 0
    print('PASS: ' + target + ' compiled DTB, config, recovery environment and artifact identity; hardware untested')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Execute actual vendor TF-A crypto/SMC code with sanitizers and Mbed TLS 3.6."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / 'tf-a/plat/ecnt/common'
MBEDTLS = Path(os.environ['MBEDTLS_DIR']).resolve()
assert (MBEDTLS / 'include/mbedtls/gcm.h').is_file()

CONFIG = '''
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PLATFORM_C
'''
PLATFORM = '''
#include <stdint.h>
#define EN7523_MEM_BASE 0x80000000UL
#define TZRAM2_BASE 0x80035000UL
#define TZRAM2_SIZE 0xb000UL
#define PAGE_SIZE 4096U
#define BL32_BASE 0x8a800000UL
#define BL32_LIMIT 0x8b000000UL
'''
XLAT = '''
#include <stddef.h>
#include <stdint.h>
#define MT_RO_DATA 1U
#define MT_RW_DATA 2U
#define MT_NS 4U
int mmap_add_dynamic_region(unsigned long long, uintptr_t, size_t, unsigned int);
int mmap_remove_dynamic_region(uintptr_t, size_t);
'''
CRYPTO = '''
#define CRYPTO_SUCCESS 0
#define CRYPTO_ERR_DECRYPTION 5
'''
SIP = '''
#define ECNT_SIP_E_SUCCESS 0
#define ECNT_SIP_E_INVALID_PARAM -2
#define ECNT_SIP_E_NOT_SUPPORTED -1
'''
with tempfile.TemporaryDirectory(prefix='airoha-tfa-security-') as folder:
    temp = Path(folder)
    def write(name, text):
        path = temp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    declaration = re.search(r'int ecnt_mbedtls_pkcs5_pbkdf2_compare\([^;]+;',
                            (COMMON / 'ecnt_plat_common.h').read_text()).group()
    write('ecnt_plat_common.h', '#include <ecnt_smc_security.h>\n' + declaration + '\n' + SIP)
    write('regression_mbedtls.h', CONFIG)
    write('platform_def.h', PLATFORM)
    write('ecnt_scu.h', 'unsigned int GET_DRAM_SIZE(void);\n')
    write('lib/xlat_tables/xlat_tables_v2.h', XLAT)
    write('common/debug.h', '')
    write('drivers/auth/crypto_mod.h', CRYPTO)
    write('drivers/auth/mbedtls/mbedtls_common.h', '')
    write('plat/common/platform.h', '''
#include <stddef.h>
#include <stdint.h>
#include <tools_share/firmware_encrypted.h>
int plat_get_enc_key_info(enum fw_enc_status_t, uint8_t *, size_t *,
                         unsigned int *, const uint8_t *, size_t);
''')
    # Compile the actual handler definitions, with only platform I/O replaced.
    source = (COMMON / 'ecnt_plat_common.c').read_text()
    handlers = source[source.index('uint64_t ecnt_verify_handler('):]
    assert 'uint64_t ecnt_decrypt_dm_key_handler(' in handlers
    write('vendor_handlers.inc', handlers)
    libraries = ['aes', 'aesni', 'aesce', 'gcm', 'cipher', 'cipher_wrap', 'md',
                 'sha256', 'sha512', 'pkcs5', 'platform', 'platform_util', 'constant_time']
    sources = [COMMON / 'ecnt_decrypt_dm_key.c', COMMON / 'ecnt_plat_mbedtls.c',
               ROOT / 'test/airoha/tfa_crypto_security.c']
    sources += [MBEDTLS / 'library' / (name + '.c') for name in libraries]
    for sanitizer, extra in [('address,undefined', ['-DECNT_CRYPTO_ONLY']),
                              ('undefined', ['-DTCSUPPORT_OPTEE'])]:
        binary = temp / ('regression-' + sanitizer.split(',')[0])
        command = [os.environ.get('HOSTCC', 'cc'), '-std=c11', '-O1', '-g',
                   '-fno-omit-frame-pointer', '-fno-sanitize-recover=all',
                   '-fsanitize=' + sanitizer, '-DIMAGE_BL31',
                   '-DMBEDTLS_CONFIG_FILE="regression_mbedtls.h"',
                   '-I' + str(temp), '-I' + str(COMMON),
                   '-I' + str(ROOT / 'tf-a/include'),
                   '-I' + str(MBEDTLS / 'include'), *extra,
                   *map(str, sources), '-o', str(binary)]
        subprocess.run(command, check=True)
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        subprocess.run([str(binary)], check=True, env=environment)
print('TF-A crypto, short/odd-length GCM, password fields and SMC mapping tests passed')

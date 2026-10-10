#!/usr/bin/env python3
"""Check that normal firmware updates preserve the resident NAND boot chain."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
source = (repo / 'net/lwip/httpd.c').read_text()
match = re.search(r'^static int run_firmware_update\(void\)\n\{', source, re.M)
assert match, 'missing firmware update handler'
end, depth = match.end(), 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
handler = source[match.start():end]
defines = []
for name, expected in [('HTTPD_UBI_PART', 'ubi'),
                       ('HTTPD_FIRMWARE_VOLUME', 'fit'),
                       ('HTTPD_DATA_VOLUME', 'rootfs_data'),
                       ('HTTPD_STAGING_VOLUME', 'fit.new')]:
    value = re.search(r'^#define\s+' + name + r'\s+"([^"]+)"', source, re.M)
    assert value and value[1] == expected, (name, value)
    defines.append('#define ' + name + ' "' + value[1] + '"')

fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CONFIG_IS_ENABLED(x) 1
#define CONFIG_SYS_LOAD_ADDR 0x80000000UL
#define CHUNKSZ_CRC32 64
#define CMD_RET_SUCCESS 0
#define CMD_RET_FAILURE 1
typedef unsigned long ulong;
typedef uint32_t u32;
static const char *phase;
static unsigned char ram[64], bl2[64];
static int scenario;
struct volume { const char *name; bool exists; unsigned char data[64]; };
static struct volume volumes[] = {
    { .name = "fip" }, { .name = "ubootenv" },
    { .name = "ubootenv2" }, { .name = "board-data" },
    { .name = "fit" }, { .name = "rootfs_data" }, { .name = "fit.new" }
};
static struct volume *find(const char *name) {
    for (unsigned i = 0; i < sizeof(volumes) / sizeof(volumes[0]); i++)
        if (!strcmp(volumes[i].name, name)) return &volumes[i];
    assert(!"unexpected volume"); return NULL;
}
static void mutable(const char *name) {
    assert(!strcmp(name, "fit") || !strcmp(name, "rootfs_data") ||
           !strcmp(name, "fit.new"));
}
static ulong env_get_ulong(const char *key, int base, ulong fallback) {
    assert(base == 16);
    if (!strcmp(key, "loadaddr")) return CONFIG_SYS_LOAD_ADDR;
    assert(!strcmp(key, "filesize")); return sizeof(ram);
}
static bool upload_region_valid(ulong addr, ulong size) {
    assert(addr == CONFIG_SYS_LOAD_ADDR && size == sizeof(ram));
    return scenario != 0;
}
static int validate_firmware_fit(ulong addr, ulong size) {
    assert(addr == CONFIG_SYS_LOAD_ADDR && size == sizeof(ram));
    return scenario == 1;
}
static void *map_sysmem(ulong addr, ulong size) {
    assert(addr == CONFIG_SYS_LOAD_ADDR && size == sizeof(ram)); return ram;
}
static void unmap_sysmem(void *buf) { assert(buf == ram); }
static u32 crc32_wd(u32 crc, const void *buf, ulong size, ulong chunk) {
    const unsigned char *bytes = buf;
    assert(chunk == CHUNKSZ_CRC32);
    for (ulong i = 0; i < size; i++) crc = crc * 31 + bytes[i];
    return crc;
}
static int ubi_part(char *name, void *offset) {
    assert(!strcmp(name, "ubi") && !offset); return scenario == 2;
}
static bool ubi_volume_exists(const char *name) { return find(name)->exists; }
static int ubi_volume_remove(const char *name) {
    mutable(name);
    if (scenario == 7) return 1;
    find(name)->exists = false; return 0;
}
static int ubi_volume_create(const char *name, ulong size, bool dynamic) {
    mutable(name); assert(!strcmp(name, "fit.new") && size == 64 && dynamic);
    if (scenario == 3) return 1;
    find(name)->exists = true; return 0;
}
static int ubi_volume_write(const char *name, const void *buf, ulong off, ulong size) {
    mutable(name); assert(!strcmp(name, "fit.new") && !off && size == 64);
    if (scenario == 4) return 1;
    memcpy(find(name)->data, buf, size); return 0;
}
static int ubi_volume_read(const char *name, void *buf, ulong off, ulong size) {
    assert(!strcmp(name, "fit.new") && !off && size == 64);
    if (scenario == 5) return 1;
    memcpy(buf, find(name)->data, size);
    if (scenario == 6) ((unsigned char *)buf)[0] ^= 1;
    return 0;
}
static int ubi_volume_rename(const char *oldname, const char *newname) {
    mutable(oldname); mutable(newname);
    assert(!strcmp(oldname, "fit.new") && !strcmp(newname, "fit"));
    if (scenario == 8) return 1;
    memcpy(find(newname)->data, find(oldname)->data, 64);
    find(newname)->exists = true; find(oldname)->exists = false; return 0;
}
'''

tests = r'''
int main(void) {
    unsigned char protected_before[4][64], bl2_before[64], uploaded[64];
    for (scenario = 0; scenario < 10; scenario++) {
        memset(bl2, 0xb2, sizeof(bl2)); memcpy(bl2_before, bl2, sizeof(bl2));
        for (unsigned i = 0; i < sizeof(volumes) / sizeof(volumes[0]); i++) {
            volumes[i].exists = true;
            memset(volumes[i].data, 0x20 + i, 64);
        }
        for (int i = 0; i < 4; i++) memcpy(protected_before[i], volumes[i].data, 64);
        for (int i = 0; i < 64; i++) ram[i] = i;
        memcpy(uploaded, ram, 64);
        assert(run_firmware_update() == (scenario == 9 ? 0 : 1));
        assert(!memcmp(bl2, bl2_before, 64));
        for (int i = 0; i < 4; i++) {
            assert(volumes[i].exists);
            assert(!memcmp(volumes[i].data, protected_before[i], 64));
        }
        if (scenario == 9) {
            assert(find("fit")->exists && !find("fit.new")->exists);
            assert(!memcmp(find("fit")->data, uploaded, 64));
        }
    }
    puts("PASS: actual Web firmware update preserves BL2/FIP/environment/board data in 10 success and failure scenarios");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='persistent-boot-') as temporary:
    path = Path(temporary)
    unit = path / 'test.c'
    unit.write_text('\n'.join(defines) + fixture + handler + tests)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
                   ['-std=gnu11', '-Wall', '-Werror', str(unit), '-o', str(path / 'test')],
                   check=True)
    subprocess.run([str(path / 'test')], check=True)

# Walk the actual TFTP system-update command graph. Bootloader updates remain
# separate manual operations; system updates may only mutate system volumes.
env = (repo / 'include/env/airoha/an758x-ubi.env').read_text()
commands = dict(line.split('=', 1) for line in env.splitlines()
                if re.match(r'^[a-zA-Z0-9_]+=', line))
seen = set()
def inspect(name):
    if name in seen:
        return
    seen.add(name)
    command = commands[name]
    assert not re.search(r'\b(?:mtd|nand|ubiformat|ubi_write_fip|mtd_write_bl2)\b', command), name
    for operation, volume in re.findall(r'\bubi\s+(remove|create)\s+([^\s;&|]+)', command):
        assert volume in ('fit', 'rootfs_data'), (name, operation, volume)
    for volume in re.findall(r'\bubi\s+write\s+\S+\s+([^\s;&|]+)', command):
        assert volume == 'fit', (name, volume)
    for child in re.findall(r'\brun\s+([a-zA-Z0-9_]+)', command):
        inspect(child)
inspect('boot_tftp_write_production')
assert 'ubi_write_production' in seen and 'ubi_verify_production' in seen
assert commands['bootcmd'] == 'run boot_production' or commands['bootcmd'] == 'run boot_ubi'
print('PASS: TFTP system update graph preserves bootloader storage:', ', '.join(sorted(seen)))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
"""Exercise FIP, FIT, BMP and UBI parsers with hostile metadata under ASan/UBSan."""
from pathlib import Path
import os
import re
import runpy
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r'^(?:static|int)[^;{}]*\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def compile_run(code, name, extra_args=()):
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / (name + '.c')
        binary = Path(directory) / name
        source.write_text(code)
        command = shlex.split(os.environ.get('HOSTCC', 'cc'))
        command += ['-std=gnu11', '-O1', '-g', '-fno-omit-frame-pointer',
                    '-fsanitize=address,undefined', '-I' + str(repo / 'tf-a/include'),
                    str(source), *extra_args, '-o', str(binary)]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)


fip = (repo / 'tf-a/drivers/io/io_fip.c').read_text()
states = fip[fip.index('typedef struct {'):fip.index('} fip_dev_state_t;') +
             len('} fip_dev_state_t;')]
fip_fixture = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tools_share/firmware_image_package.h>
#define WARN(...) ((void)0)
#define VERBOSE(...) ((void)0)
#define zeromem(p, n) memset(p, 0, n)
#define IO_SEEK_SET 1
struct io_fixture { uintptr_t info; };
typedef struct io_fixture io_entity_t;
typedef struct io_fixture io_dev_info_t;
typedef struct { uuid_t uuid; } io_uuid_spec_t;
static unsigned char backing[512];
static size_t backend_size, position;
static int fault, opened, reads;
static int plat_get_image_source(unsigned int id, uintptr_t *dev, uintptr_t *spec) {
    *dev = 1; *spec = 1; return 0;
}
static int io_open(uintptr_t dev, uintptr_t spec, uintptr_t *handle) {
    if (fault == 4) return -EIO;
    assert(!opened); opened = 1; position = 0; *handle = 1; return 0;
}
static int io_close(uintptr_t handle) { assert(opened); opened = 0; return 0; }
static int io_size(uintptr_t handle, size_t *length) {
    if (fault == 5) return -EIO;
    *length = backend_size; return 0;
}
static int io_seek(uintptr_t handle, int mode, signed long long offset) {
    if (fault == 6) return -EIO;
    assert(offset >= 0 && (uint64_t)offset < backend_size);
    position = offset; return 0;
}
static int io_read(uintptr_t handle, uintptr_t buffer, size_t length, size_t *got) {
    assert(opened && position <= backend_size && length <= backend_size - position);
    reads++;
    *got = length;
    if ((fault == 1 && position == 0) ||
        (fault == 2 && position == sizeof(fip_toc_header_t)) ||
        (fault == 3 && position == 128)) (*got)--;
    memcpy((void *)buffer, backing + position, *got);
    position += *got; return 0;
}
'''
fip_globals = r'''
static fip_file_state_t current_fip_file;
static fip_dev_state_t state;
static uintptr_t backend_dev_handle, backend_image_spec;
static io_dev_info_t device;
static io_uuid_spec_t wanted;
'''
fip_cases = r'''
static void reset(void) {
    fip_toc_header_t header = { .name = TOC_HEADER_NAME, .serial_number = 1,
                               .flags = (uint64_t)0x1234 << 32 };
    fip_toc_entry_t entry = { .offset_address = 128, .size = 8,
                             .flags = FW_ENCRYPTION };
    memset(&wanted, 1, sizeof(wanted)); entry.uuid = wanted.uuid;
    memset(backing, 0, sizeof(backing));
    memset(&current_fip_file, 0, sizeof(current_fip_file));
    memset(&state, 0, sizeof(state)); device.info = (uintptr_t)&state;
    memcpy(backing, &header, sizeof(header));
    memcpy(backing + sizeof(header), &entry, sizeof(entry));
    memset(backing + 128, 0x5a, 8);
    backend_size = sizeof(backing); position = 0; fault = opened = reads = 0;
}
static void bad_entry(uint64_t offset, uint64_t size) {
    io_entity_t entity = {0};
    fip_toc_entry_t entry = { .uuid = wanted.uuid, .offset_address = offset,
                             .size = size };
    reset(); entry.uuid = wanted.uuid;
    memcpy(backing + sizeof(fip_toc_header_t), &entry, sizeof(entry));
    assert(fip_dev_init(&device, 0) == 0);
    assert(fip_file_open(&device, (uintptr_t)&wanted, &entity) < 0);
    assert(!opened && !entity.info && !current_fip_file.entry.offset_address);
}
int main(void) {
    io_entity_t entity = {0}, second = {0};
    unsigned char output[16]; size_t got = 99, length;
    reset(); assert(fip_dev_init(&device, 0) == 0);
    assert(state.plat_toc_flag == 0x1234);
    assert(fip_file_open(&device, (uintptr_t)&wanted, &entity) == 0);
    assert(fip_file_len(&entity, &length) == 0 && length == 8);
    assert(fip_file_enc((uintptr_t)&entity) == FW_ENCRYPTION);
    assert(fip_file_open(&device, (uintptr_t)&wanted, &second) == -ENFILE);
    assert(fip_file_read(&entity, (uintptr_t)output, 3, &got) == 0 && got == 3);
    assert(fip_file_read(&entity, (uintptr_t)(output + 3), 5, &got) == 0 && got == 5);
    for (int i = 0; i < 8; i++) assert(output[i] == 0x5a);
    assert(fip_file_read(&entity, (uintptr_t)output, 0, &got) == 0 && got == 0);
    assert(fip_file_read(&entity, (uintptr_t)output, 1, &got) == -EINVAL && got == 0);
    assert(fip_file_close(&entity) == 0 && !entity.info);
    bad_entry(0, 8); bad_entry(511, 2); bad_entry(512, 1);
    bad_entry(128, 0); bad_entry(128, UINT64_MAX);
    bad_entry(UINT64_MAX - 3, 8); bad_entry(UINT64_C(1) << 32, 8);
    reset(); backend_size = sizeof(fip_toc_header_t) - 1;
    assert(fip_dev_init(&device, 0) < 0 && state.fip_size == 0 && !opened);
    reset(); fault = 1;
    assert(fip_dev_init(&device, 0) == -EIO && state.fip_size == 0 && !opened);
    reset(); assert(fip_dev_init(&device, 0) == 0); fault = 2;
    assert(fip_file_open(&device, (uintptr_t)&wanted, &entity) == -EIO && !opened);
    fault = 0;
    assert(fip_file_open(&device, (uintptr_t)&wanted, &entity) == 0);
    fault = 3; got = 99;
    assert(fip_file_read(&entity, (uintptr_t)output, 8, &got) == -EIO);
    assert(got == 0 && current_fip_file.file_pos == 0 && !opened);
    fip_file_close(&entity);
    reset(); assert(fip_dev_init(&device, 0) == 0);
    backend_size = sizeof(fip_toc_header_t) + sizeof(fip_toc_entry_t);
    state.fip_size = backend_size; memset(&wanted, 2, sizeof(wanted));
    assert(fip_file_open(&device, (uintptr_t)&wanted, &entity) < 0 && !opened);
    assert(reads == 2); /* header plus one ToC; no read beyond the backing extent */
    for (int failure = 4; failure <= 5; failure++) {
        reset(); fault = failure;
        assert(fip_dev_init(&device, 0) < 0 && state.fip_size == 0 && !opened);
    }
    reset(); assert(fip_dev_init(&device, 0) == 0); fault = 6;
    assert(fip_file_open(&device, (uintptr_t)&wanted, &entity) < 0 && !opened);
    puts("PASS: actual TF-A FIP parser rejects overflow, truncated ToC and short reads; valid reads and encryption flags preserved");
}
'''
fip_functions = '\n'.join(function(fip, name) for name in
                          ('compare_uuids', 'is_valid_header', 'fip_dev_init',
                           'fip_file_open', 'fip_file_len', 'fip_file_read',
                           'fip_file_close'))
# Vendor encryption flag accessor is non-static; keep it verbatim as well.
enc = fip[fip.index('int fip_file_enc('):fip.rindex('#endif')]
compile_run(fip_fixture + states + fip_globals + fip_functions + enc + fip_cases, 'fip')

bmp = (repo / 'drivers/video/video_bmp.c').read_text()
layout = (repo / 'include/bmp_layout.h').read_text()
layout = layout[layout.index('struct __packed bmp_color_table_entry'):layout.index('/* Data in')]
video = (repo / 'include/video.h').read_text()
video_format = re.search(r'enum video_format \{.*?\};', video, re.S)[0]
bmp_fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8, __u8, uchar;
typedef uint16_t u16, __u16;
typedef uint32_t u32, __u32;
typedef unsigned int uint;
typedef unsigned long ulong;
#define __packed __attribute__((packed))
#define debug(...) ((void)0)
#define BMP_RLE8_ESCAPE 0
#define BMP_RLE8_EOL 0
#define BMP_RLE8_EOBMP 1
#define BMP_RLE8_DELTA 2
static uint32_t get_unaligned_le32(const void *p) { uint32_t n; memcpy(&n, p, 4); return n; }
'''
bmp_device = r'''
struct video_priv { void *fb; int fb_size, line_length; enum video_format format; };
struct udevice { struct video_priv *priv; };
static struct video_priv *dev_get_uclass_priv(struct udevice *dev) { return dev->priv; }
'''
bmp_cases = r'''
static void run_case(const unsigned char *stream, size_t size, uint bpix,
                     int cursor, int expected) {
    unsigned char arena[256], image[256];
    struct bmp_image *bmp = (void *)image;
    struct bmp_color_table_entry palette[256] = {0};
    struct video_priv priv = { .fb = arena + 64, .fb_size = 64, .line_length = 16 };
    struct udevice device = { &priv };
    memset(arena, 0xa5, sizeof(arena)); memset(image, 0, sizeof(image));
    bmp->header.data_offset = sizeof(bmp->header);
    memcpy(image + sizeof(bmp->header), stream, size);
    assert(video_display_rle8_bitmap(&device, bmp, bpix, palette,
                                    arena + 64 + cursor, 0, 0, 4, 4) == expected);
    if (!expected) assert(arena[64 + cursor] != 0xa5);
    for (int i = 0; i < 64; i++) assert(arena[i] == 0xa5);
    for (int i = 128; i < 256; i++) assert(arena[i] == 0xa5);
}
int main(void) {
    unsigned char valid[] = { 4, 7, 0, 1 };
    unsigned char absolute[] = { 0, 3, 1, 2, 3, 0, 0, 1 };
    unsigned char eol[] = { 0, 0, 0, 0, 0, 0, 1, 7, 0, 1 };
    unsigned char delta[] = { 0, 2, 0, 3, 1, 7, 0, 1 };
    for (uint bpix = 8; bpix <= 32; bpix += 8) {
        run_case(valid, sizeof(valid), bpix, 48, 0);
        run_case(absolute, sizeof(absolute), bpix, 48, 0);
        run_case(eol, sizeof(eol), bpix, 48, -EINVAL);
        run_case(delta, sizeof(delta), bpix, 48, -EINVAL);
        run_case(valid, sizeof(valid), bpix, 63, -EINVAL);
        run_case(absolute, sizeof(absolute), bpix, 63, -EINVAL);
    }
    puts("PASS: actual BMP RLE8 decoder bounds both run types across 8/16/24/32 bpp; valid images preserved");
}
'''
helpers = bmp[bmp.index('static uint get_bmp_col_16bpp'):bmp.index('/**\n * video_splash_align_axis')]
assert 'ret = video_display_rle8_bitmap' in bmp and 'if (ret)' in bmp
compile_run(bmp_fixture + layout + video_format + bmp_device + helpers + bmp_cases, 'bmp')

fit = (repo / 'boot/image-fit.c').read_text()
fit_names = ['fit_image_get_data_' + name for name in
             ('offset', 'position', 'size', 'size_unciphered')]
fit_fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <libfdt.h>
typedef uint32_t u32;
#define FIT_DATA_OFFSET_PROP "data-offset"
#define FIT_DATA_POSITION_PROP "data-position"
#define FIT_DATA_SIZE_PROP "data-size"
'''
fit_cases = r'''
int main(void)
{
    static const struct {
        const char *property;
        int (*read_cell)(const void *, int, u32 *);
    } cases[] = {
        { "data-offset", fit_image_get_data_offset },
        { "data-position", fit_image_get_data_position },
        { "data-size", fit_image_get_data_size },
        { "data-size-unciphered", NULL },
    };
    uint64_t tree[128];
    fdt32_t data[] = { cpu_to_fdt32(0x100), cpu_to_fdt32(0x200) };
    int lengths[] = { -1, 0, 1, 3, 4, 5, 8 };
    int node;

    assert(fdt_create_empty_tree(tree, sizeof(tree)) == 0);
    node = fdt_add_subnode(tree, 0, "kernel");
    assert(node >= 0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        for (size_t j = 0; j < sizeof(lengths) / sizeof(*lengths); j++) {
            int len = lengths[j];
            u32 val = 0xdead;
            size_t unciphered = 0xdead;
            int ret;

            if (len >= 0)
                assert(fdt_setprop(tree, node, cases[i].property, data, len) == 0);
            if (cases[i].read_cell) {
                ret = cases[i].read_cell(tree, node, &val);
            } else {
                ret = fit_image_get_data_size_unciphered(tree, node, &unciphered);
                assert(unciphered == (len == 4 ? 0x100 : 0xdead));
                val = unciphered;
            }
            if (len == 4) {
                assert(ret == 0);
                assert(val == 0x100);
            } else {
                assert(ret == (len < 0 ? -ENOENT : -EINVAL));
                assert(val == 0xdead);
            }
        }
    }
    puts("PASS: all four FIT readers reject invalid property lengths and preserve valid cells");
    return 0;
}
'''
libfdt = repo / 'scripts/dtc/libfdt'
fit_sources = ['-I' + str(libfdt)] + [str(libfdt / (name + '.c')) for name in
    ('fdt', 'fdt_empty_tree', 'fdt_ro', 'fdt_rw', 'fdt_sw', 'fdt_wip')]
compile_run(fit_fixture + '\n'.join(function(fit, name) for name in fit_names) + fit_cases,
            'fit', fit_sources)


check = runpy.run_path(str(repo / 'scripts/check-mbedtls.py'))['check']
with tempfile.TemporaryDirectory() as directory:
    include = Path(directory) / 'include/mbedtls'
    include.mkdir(parents=True)
    for version, accepted in [((3, 4, 1), False), ((3, 6, 0), False),
                              ((3, 6, 6), False), ((3, 6, 7), True),
                              ((3, 6, 8), True), ((4, 2, 0), False)]:
        (include / 'build_info.h').write_text(''.join(
            '#define MBEDTLS_VERSION_' + part + ' ' + str(number) + '\n'
            for part, number in zip(('MAJOR', 'MINOR', 'PATCH'), version)))
        try:
            assert check(directory) == version
            assert accepted, version
        except ValueError:
            assert not accepted, version
    (include / 'build_info.h').write_text('')
    try:
        check(directory)
        raise AssertionError('unknown dependency version accepted')
    except ValueError:
        pass
print('PASS: dependency guard accepts patched 3.6.x and rejects old, unknown and unsupported major versions')

# Use the actual UBI validators and the vendor preloader's complete fastmap
# attach/load functions. Only flash I/O and unrelated attach helpers are mocked.
ubi_dir = repo / 'tf-a/drivers/io/ubi'
def header_text(path):
    return re.sub(r'^#include[^\n]*\n', '', path.read_text(), flags=re.M)

ubi_media = header_text(repo / 'drivers/mtd/ubi/ubi-media.h')
ubi_prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#define __packed __attribute__((packed))
#define ubi_err(...) ((void)0)
#define ubi_dump_vid_hdr(...) ((void)0)
#define ubi_dump_av(...) ((void)0)
#define ubi_dump_vol_info(...) ((void)0)
#define dump_stack() ((void)0)
#define be32_to_cpu be32toh
typedef uint8_t __u8;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;
'''
ubi_core_fixture = r'''
#define UBI_STATIC_VOLUME 4
struct ubi_device { int leb_size, peb_count; };
struct ubi_volume {
    struct ubi_device *ubi;
    int reserved_pebs, vol_type, data_pad, usable_leb_size;
};
struct ubi_ainf_volume {
    int highest_lnum, leb_count, vol_type, used_ebs, data_pad, last_data_size;
};
'''
ubi_core_cases = r'''
int main(void) {
    struct ubi_device ubi = { .leb_size = 128, .peb_count = 4 };
    struct ubi_vid_hdr hdr = { .vol_type = UBI_VID_STATIC,
        .used_ebs = htobe32(1), .data_size = htobe32(128) };
    struct ubi_volume vol = { .ubi = &ubi, .reserved_pebs = 1,
        .vol_type = UBI_STATIC_VOLUME, .data_pad = 16, .usable_leb_size = 112 };
    struct ubi_ainf_volume av = { .leb_count = 1, .used_ebs = 1,
        .vol_type = UBI_STATIC_VOLUME, .data_pad = 16, .last_data_size = 112 };
    assert(validate_vid_hdr(&ubi, &hdr) == 0);
    hdr.data_size = htobe32(129); assert(validate_vid_hdr(&ubi, &hdr) != 0);
    hdr.data_size = htobe32(UINT32_MAX); assert(validate_vid_hdr(&ubi, &hdr) != 0);
    hdr.vol_type = UBI_VID_DYNAMIC; hdr.copy_flag = 1; hdr.used_ebs = 0;
    hdr.data_size = htobe32(128); assert(validate_vid_hdr(&ubi, &hdr) == 0);
    hdr.data_size = htobe32(129); assert(validate_vid_hdr(&ubi, &hdr) != 0);
    assert(check_av(&vol, &av) == 0);
    av.last_data_size = 113; assert(check_av(&vol, &av) == -EINVAL);
    av.last_data_size = -1; assert(check_av(&vol, &av) == -EINVAL);
    for (unsigned i = 0; i < 4; i++) {
        int out = -1; assert(read_pnum(&ubi, htobe32(i), &out)); assert(out == i);
    }
    uint32_t invalid[] = { 4, INT32_MAX, UINT32_MAX };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        int out = -1; assert(!read_pnum(&ubi, htobe32(invalid[i]), &out));
        assert(out == -1);
    }
    puts("PASS: actual UBI VID, static-volume and fastmap PEB validators reject corrupt metadata; valid boundaries preserved");
}
'''
ubi_io = (repo / 'drivers/mtd/ubi/io.c').read_text()
ubi_vtbl = (repo / 'drivers/mtd/ubi/vtbl.c').read_text()
ubi_fm = (repo / 'drivers/mtd/ubi/fastmap.c').read_text()
compile_run(ubi_prefix + ubi_media + ubi_core_fixture +
            function(ubi_io, 'validate_vid_hdr') + function(ubi_vtbl, 'check_av') +
            function(ubi_fm, 'read_pnum') + ubi_core_cases, 'ubi_core')

ubi_vendor = (ubi_dir / 'ubispl.c').read_text()
ubi_vendor_prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#define __packed __attribute__((packed))
#define ARM_ARCH_MAJOR 7
#define WARN(...) ((void)0)
#define NOTICE(...) ((void)0)
#define VERBOSE(...) ((void)0)
#define ERROR(...) ((void)0)
'''
ubi_vendor_stubs = r'''
struct ubi_attach_info;
static unsigned assignments, flash_reads;
static int assign_aeb_to_av(struct ubi_scan_info *ubi, int pnum, int lnum,
                           uint32_t vol_id, uint32_t vol_type, uint32_t used) {
    assert(pnum >= 0 && pnum < ubi->peb_count); assignments++; return 0;
}
static int scan_pool(struct ubi_scan_info *ubi, uint32_t *pebs, int size) {
    assert(size == 0); return 0;
}
static int ubi_rescan_fm_vid_hdr(struct ubi_scan_info *ubi, struct ubi_vid_hdr *hdr,
                               uint32_t pnum, uint32_t vol_id, uint32_t lnum) {
    assert(!"fixture blocks must already be scanned"); return -EINVAL;
}
uint32_t ubi_crc32(uint32_t crc, const void *buf, size_t size) { return 0; }
static int flash_read(uint32_t pnum, unsigned long from, unsigned long len, void *buf) {
    assert(pnum < 4 && len <= 32); flash_reads++; memset(buf, 0xa5, len); return 0;
}
'''
ubi_vendor_cases = r'''
int main(void) {
    struct ubi_scan_info *ubi = calloc(1, sizeof(*ubi));
    assert(ubi);
    ubi->peb_count = 4; ubi->leb_size = 32; ubi->fm_size = sizeof(ubi->fm_buf);
    size_t pos = sizeof(struct ubi_fm_sb);
    struct ubi_fm_hdr *hdr = (void *)(ubi->fm_buf + pos); pos += sizeof(*hdr);
    hdr->magic = htobe32(UBI_FM_HDR_MAGIC); hdr->used_peb_count = htobe32(1);
    hdr->vol_count = htobe32(1);
    for (int i = 0; i < 2; i++) {
        struct ubi_fm_scan_pool *pool = (void *)(ubi->fm_buf + pos);
        pool->magic = htobe32(UBI_FM_POOL_MAGIC); pos += sizeof(*pool);
    }
    struct ubi_fm_ec *ec = (void *)(ubi->fm_buf + pos); pos += sizeof(*ec);
    struct ubi_fm_volhdr *vol = (void *)(ubi->fm_buf + pos); pos += sizeof(*vol);
    vol->magic = htobe32(UBI_FM_VHDR_MAGIC); vol->vol_type = UBI_STATIC_VOLUME;
    vol->used_ebs = htobe32(1);
    struct ubi_fm_eba *eba = (void *)(ubi->fm_buf + pos);
    eba->magic = htobe32(UBI_FM_EBA_MAGIC); eba->reserved_pebs = htobe32(1);
    assert(ubi_attach_fastmap(ubi, NULL, &ubi->fm_layout) == 0 && assignments == 1);
    uint32_t invalid[] = { 4, INT32_MAX, UINT32_MAX };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        ec->pnum = htobe32(invalid[i]); assignments = 0;
        assert(ubi_attach_fastmap(ubi, NULL, &ubi->fm_layout) == UBI_BAD_FASTMAP);
        assert(!assignments);
    }
    ec->pnum = 0;
    eba->pnum[0] = htobe32(4);
    assert(ubi_attach_fastmap(ubi, NULL, &ubi->fm_layout) == UBI_BAD_FASTMAP);
    eba->pnum[0] = htobe32(UINT32_MAX); assignments = 0;
    assert(ubi_attach_fastmap(ubi, NULL, &ubi->fm_layout) == 0 && !assignments);
    eba->pnum[0] = 0;
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        eba->reserved_pebs = htobe32(invalid[i] + (invalid[i] == 4));
        assert(ubi_attach_fastmap(ubi, NULL, &ubi->fm_layout) == UBI_BAD_FASTMAP);
    }
    eba->reserved_pebs = htobe32(1);
    ubi->fm_size = pos + sizeof(*eba);
    assert(ubi_attach_fastmap(ubi, NULL, &ubi->fm_layout) == UBI_BAD_FASTMAP);

    memset(ubi, 0, sizeof(*ubi)); ubi->peb_count = 4; ubi->leb_size = 32;
    ubi->read = flash_read;
    for (int i = 1; i < 4; i++) ubi->blockinfo[i].vol_id = htobe32(1);
    struct ubi_vol_info *vi = &ubi->volinfo[0];
    struct ubi_vid_hdr *vh = &ubi->blockinfo[0];
    vh->used_ebs = htobe32(1); vh->data_size = htobe32(9);
    generic_set_bit(0, vi->found); generic_set_bit(0, ubi->scanned);
    unsigned char output[8]; uint32_t got;
    assert(ubi_load_block(ubi, output, vi, 0, 0, 1, 1, 4, &got) == 9);
    assert(got == 4 && flash_reads == 1);
    for (unsigned i = 0; i < got; i++) assert(output[i] == 0xa5);
    assert(ubi_load_block(ubi, output, vi, 0, 0, 1, 0, 4, &got) == 9);
    assert(flash_reads == 1); /* valid cached reads still work */
    uint32_t bad_sizes[] = { 33, UINT32_MAX };
    for (unsigned i = 0; i < sizeof(bad_sizes) / sizeof(*bad_sizes); i++) {
        vh->data_size = htobe32(bad_sizes[i]); flash_reads = 0;
        generic_set_bit(0, vi->found); generic_clear_bit(0, ubi->corrupt);
        assert(ubi_load_block(ubi, output, vi, 0, 0, 1, 0, 4, &got) == -EINVAL);
        assert(!flash_reads && test_bit(0, ubi->corrupt));
    }
    /* A corrupt copy must not prevent loading a valid replacement. */
    ubi->blockinfo[1] = *vh; ubi->blockinfo[1].data_size = htobe32(9);
    generic_set_bit(1, ubi->scanned); generic_set_bit(0, vi->found);
    generic_clear_bit(0, ubi->corrupt); ubi->leb_cache_info.valid = 0;
    assert(ubi_load_block(ubi, output, vi, 0, 0, 1, 0, 4, &got) == 9);
    assert(flash_reads == 1 && vi->lebs_to_pebs[0] == 1);
    free(ubi);
    puts("PASS: actual TF-A UBI attach/load reject PEB, EBA and LEB overflows; valid loads, cache and replacement fallback preserved");
}
'''
ubi_vendor_headers = ''.join(header_text(path) for path in
    (repo / 'tf-a/include/drivers/io/io_ubi.h', ubi_dir / 'ubi-media.h',
     ubi_dir / 'ubi-wrapper.h', ubi_dir / 'compat.h', ubi_dir / 'ubispl.h'))
compile_run(ubi_vendor_prefix + ubi_vendor_headers + ubi_vendor_stubs +
            '\n'.join(function(ubi_vendor, name) for name in
                      ('ubi_io_read', 'ubi_io_is_bad', 'ubi_attach_fastmap', 'ubi_load_block')) +
            ubi_vendor_cases, 'ubi_vendor')


# Exercise the complete host importer with real files, mmap and libfdt.
fit_tool = (repo / 'tools/fit_image.c').read_text()
fit_import_fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <libfdt.h>
typedef uint32_t u32;
#define FIT_DATA_OFFSET_PROP "data-offset"
#define FIT_DATA_POSITION_PROP "data-position"
#define FIT_DATA_SIZE_PROP "data-size"
#define FIT_DATA_PROP "data"
#define FIT_IMAGES_PATH "/images"
#define FIT_CONFS_PATH "/configurations"
#define FIT_DEFAULT_PROP "default"
#define FIT_KERNEL_PROP "kernel"
#define FIT_RAMDISK_PROP "ramdisk"
#define FIT_FDT_PROP "fdt"
#define FIT_LOADABLE_PROP "loadables"
#define FIT_FPGA_PROP "fpga"
#define FIT_FIRMWARE_PROP "firmware"
#define FIT_SCRIPT_PROP "script"
#define O_BINARY 0
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define debug(...) ((void)0)
struct image_tool_params { const char *cmdname; };
static int mmap_fdt(const char *cmd, const char *name, int size, void **mapped,
                    struct stat *st, bool first, bool second) {
    int fd = open(name, O_RDONLY); assert(fd >= 0);
    assert(fstat(fd, st) == 0);
    *mapped = mmap(NULL, st->st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(*mapped != MAP_FAILED && fdt_check_header(*mapped) == 0);
    return fd;
}
'''
fit_import_cases = r'''
static void import_case(bool absolute, uint32_t location, uint32_t length,
                        int cell_length, int expected, bool imported) {
    uint64_t tree[256]; char path[] = "/tmp/an758x-fit-XXXXXX";
    struct image_tool_params params = { .cmdname = "fit-regression" };
    fdt32_t cells[2] = { cpu_to_fdt32(location), 0 };
    assert(fdt_create_empty_tree(tree, sizeof(tree)) == 0);
    assert(fdt_add_subnode(tree, 0, "configurations") >= 0);
    int images = fdt_add_subnode(tree, 0, "images"); assert(images >= 0);
    int node = fdt_add_subnode(tree, images, "kernel"); assert(node >= 0);
    const char *prop = absolute ? FIT_DATA_POSITION_PROP : FIT_DATA_OFFSET_PROP;
    assert(fdt_setprop(tree, node, prop, cells, cell_length) == 0);
    assert(fdt_setprop_u32(tree, node, FIT_DATA_SIZE_PROP, length) == 0);
    assert(fdt_pack(tree) == 0);
    int tree_size = fdt_totalsize(tree);
    if (absolute && location == 0 && cell_length == 4)
        assert(fdt_setprop_inplace_u32(tree, node, prop, tree_size) == 0);
    int fd = mkstemp(path); assert(fd >= 0);
    assert(write(fd, tree, tree_size) == tree_size);
    assert(write(fd, "payload!", 8) == 8); close(fd);
    assert(fit_import_data(&params, path) == expected);
    uint64_t result_words[512]; unsigned char *result = (void *)result_words;
    fd = open(path, O_RDONLY); assert(fd >= 0);
    ssize_t got = read(fd, result, sizeof(result_words)); assert(got > 0); close(fd);
    if (expected) {
        assert(got == tree_size + 8 && memcmp(result, tree, tree_size) == 0);
        assert(memcmp(result + tree_size, "payload!", 8) == 0);
    } else {
        node = fdt_path_offset(result, "/images/kernel"); assert(node >= 0);
        int size; const void *data = fdt_getprop(result, node, FIT_DATA_PROP, &size);
        if (imported) {
            assert(data && size == length);
            if (length) assert(memcmp(data, "payload!", length) == 0);
            assert(!fdt_getprop(result, node, FIT_DATA_SIZE_PROP, NULL));
        } else {
            assert(!data && fdt_getprop(result, node, prop, NULL));
        }
    }
    assert(unlink(path) == 0);
}
int main(void) {
    import_case(false, 0, 8, 4, 0, true);
    import_case(true, 0, 8, 4, 0, true);
    import_case(false, 0, 9, 4, -EINVAL, false);
    import_case(true, UINT32_MAX, 8, 4, -EINVAL, false);
    import_case(false, UINT32_MAX, 8, 4, -EINVAL, false);
    import_case(false, 0, UINT32_MAX, 4, -EINVAL, false);
    for (int size = 0; size <= 8; size++) {
        if (size != 4) import_case(false, 0, 8, size, 0, false);
    }
    /* mkimage -E -p compatibility: an empty payload may be beyond EOF. */
    import_case(true, UINT32_MAX, 0, 4, 0, true);
    puts("PASS: actual FIT importer rejects out-of-file data without modifying input; valid relative, absolute and empty payloads preserved");
}
'''
compile_run(fit_import_fixture + '\n'.join(function(fit, name) for name in fit_names[:3]) +
            function(fit_tool, 'fit_import_data') + fit_import_cases,
            'fit_import', fit_sources)

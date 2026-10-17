#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
"""Exercise the actual FIP and BMP parsers with hostile metadata under ASan/UBSan."""
from pathlib import Path
import os
import re
import runpy
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r'^static[^;{}]*\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def compile_run(code, name):
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / (name + '.c')
        binary = Path(directory) / name
        source.write_text(code)
        command = shlex.split(os.environ.get('HOSTCC', 'cc'))
        command += ['-std=gnu11', '-O1', '-g', '-fno-omit-frame-pointer',
                    '-fsanitize=address,undefined', '-I' + str(repo / 'tf-a/include'),
                    str(source), '-o', str(binary)]
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

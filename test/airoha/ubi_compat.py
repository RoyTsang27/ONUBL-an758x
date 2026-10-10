#!/usr/bin/env python3
"""Compile actual recovery UBI helpers against a memory-backed test device."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile


repo = Path(__file__).resolve().parents[2]
source = (repo / 'cmd/ubi.c').read_text()


def function(name):
    match = re.search(r'^.*\b' + name + r'\([^;]*?\)\n\{', source, re.M)
    assert match, name
    end = match.end()
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define loff_t int64_t
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define do_div(n, b) ({ unsigned int r = (n) % (b); (n) /= (b); r; })
#define UBI_VOL_NUM_AUTO (-1)
struct ubi_volume {
    const char *name;
    int usable_leb_size, reserved_pebs, data_pad, vol_id;
    bool updating, upd_marker, corrupted;
    int64_t used_bytes;
};
struct ubi_device {
    int min_io_size, avail_pebs, leb_size, vtbl_slots;
    struct ubi_volume *volumes[2];
};
static struct ubi_device *ubi;
static unsigned char data[64];
static int reads, blinks, offs, env_writes, read_error, core_error;
static size_t reported_size;
static int64_t created_size;
static bool allocation_error;
static void *malloc_cache_aligned(size_t size) {
    return allocation_error ? NULL : malloc(size);
}
static void led_activity_blink(void) { blinks++; }
static void led_activity_off(void) { offs++; }
static void env_set_hex(const char *name, size_t size) {
    assert(!strcmp(name, "filesize")); env_writes++; reported_size = size;
}
static int ubi_eba_read_leb(struct ubi_device *u, struct ubi_volume *v,
                          int lnum, void *buf, int off, int len, int check) {
    assert(u == ubi && off >= 0 && len > 0 && off + len <= v->usable_leb_size);
    reads++;
    if (read_error) return read_error;
    memcpy(buf, data + lnum * v->usable_leb_size + off, len);
    return 0;
}
static int ubi_check(const char *name) { return strcmp(name, "data"); }
static int ubi_create_vol(const char *name, int64_t size, bool dynamic,
                          int id, bool skipcheck) {
    assert(!strcmp(name, "new") && dynamic && id == -1 && !skipcheck);
    created_size = size; return core_error;
}
static int ubi_remove_vol(const char *name) { return core_error; }
static int ubi_rename_vol(const char *oldname, const char *newname) {
    return core_error;
}
'''

tests = r'''
static void reset(void) {
    reads = blinks = offs = env_writes = read_error = core_error = 0;
    allocation_error = false; reported_size = 999;
}
int main(void) {
    struct ubi_volume volume = { .name = "data", .usable_leb_size = 16,
        .used_bytes = 53, .reserved_pebs = 4, .vol_id = 0 };
    struct ubi_device device = { .min_io_size = 4, .avail_pebs = 2,
        .leb_size = 16, .vtbl_slots = 2, .volumes = { &volume, NULL } };
    unsigned char buf[64];
    size_t used, reserved;
    for (int i = 0; i < 64; i++) data[i] = i;
    ubi = NULL;
    assert(!ubi_volume_exists("data"));
    assert(ubi_volume_create("new", 0, true) == ENODEV);
    assert(ubi_volume_remove("data") == ENODEV);
    assert(ubi_volume_rename("data", "new") == ENODEV);
    assert(ubi_volume_get_size("data", &used, &reserved) == ENODEV);
    assert(ubi_volume_read_quiet("data", buf, 0, 1) == ENODEV);
    ubi = &device;
    assert(ubi_volume_exists("data") && !ubi_volume_exists("missing"));
    assert(ubi_volume_get_size("data", &used, &reserved) == 0);
    assert(used == 53 && reserved == 64);
    assert(ubi_volume_get_size("data", NULL, NULL) == 0);
    assert(ubi_volume_get_size("missing", NULL, NULL) == ENODEV);
    assert(ubi_volume_create("new", 0, true) == 0 && created_size == 32);
    assert(ubi_volume_create("new", 17, true) == 0 && created_size == 17);
    core_error = -EROFS;
    assert(ubi_volume_remove("data") == EROFS);
    assert(ubi_volume_rename("data", "new") == EROFS);
    core_error = 0;
    assert(ubi_volume_remove("data") == 0);
    assert(ubi_volume_rename("data", "new") == 0);
    assert(ubi_volume_read_quiet("missing", buf, 0, 1) == ENODEV);
    for (int offset = 0; offset <= 53; offset++) {
        reset(); memset(buf, 0xff, sizeof(buf));
        assert(ubi_volume_read_quiet("data", buf, offset, 0) == 0);
        assert(!memcmp(buf, data + offset, 53 - offset));
        assert(!env_writes && !blinks && !offs && reported_size == 999);
        assert(buf[53 - offset] == 0xff);
    }
    reset();
    assert(ubi_volume_read("data", buf, 15, 20) == 0);
    assert(!memcmp(buf, data + 15, 20));
    assert(blinks == 1 && offs == 1 && env_writes == 1 && reported_size == 20);
    reset();
    assert(ubi_volume_read_quiet("data", buf, -1, 1) == EINVAL);
    assert(ubi_volume_read_quiet("data", buf, 54, 0) == EINVAL);
    assert(ubi_volume_read_quiet("data", buf, 53, 1) == EINVAL);
    assert(ubi_volume_read_quiet("data", buf, 52, 2) == EINVAL);
    assert(ubi_volume_read_quiet("data", buf, 1, SIZE_MAX) == EINVAL);
    assert(ubi_volume_read("data", buf, 54, 0) == -EINVAL);
    assert(!reads && !env_writes && !blinks);
    volume.updating = true;
    assert(ubi_volume_read_quiet("data", buf, 0, 1) == EBUSY);
    volume.updating = false; volume.upd_marker = true;
    assert(ubi_volume_read_quiet("data", buf, 0, 1) == EBADF);
    volume.upd_marker = false; allocation_error = true;
    assert(ubi_volume_read_quiet("data", buf, 0, 1) == ENOMEM);
    allocation_error = false; read_error = -EIO;
    assert(ubi_volume_read_quiet("data", buf, 0, 1) == EIO);
    assert(ubi_volume_read("data", buf, 0, 1) == -EIO);
    assert(!env_writes);
    volume.used_bytes = 0; reset();
    assert(ubi_volume_read_quiet("data", buf, 0, 0) == 0 && !reads);
    puts("PASS: actual UBI recovery helpers, all offsets, bounds, errors and quiet metadata");
}
'''

names = ['ubi_find_volume', 'ubi_volume_exists', 'ubi_volume_create',
         'ubi_volume_get_size', 'ubi_require_volume', 'ubi_volume_remove',
         'ubi_volume_rename', '__ubi_volume_read', 'ubi_volume_read',
         'ubi_volume_read_quiet']
with tempfile.TemporaryDirectory(prefix='ubi-compat-') as temporary:
    path = Path(temporary)
    unit = path / 'test.c'
    unit.write_text(fixture + '\n\n'.join(function(n) for n in names) + tests)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc')) +
                   ['-std=gnu11', '-Wall', '-Werror', str(unit), '-o',
                    str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)

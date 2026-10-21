#!/usr/bin/env python3
"""Compile actual recovery HTTP/command functions; hardware calls are stubbed."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    """Find a definition and balance braces while ignoring C comments/strings."""
    match = re.search(r'(?m)^(?:static\s+)?[\w *]+\b' + re.escape(name) +
                      r'\([^;{}]*\)\s*\{', source)
    if not match:
        raise AssertionError('definition missing: ' + name)
    start = source.index('{', match.start())
    depth, i, state = 0, start, 'code'
    while i < len(source):
        c, pair = source[i], source[i:i + 2]
        if state == 'line':
            if c == '\n':
                state = 'code'
        elif state == 'comment':
            if pair == '*/':
                state = 'code'
                i += 1
        elif state in ('"', "'"):
            if c == '\\':
                i += 1
            elif c == state:
                state = 'code'
        elif pair in ('/*', '//'):
            state = 'comment' if pair == '/*' else 'line'
            i += 1
        elif c in ('"', "'"):
            state = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if not depth:
                return source[match.start():i + 1]
        i += 1
    raise AssertionError('unbalanced definition: ' + name)


PREAMBLE = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
typedef unsigned long ulong;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16_t;
typedef uint8_t u8_t;
typedef unsigned long phys_addr_t;
typedef int err_t;
typedef int ofnode;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define min_t(t,a,b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define CONFIG_IS_ENABLED(x) 1
#define CONFIG_SYS_LOAD_ADDR 0
#define CONFIG_HTTPD_SERVER_IP "192.168.0.1"
#define CONFIG_HTTPD_SERVER_NETMASK "255.255.255.0"
#define ERR_OK 0
#define ERR_ARG -1
#define LMB_NONE 0
#define LMB_MEM_ALLOC_MAX 0
#define FS_FILE_FLAGS_HEADER_INCLUDED 1
#define IS_ERR(p) ((intptr_t)(p) < 0)
#define CMD_RET_SUCCESS 0
#define CMD_RET_FAILURE 1
#define CMD_RET_USAGE 2
struct cmd_tbl { int unused; };
struct mtd_info { u64 size; };
struct blk_desc { u64 lba; u32 blksz; };
struct udevice { int unused; };
struct netif { int unused; };
struct fs_file { const char *data; int len, index, flags; void *pextension; };
struct pbuf { size_t tot_len; const void *data; };
static unsigned char ram[8192];
static struct { phys_addr_t ram_base, ram_size, start_addr_sp; } global_data;
#define gd (&global_data)
static struct mtd_info whole_mtd = { sizeof(ram) };
static struct udevice eth_dev;
static struct netif test_netif;
static const char version_string[] = "test";
static const char httpd_page[] = "page";
static const size_t httpd_page_size = sizeof(httpd_page);
static int env_writes, allocations, releases, download_calls, starts, start_error;
static int current_tick, dhcp_starts, network_fail;
#define mtd_for_each_device(mtd) for ((mtd) = &whole_mtd; (mtd); (mtd) = NULL)
static u64 simple_strtoull(const char *s,char **e,unsigned int b) { return strtoull(s,e,b); }
static int hex_to_bin(char ch) { if (ch >= '0' && ch <= '9') return ch-'0'; ch=tolower((unsigned char)ch); return ch >= 'a' && ch <= 'f' ? ch-'a'+10 : -1; }
static void mtd_probe_devices(void) {}
static bool mtd_is_partition(const struct mtd_info *mtd) { return false; }
static int blk_get_device_by_str(const char *a,const char *b,struct blk_desc **d) { return -1; }
static ofnode ofnode_root(void) { return 0; }
static const char *ofnode_read_string(ofnode n,const char *s) { return "test board"; }
static const char *env_get(const char *s) { return NULL; }
static ulong env_get_ulong(const char *s,int b,ulong def) { return (ulong)ram; }
static int env_set_hex(const char *s,ulong v) { env_writes++; return 0; }
static int env_set(const char *s,const char *v) { env_writes++; return 0; }
static int lmb_free(phys_addr_t a,size_t s,int f) { releases++; return 0; }
static int lmb_alloc_mem(int k,int align,phys_addr_t *a,size_t s,int f) { allocations++; *a=(phys_addr_t)ram; return 0; }
static void put_mtd_device(struct mtd_info *mtd) {}
static struct mtd_info *whole_flash_mtd(void) { return &whole_mtd; }
static void pbuf_free(struct pbuf *p) {}
static void *map_sysmem(ulong a,size_t s) { return (void *)a; }
static void unmap_sysmem(void *p) {}
static void pbuf_copy_partial(struct pbuf *p,void *d,size_t s,size_t o) { memcpy(d,(const char *)p->data+o,s); }
static ulong get_timer(ulong t) { return ++current_tick; }
static int webconsole_register(void) { return start_error; }
static int net_lwip_eth_start(void) { starts++; return network_fail; }
static void net_lwip_eth_stop(void) {}
static struct udevice *eth_get_dev(void) { return &eth_dev; }
static struct netif *net_lwip_new_netif(struct udevice *d) { return &test_netif; }
static void net_lwip_remove_netif(struct netif *n) {}
static int net_lwip_rx(struct udevice *d,struct netif *n) { return 0; }
static void led_activity_blink(void) {}
static void led_activity_on(void) {}
static void httpd_init(void) {}
static void httpd_stop(void) {}
static int uboot_httpd_dhcp_start(struct netif *n) { dhcp_starts++; return 0; }
static void uboot_httpd_dhcp_stop(void) {}
static void clear_ctrlc(void) {}
static int ctrlc(void) { return 1; }
static void process_job(void) {}
static void build_storage_catalog(void) {}
static bool recovery_layout_present(void) { return true; }
static int open_download(struct fs_file *f,const char *n) { download_calls++; return 1; }
static int parse_task(void);
'''

BOARD_STUBS = r'''
static int board_data_config(unsigned int i,struct http_storage_request *r) { return -ENOENT; }
static int board_data_find(const char *s,struct http_storage_request *r) {
    memset(r,0,sizeof(*r)); r->kind=HTTP_STORAGE_UBI; r->size=16;
    strcpy(r->target,s); return 0;
}
'''


def main():
    source = (ROOT / 'net/lwip/httpd.c').read_text()
    command = (ROOT / 'cmd/lwip/httpd.c').read_text()
    header = (ROOT / 'include/net/httpd-json.h').read_text()
    header = re.sub(r'^#include.*$', '', header, flags=re.M)
    header = header.replace('#define JSMN_STRICT', '#define JSMN_STRICT\n' +
                            (ROOT / 'include/net/httpd-jsmn.h').read_text())
    globals_ = source[source.index('#define HTTPD_COMMAND_LEN'):
                      source.index('static bool http_busy(void)')]
    selected = ['http_busy', 'http_operation_requires_privilege', 'fs_set_data',
                'job_state_name', 'build_result', 'build_info', 'fs_json',
                'fs_open_custom', 'release_flash_all_upload', 'upload_region_valid',
                'httpd_post_begin', 'httpd_post_receive_data', 'httpd_post_finished',
                'storage_name_valid', 'parse_task', 'uboot_httpd_is_running',
                'uboot_httpd_start_mode', 'uboot_httpd_start']
    harness = '\n'.join([PREAMBLE, header, globals_, BOARD_STUBS] +
                        [function(source, name) for name in selected] +
                        [function(command, 'do_httpd'),
                         (ROOT / 'test/airoha/recovery_security.c').read_text()])
    with tempfile.TemporaryDirectory(prefix='recovery-security-') as temporary:
        path = Path(temporary)
        (path / 'httpd.c').write_text(harness)
        subprocess.run([os.environ.get('HOSTCC', 'cc'), '-std=gnu11', '-O1', '-g',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(path / 'httpd.c'), '-o', str(path / 'httpd')], check=True)
        subprocess.run([str(path / 'httpd')], check=True)


if __name__ == '__main__':
    main()

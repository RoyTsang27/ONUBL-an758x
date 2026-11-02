/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <ecnt_plat_common.h>
#include <tools_share/firmware_encrypted.h>

int decrypt_dm_key(uint8_t *, unsigned int);
int decrypt_gcm_data(uint8_t *, unsigned int);
int aes_gcm_decrypt(void *, size_t, const void *, unsigned int,
                    const void *, unsigned int, const void *, unsigned int);
static unsigned int checks;
#define CHECK(x) do { checks++; assert(x); } while (0)
static unsigned char device_key[32];
static int key_error, key_calls;
static size_t supplied_key_length = 32;
int plat_get_enc_key_info(enum fw_enc_status_t status, uint8_t *key,
                         size_t *length, unsigned int *flags,
                         const uint8_t *uuid, size_t uuid_len)
{
    (void)status; (void)flags; (void)uuid; (void)uuid_len;
    key_calls++;
    CHECK(*length >= sizeof(device_key));
    memcpy(key, device_key, sizeof(device_key));
    *length = supplied_key_length;
    return key_error;
}

static unsigned int dram_mb = 512;
unsigned int GET_DRAM_SIZE(void) { return dram_mb; }
static unsigned int active_maps, map_calls, fail_map_call;
static uintptr_t last_base;
static size_t last_size;
int mmap_add_dynamic_region(unsigned long long pa, uintptr_t va,
                            size_t size, unsigned int attr)
{
    (void)attr;
    CHECK(pa == va && (pa % PAGE_SIZE) == 0 && (size % PAGE_SIZE) == 0);
    map_calls++;
    if (map_calls == fail_map_call) return -1;
    active_maps++;
    last_base = va; last_size = size;
    return 0;
}
int mmap_remove_dynamic_region(uintptr_t base, size_t size)
{
    (void)base; (void)size;
    CHECK(active_maps != 0);
    active_maps--;
    return 0;
}

typedef struct { uintptr_t image_base; uint32_t image_size, image_max_size; } image_info_t;
typedef struct { uint32_t image_id; image_info_t image_info; } bl_mem_params_node_t;
static bl_mem_params_node_t params = { 3, { 0x80035000U, 0, 0xb000U } };
static uintptr_t image_hash_base;
static size_t fip_offset, fip_length;
static unsigned int loader_calls;
static uint32_t loader_limit;
static int loader_error;
bl_mem_params_node_t *get_bl_mem_params_node(uint32_t id)
{ return id == 3 ? &params : NULL; }
void set_fip_block_spec(size_t offset, size_t length)
{ fip_offset = offset; fip_length = length; }
int load_auth_image(uint32_t id, image_info_t *info)
{
    (void)id;
    CHECK(fip_offset != 0 && fip_length != 0);
    loader_calls++; loader_limit = info->image_max_size;
    info->image_size = 17;
    return loader_error;
}
/* The runner appends the actual vendor handler definitions here. */
#include "vendor_handlers.inc"

static void derive(const char *user, const char *password, unsigned int hash,
                   unsigned int iterations, unsigned int length, unsigned char *out)
{
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    CHECK(mbedtls_md_setup(&md, mbedtls_md_info_from_type(
        hash == 512 ? MBEDTLS_MD_SHA512 : MBEDTLS_MD_SHA256), 1) == 0);
    CHECK(mbedtls_pkcs5_pbkdf2_hmac(&md, (const unsigned char *)password,
        strlen(password), (const unsigned char *)user, strlen(user),
        iterations, length, out) == 0);
    mbedtls_md_free(&md);
}
static void dm_tests(void)
{
    struct { unsigned char before[16], data[256], after[16]; } block;
    unsigned char plain[256], cipher[256];
    const unsigned int bad[] = {0,1,15,17,255,257,UINT_MAX};
    mbedtls_aes_context aes;
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = (unsigned char)i;
    mbedtls_aes_init(&aes);
    CHECK(mbedtls_aes_setkey_enc(&aes, device_key, 256) == 0);
    for (size_t i = 0; i < sizeof(plain); i += 16)
        CHECK(mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plain+i, cipher+i) == 0);
    for (size_t n = 16; n <= 256; n += 16) {
        memset(&block, 0xa5, sizeof(block)); memcpy(block.data, cipher, n);
        CHECK(decrypt_dm_key(block.data, n) == 0);
        CHECK(memcmp(block.data, plain, n) == 0);
        for (size_t i = n; i < sizeof(block.data); i++) CHECK(block.data[i] == 0xa5);
        for (size_t i = 0; i < 16; i++)
            CHECK(block.before[i] == 0xa5 && block.after[i] == 0xa5);
    }
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        memset(&block, 0xa5, sizeof(block)); int calls = key_calls;
        CHECK(decrypt_dm_key(block.data, bad[i]) != 0);
        CHECK(key_calls == calls && block.data[0] == 0xa5);
    }
    CHECK(decrypt_dm_key(NULL, 16) != 0);
    key_error = -1; CHECK(decrypt_dm_key(block.data, 16) != 0);
    key_error = 0; supplied_key_length = 33;
    CHECK(decrypt_dm_key(block.data, 16) != 0);
    supplied_key_length = 32;
    mbedtls_aes_free(&aes);
}
static void encrypt_image(unsigned char *buffer, const unsigned char *plain, size_t len)
{
    struct fw_enc_hdr h = { .magic=ENC_HEADER_MAGIC, .iv_len=12, .tag_len=16 };
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    CHECK(mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, device_key, 256) == 0);
    CHECK(mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, h.iv, h.iv_len,
        NULL, 0, plain, buffer+sizeof(h), sizeof(h.tag), h.tag) == 0);
    memcpy(buffer, &h, sizeof(h));
    mbedtls_gcm_free(&gcm);
}
static void gcm_tests(void)
{
    const size_t lengths[] = {0,1,15,16,17,255,256,257,511,512,513};
    unsigned char plain[513], data[sizeof(struct fw_enc_hdr)+513+16];
    struct fw_enc_hdr header;
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = (unsigned char)(i*3U);
    for (size_t j = 0; j < sizeof(lengths)/sizeof(lengths[0]); j++) {
        size_t n = lengths[j];
        memset(data, 0xa5, sizeof(data)); encrypt_image(data, plain, n);
        CHECK(decrypt_gcm_data(data, sizeof(header)+n) == 0);
        CHECK(memcmp(data, plain, n) == 0);
        for (size_t i = sizeof(header)+n; i < sizeof(data); i++) CHECK(data[i] == 0xa5);
        encrypt_image(data, plain, n); data[offsetof(struct fw_enc_hdr,tag)] ^= 1;
        CHECK(decrypt_gcm_data(data, sizeof(header)+n) != 0);
        for (size_t i = 0; i < n; i++) CHECK(data[sizeof(header)+i] == 0);
    }
    for (size_t n = 0; n < sizeof(header); n++) {
        unsigned char *short_input = malloc(n ? n : 1);
        memset(short_input, 0, n ? n : 1);
        CHECK(decrypt_gcm_data(short_input, n) != 0); free(short_input);
    }
    const unsigned int tags[] = {0,1,4,15,17,65535};
    for (size_t j = 0; j < sizeof(tags)/sizeof(tags[0]); j++) {
        encrypt_image(data, plain, 17); memcpy(&header, data, sizeof(header));
        header.tag_len = tags[j]; memcpy(data, &header, sizeof(header));
        int calls = key_calls;
        CHECK(decrypt_gcm_data(data, sizeof(header)+17) != 0);
        CHECK(key_calls == calls);
    }
    for (unsigned int j = 0; j < 4; j++) {
        encrypt_image(data, plain, 17); memcpy(&header, data, sizeof(header));
        if (j == 0) header.iv_len=0;
        if (j == 1) header.iv_len=17;
        if (j == 2) header.dec_algo=1;
        if (j == 3) header.flags=2;
        memcpy(data, &header, sizeof(header));
        CHECK(decrypt_gcm_data(data, sizeof(header)+17) != 0);
    }
    encrypt_image(data, plain, 17); key_error=-1;
    CHECK(decrypt_gcm_data(data, sizeof(header)+17) != 0); key_error=0;
    CHECK(aes_gcm_decrypt(data, 17, device_key, 32, data, 12, data, 0) != 0);
}
static void password_tests(void)
{
    unsigned char expected[128];
    for (unsigned int hash=256; hash<=512; hash+=256) {
        const unsigned int sizes[]={1,32,64,128};
        for (size_t i=0; i<sizeof(sizes)/sizeof(sizes[0]); i++) {
            derive("user", "password", hash, 2, sizes[i], expected);
            CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("user",4,"password",8,
                expected,2,sizes[i],hash)==0);
            expected[0]^=1;
            CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("user",4,"password",8,
                expected,2,sizes[i],hash)!=0);
        }
    }
    CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("u",1,"p",1,expected,2,129,256)!=0);
    CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("u",1,"p",1,expected,2,UINT_MAX,256)!=0);
    CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("u",1,"p",1,expected,2,0,256)!=0);
    CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("u",1,"p",1,expected,0,32,256)!=0);
    CHECK(ecnt_mbedtls_pkcs5_pbkdf2_compare("u",1,"p",1,expected,2,32,123)!=0);
    uintptr_t base; size_t size;
    CHECK(ecnt_ns_window(0x81000ff9U,640,&base,&size));
    CHECK(base==0x81000000U && size==8192);
    CHECK(!ecnt_ns_window(0x80003000U,16,&base,&size));
    CHECK(!ecnt_ns_window(0x1fbf8000U,16,&base,&size));
    CHECK(!ecnt_ns_window(0x81000000U,0,&base,&size));
    CHECK(!ecnt_ns_window(UINT64_MAX,16,&base,&size));
    CHECK(!ecnt_ns_window(0xfffffff0U,UINT_MAX,&base,&size));
    CHECK(!ecnt_ns_window(0x9ffffff0U,17,&base,&size));
    CHECK(ecnt_ns_window(0x9ffffff0U,16,&base,&size));
    dram_mb=2048;
    CHECK(ecnt_ns_window(0xfffffff0U,16,&base,&size));
    CHECK(!ecnt_ns_window(0xfffffff0U,17,&base,&size));
    dram_mb=0; CHECK(!ecnt_ns_window(0x81000000U,16,&base,&size)); dram_mb=512;
#ifdef TCSUPPORT_OPTEE
    CHECK(!ecnt_ns_window(BL32_BASE,16,&base,&size));
    CHECK(!ecnt_ns_window(BL32_BASE-16,32,&base,&size));
#endif
#ifndef ECNT_CRYPTO_ONLY
    unsigned char *shared=mmap((void *)0x81000000U,12288,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    CHECK(shared!=(void *)MAP_FAILED);
    unsigned char *unaligned=shared+4096-7;
    memset(shared,0,12288); strcpy((char *)unaligned,"user");
    strcpy((char *)unaligned+256,"password");
    derive("user","password",256,2,128,unaligned+512);
    CHECK(ecnt_pbkdf2_setting(2,(256U<<16)|128)==0);
    CHECK(ecnt_password_verify((uint32_t)(uintptr_t)unaligned,256)==0);
    CHECK(last_base==0x81000000U && last_size==8192 && active_maps==0);
    memset(unaligned,'x',256);
    CHECK(ecnt_password_verify((uint32_t)(uintptr_t)unaligned,256)!=0);
    strcpy((char *)unaligned,"user"); memset(unaligned+256,'x',256);
    CHECK(ecnt_password_verify((uint32_t)(uintptr_t)unaligned,256)!=0);
    CHECK(ecnt_password_verify(0x81000000U,UINT_MAX)!=0);
    CHECK(ecnt_pbkdf2_setting(2,(256U<<16)|65535)!=0);
    CHECK(ecnt_pbkdf2_setting(0,(256U<<16)|32)!=0);
    CHECK(ecnt_pbkdf2_setting(2,(123U<<16)|32)!=0);
    fail_map_call=map_calls+1;
    CHECK(ecnt_password_verify(0x81000000U,256)!=0); fail_map_call=0;
    CHECK(ecnt_decrypt_dm_key_handler(0x80003000U,16,0)!=0);
    CHECK(ecnt_decrypt_dm_key_handler(0x81000000U,257,0)!=0);
    CHECK(active_maps==0);
    CHECK(ecnt_decrypt_dm_key_handler(0x81000000U,16,0)==0);
    CHECK(active_maps==0);
    CHECK(munmap(shared,12288)==0);
#endif
}
static void loader_tests(void)
{
    image_info_t saved=params.image_info;
    CHECK(ecnt_decrypt_handler(3,4096,0x82000000U,0x83000000U)==0);
    CHECK(loader_limit==4096 && active_maps==0);
    CHECK(memcmp(&saved,&params.image_info,sizeof(saved))==0);
    CHECK(fip_offset==0 && fip_length==0);
    loader_error=-1;
    CHECK(ecnt_decrypt_handler(3,4096,0x82000000U,0x83000000U)!=0);
    CHECK(active_maps==0 && memcmp(&saved,&params.image_info,sizeof(saved))==0);
    loader_error=0;
    unsigned int calls=loader_calls;
    CHECK(ecnt_decrypt_handler(3,UINT_MAX,0x82000000U,0x83000000U)!=0);
    CHECK(ecnt_decrypt_handler(3,4096,0x82000000U,0x80003000U)!=0);
    CHECK(ecnt_verify_handler(3,0x80003000U,0x82000000U,4096)!=0);
    CHECK(ecnt_verify_handler(3,0x83000000U,0xfffffff0U,4096)!=0);
    CHECK(loader_calls==calls);
    fail_map_call=map_calls+2;
    CHECK(ecnt_decrypt_handler(3,4096,0x82000000U,0x83000000U)!=0);
    CHECK(active_maps==0 && fip_length==0); fail_map_call=0;
    CHECK(ecnt_verify_handler(3,0x83000000U,0x82000000U,4096)==0);
    CHECK(active_maps==0 && image_hash_base==0 && fip_length==0);
}
int main(void)
{
    dm_tests(); gcm_tests(); password_tests(); loader_tests();
    printf("TF-A crypto/SMC regressions: %u assertions passed\n",checks);
    return 0;
}

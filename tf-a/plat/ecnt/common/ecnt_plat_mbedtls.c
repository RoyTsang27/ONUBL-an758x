/*
 * Copyright (c) 2016, ARM Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <ecnt_plat_common.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>

#if defined(IMAGE_BL31)
int ecnt_mbedtls_pkcs5_pbkdf2_compare(const char *account, size_t account_len,
		const char *password, size_t password_len,
		const unsigned char *login_auth, unsigned int iterations,
		unsigned int key_length, unsigned int hash_algo)
{
	const mbedtls_md_info_t *info;
	mbedtls_md_context_t ctx;
	unsigned char key[ECNT_PBKDF2_MAX_KEY_SIZE] = {0};
	int ret = MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;

	if (account == NULL || password == NULL || login_auth == NULL ||
	    iterations == 0U || key_length == 0U || key_length > sizeof(key) ||
	    (hash_algo != 256U && hash_algo != 512U))
		return ret;
	info = mbedtls_md_info_from_type(hash_algo == 512U ?
					 MBEDTLS_MD_SHA512 : MBEDTLS_MD_SHA256);
	if (info == NULL)
		return ret;
	mbedtls_md_init(&ctx);
	if (mbedtls_md_setup(&ctx, info, 1) == 0) {
		ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx,
			(const unsigned char *)password, password_len,
			(const unsigned char *)account, account_len,
			iterations, key_length, key);
		if (ret == 0 && mbedtls_ct_memcmp(key, login_auth, key_length) != 0)
			ret = MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH;
	}
	mbedtls_md_free(&ctx);
	mbedtls_platform_zeroize(key, sizeof(key));
	return ret;
}
#endif

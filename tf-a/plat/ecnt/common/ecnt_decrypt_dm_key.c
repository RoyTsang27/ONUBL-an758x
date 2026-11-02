/* SPDX-License-Identifier: BSD-3-Clause */
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <common/debug.h>
#include <plat/common/platform.h>
#include <tools_share/firmware_encrypted.h>
#include <drivers/auth/crypto_mod.h>
#include <drivers/auth/mbedtls/mbedtls_common.h>
#include <mbedtls/aes.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>

#define DEC_OP_BUF_SIZE 256U
#define AIROHA_KEY_SIZE 32U

static int valid_aes_key_size(size_t size)
{
	return size == 16U || size == 24U || size == 32U;
}

int decrypt_dm_key(uint8_t *buffer, unsigned int size)
{
	mbedtls_aes_context ctx;
	uint8_t encrypted[DEC_OP_BUF_SIZE], decrypted[DEC_OP_BUF_SIZE];
	uint8_t key[AIROHA_KEY_SIZE] = {0};
	size_t key_len = sizeof(key), offset;
	unsigned int flags = 0;
	int rc = CRYPTO_ERR_DECRYPTION;

	if (buffer == NULL || size == 0U || size > sizeof(encrypted) ||
	    size % 16U != 0U)
		return CRYPTO_ERR_DECRYPTION;

	mbedtls_aes_init(&ctx);
	memcpy(encrypted, buffer, size);
	if (plat_get_enc_key_info(FW_ENC_WITH_SSK, key, &key_len, &flags,
				  0, 0) != 0 || !valid_aes_key_size(key_len))
		goto out;
	if (mbedtls_aes_setkey_dec(&ctx, key, key_len * 8U) != 0)
		goto out;
	for (offset = 0; offset < size; offset += 16U) {
		if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT,
					encrypted + offset, decrypted + offset) != 0)
			goto out;
	}
	/* Do not expose partial output or write beyond the supplied length. */
	memcpy(buffer, decrypted, size);
	rc = CRYPTO_SUCCESS;
out:
	mbedtls_aes_free(&ctx);
	mbedtls_platform_zeroize(key, sizeof(key));
	mbedtls_platform_zeroize(encrypted, sizeof(encrypted));
	mbedtls_platform_zeroize(decrypted, sizeof(decrypted));
	return rc;
}

int aes_gcm_decrypt(void *data, size_t len, const void *key,
		    unsigned int key_len, const void *iv,
		    unsigned int iv_len, const void *tag,
		    unsigned int tag_len)
{
	mbedtls_gcm_context ctx;
	unsigned char output[DEC_OP_BUF_SIZE + 16U], computed_tag[16];
	unsigned char expected_tag[16], nonce[ENC_MAX_IV_SIZE];
	unsigned char *bytes = data;
	size_t consumed = 0, produced = 0, chunk, written;
	int rc = CRYPTO_ERR_DECRYPTION;

	/* Format 1, produced by encrypt_fw, always carries a full 128-bit tag. */
	if (data == NULL || key == NULL || iv == NULL || tag == NULL ||
	    !valid_aes_key_size(key_len) || iv_len == 0U ||
	    iv_len > sizeof(nonce) || tag_len != sizeof(expected_tag))
		return CRYPTO_ERR_DECRYPTION;
	memcpy(expected_tag, tag, sizeof(expected_tag));
	memcpy(nonce, iv, iv_len);
	mbedtls_gcm_init(&ctx);
	if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key,
			       key_len * 8U) != 0 ||
	    mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, nonce, iv_len) != 0)
		goto out;

	while (consumed < len) {
		chunk = len - consumed;
		if (chunk > DEC_OP_BUF_SIZE)
			chunk = DEC_OP_BUF_SIZE;
		if (mbedtls_gcm_update(&ctx, bytes + consumed, chunk, output,
				       sizeof(output), &written) != 0)
			goto out;
		consumed += chunk;
		/* Support both immediate and buffered Mbed TLS 3.6 output. */
		if (written > sizeof(output) || written > consumed - produced)
			goto out;
		memcpy(bytes + produced, output, written);
		produced += written;
	}
	if (mbedtls_gcm_finish(&ctx, output, sizeof(output), &written,
			       computed_tag, sizeof(computed_tag)) != 0 ||
	    written > sizeof(output) || written != len - produced)
		goto out;
	memcpy(bytes + produced, output, written);
	if (mbedtls_ct_memcmp(expected_tag, computed_tag,
			      sizeof(expected_tag)) != 0)
		goto out;
	rc = CRYPTO_SUCCESS;
out:
	/* An authentication/backend failure must not leave usable plaintext. */
	if (rc != CRYPTO_SUCCESS)
		mbedtls_platform_zeroize(data, len);
	mbedtls_gcm_free(&ctx);
	mbedtls_platform_zeroize(output, sizeof(output));
	mbedtls_platform_zeroize(computed_tag, sizeof(computed_tag));
	mbedtls_platform_zeroize(expected_tag, sizeof(expected_tag));
	mbedtls_platform_zeroize(nonce, sizeof(nonce));
	return rc;
}

int decrypt_gcm_data(uint8_t *buffer, unsigned int size)
{
	struct fw_enc_hdr header;
	uint8_t key[AIROHA_KEY_SIZE] = {0};
	size_t key_len = sizeof(key), len;
	unsigned int flags = 0;
	int rc = CRYPTO_ERR_DECRYPTION;

	if (buffer == NULL || size < sizeof(header))
		return -EINVAL;
	/* Snapshot untrusted metadata before validating and using it. */
	memcpy(&header, buffer, sizeof(header));
	if (header.magic != ENC_HEADER_MAGIC || header.dec_algo != 0U ||
	    (header.flags & ~FW_ENC_STATUS_FLAG_MASK) != 0U ||
	    header.iv_len == 0U || header.iv_len > ENC_MAX_IV_SIZE ||
	    header.tag_len != ENC_MAX_TAG_SIZE)
		return -EINVAL;
	if (plat_get_enc_key_info(header.flags & FW_ENC_STATUS_FLAG_MASK,
				  key, &key_len, &flags, 0, 0) != 0 ||
	    !valid_aes_key_size(key_len))
		goto out;
	len = size - sizeof(header);
	rc = aes_gcm_decrypt(buffer + sizeof(header), len, key, key_len,
			     header.iv, header.iv_len, header.tag, header.tag_len);
	if (rc == CRYPTO_SUCCESS)
		memmove(buffer, buffer + sizeof(header), len);
out:
	mbedtls_platform_zeroize(key, sizeof(key));
	mbedtls_platform_zeroize(&header, sizeof(header));
	return rc;
}

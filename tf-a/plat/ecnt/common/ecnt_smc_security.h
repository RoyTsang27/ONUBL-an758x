/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef ECNT_SMC_SECURITY_H
#define ECNT_SMC_SECURITY_H

#include <stddef.h>
#include <stdint.h>
#include <platform_def.h>
#include <ecnt_scu.h>
#include <lib/xlat_tables/xlat_tables_v2.h>

/* Preserve the vendor SHA-256/SHA-512 derived-key capacity. */
#define ECNT_PBKDF2_MAX_KEY_SIZE 128U
#define ECNT_DM_KEY_MAX_SIZE 256U

/* Validate before rounding: caller arithmetic must never wrap at 32 bits.
 * Only normal-world DRAM is eligible, never MMIO, EL3 RAM or OP-TEE RAM.
 * The first reserved DRAM pages are not a general SMC exchange buffer.
 */
static inline int ecnt_ns_window(uint64_t address, uint64_t length,
				 uintptr_t *base, size_t *size)
{
	uint64_t limit = (uint64_t)EN7523_MEM_BASE +
			 ((uint64_t)GET_DRAM_SIZE() << 20);
	uint64_t end, aligned_end;

	if (limit > UINT64_C(0x100000000))
		limit = UINT64_C(0x100000000);
	if (length == 0U || address < (uint64_t)TZRAM2_BASE + TZRAM2_SIZE ||
	    address >= limit || length > limit - address)
		return 0;
	end = address + length;
#ifdef TCSUPPORT_OPTEE
	if (address < BL32_LIMIT && end > BL32_BASE)
		return 0;
#endif
	*base = (uintptr_t)(address & ~((uint64_t)PAGE_SIZE - 1U));
	aligned_end = (end + PAGE_SIZE - 1U) & ~((uint64_t)PAGE_SIZE - 1U);
	if (aligned_end > limit)
		return 0;
	*size = (size_t)(aligned_end - *base);
	return 1;
}
#endif

/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_SIG_AUTH_H
#define __PAS_SIG_AUTH_H

#include <pas_mbn_parser.h>
#include <qcom_pas_priv.h>
#include <tee_internal_api.h>

/*
 * Signature-authentication backend for the PAS TA: certificate chain,
 * signature, SW_ID/HW binding and anti-rollback. Mirrors the reference PIL
 * image-authentication flow, which runs this crypto work BEFORE the REE
 * loads any ELF segment into the carveout - called from
 * qcom_pas_seg_hash.c's INIT_IMAGE handling, between parsing the hash table
 * and trusting it.
 *
 * When CFG_QCOM_PAS_AUTH is disabled these calls compile to
 * no-ops (segment hash size defaults to SHA-384, authentication is skipped),
 * so qcom_pas_seg_hash.c stays free of build-config conditionals.
 */

#ifdef CFG_QCOM_PAS_AUTH
/*
 * Determine the per-segment hash digest size for @slot's metadata, mirroring
 * the reference segment-hash-algorithm selection: the OEM metadata's
 * root_cert_sel selects the fuse-configured algorithm on platforms that
 * implement the field; MBN v5 images (no OEM metadata) always use SHA-256.
 */
TEE_Result pas_sig_auth_hash_size(const struct pas_md_slot *slot,
				  uint32_t *hash_size);

/*
 * Authenticate @hs (already parsed by pas_mbn_parse()): reject
 * UIE-encrypted images, verify the certificate chain, signature and
 * fuse-bound bindings, verify the hash-table preamble entry, and enforce
 * anti-rollback. @md/@md_size are the same INIT_IMAGE metadata blob @hs was
 * parsed from.
 */
TEE_Result pas_sig_auth_authenticate(const struct pas_mbn *hs,
				     const uint8_t *md, size_t md_size,
				     uint32_t pas_id, uint32_t hash_size);
#else
static inline TEE_Result
pas_sig_auth_hash_size(const struct pas_md_slot *slot __unused,
		       uint32_t *hash_size)
{
	*hash_size = TEE_SHA384_HASH_SIZE;
	return TEE_SUCCESS;
}

static inline TEE_Result
pas_sig_auth_authenticate(const struct pas_mbn *hs __unused,
			  const uint8_t *md __unused,
			  size_t md_size __unused,
			  uint32_t pas_id __unused,
			  uint32_t hash_size __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_QCOM_PAS_AUTH */

#endif /* __PAS_SIG_AUTH_H */

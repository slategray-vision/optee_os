/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_FUSE_H
#define __PAS_FUSE_H

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * Thin wrappers around the fuse PTA (PTA_QCOM_FUSE_UUID). None apply policy
 * to the result - that is qcom_pas_auth.c's job. CFG_QCOM_PAS_AUTH
 * only: callers on a fuse PTA access failure decide for themselves whether
 * that means "not enforced" or a hard error.
 *
 * All calls share one session held for the TA's lifetime (see pas_fuse_open()
 * / pas_fuse_close()), matching how qcom_pas.c holds its own PTA_QCOM_PAS_UUID
 * session rather than opening one per command.
 */

/*
 * pas_fuse_open() - open the shared fuse PTA session
 *
 * Call once from TA_OpenSessionEntryPoint, alongside opening the PAS PTA
 * session. Every pas_fuse_* call below uses this session; none open their
 * own. Compiles to a no-op when CFG_QCOM_PAS_AUTH is disabled, so
 * qcom_pas.c stays free of a build-config conditional here too.
 */
#ifdef CFG_QCOM_PAS_AUTH
TEE_Result pas_fuse_open(void);

/*
 * pas_fuse_close() - close the shared fuse PTA session
 *
 * Call once from TA_CloseSessionEntryPoint, alongside closing the PAS PTA
 * session.
 */
void pas_fuse_close(void);
#else
static inline TEE_Result pas_fuse_open(void)
{
	return TEE_SUCCESS;
}

static inline void pas_fuse_close(void)
{
}
#endif /* CFG_QCOM_PAS_AUTH */

/*
 * pas_fuse_get_secboot_and_root_anchor() - secure-boot state + root-of-trust
 * @anchor:     buffer to receive the OEM root-of-trust digest (SHA-384,
 *              PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE bytes)
 * @secboot_on: out: true if secure boot (image authentication) is fused on
 */
TEE_Result pas_fuse_get_secboot_and_root_anchor(uint8_t *anchor,
						bool *secboot_on);

/*
 * struct pas_fuse_hw_binding_info - fuse-backed values for HW binding checks
 * @oem_id:                OEM_ID fuse value
 * @model_id:               MODEL_ID fuse value
 * @jtag_id:                JTAG_ID authentication bits (masked 0x0FFFFFFF)
 * @serial_num:             device serial number
 * @use_serial_num_override: true if the APPS SECURE_BOOTn USE_SERIAL_NUM
 *                            override fuse is blown (forces serial binding
 *                            regardless of the image metadata's own flag)
 * @soc_fam_dev:            SoC family|device number (TCSR SOC_HW_VERSION bits
 *                            31:16), valid only when @need_soc_vers was set
 */
struct pas_fuse_hw_binding_info {
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t jtag_id;
	uint32_t serial_num;
	bool use_serial_num_override;
	uint32_t soc_fam_dev;
};

/*
 * pas_fuse_get_hw_binding_info() - read every fuse-backed HW-binding value
 * @need_soc_vers: whether to also read SOC_HW_VERSION (only needed when the
 *                 image metadata sets IN_USE_SOC_HW_VERSION); skipping it
 *                 otherwise saves a command on the shared session
 * @info:          out: fuse values, undefined on error
 *
 * Reads device ids, the serial-number override and (conditionally) the SoC
 * version over one fuse PTA session, mirroring how the caller consumes them
 * together for a single image's HW binding checks.
 */
TEE_Result pas_fuse_get_hw_binding_info(bool need_soc_vers,
					struct pas_fuse_hw_binding_info *info);

/*
 * pas_fuse_get_eku_enforcement_en() - OEM_CONFIG2 EKU_ENFORCEMENT_EN
 * Returns false (not true/error) on a fuse PTA access failure: EKU
 * enforcement is an additional restriction on top of secure boot, not a
 * substitute for it.
 */
bool pas_fuse_get_eku_enforcement_en(void);

/*
 * pas_fuse_get_image_encryption_en() - OEM_CONFIG0 IMAGE_ENCRYPTION_ENABLE
 * Returns true (not false/error) on a fuse PTA access failure: an image
 * carrying UIE parameters must never be silently accepted as plaintext when
 * the device's encryption-fuse state cannot be confirmed.
 */
bool pas_fuse_get_image_encryption_en(void);

/*
 * struct pas_fuse_mrc_info - multiple-root-certificate provisioning state
 * @num_roots:       number of provisioned roots (1 when selection disabled)
 * @activation_list: per-index activation bitmap (bit i set => root i active)
 * @revocation_list: per-index revocation bitmap (bit i set => root i revoked)
 */
struct pas_fuse_mrc_info {
	uint32_t num_roots;
	uint32_t activation_list;
	uint32_t revocation_list;
};

/*
 * pas_fuse_get_mrc_info() - read the MRC provisioning state
 * On a fuse PTA access failure, @info is set to the single-root default
 * (num_roots=1, empty lists): the mandatory root-of-trust bind still runs
 * regardless, so a board without an accessible fuse PTA session simply does
 * not engage root selection.
 */
void pas_fuse_get_mrc_info(struct pas_fuse_mrc_info *info);

/*
 * pas_fuse_get_segment_hash_size() - per-segment digest size for root_cert_sel
 * @root_cert_sel: metadata root_cert_sel index (0-3)
 * @hash_size:     out: digest size in bytes (32 = SHA-256, 48 = SHA-384)
 */
TEE_Result pas_fuse_get_segment_hash_size(uint32_t root_cert_sel,
					  uint32_t *hash_size);

/*
 * pas_fuse_get_pil_rollback_version() - device PIL anti-rollback version
 * @dev_ver: out: device version (0 when ARB enforcement is off)
 */
TEE_Result pas_fuse_get_pil_rollback_version(uint32_t *dev_ver);

/*
 * pas_fuse_blow_pil_rollback_version() - advance the device ARB fuse
 * @version: image version to record as the new floor
 *
 * Monotonic and a no-op when @version is not greater than the current
 * device version or ARB enforcement is off.
 */
TEE_Result pas_fuse_blow_pil_rollback_version(uint32_t version);

#endif /* __PAS_FUSE_H */

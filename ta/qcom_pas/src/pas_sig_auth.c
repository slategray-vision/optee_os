// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * Signature-authentication backend for the PAS TA. Built only when
 * CFG_QCOM_PAS_AUTH is enabled; qcom_pas_seg_hash.c calls the
 * entry points at the bottom of this file, which compile to no-ops when the
 * feature is disabled (see pas_sig_auth.h).
 */

#include <config.h>
#include <pas_sig.h>
#include <pas_fuse.h>
#include <pas_mbn_parser.h>
#include <pas_meta.h>
#include <pas_policy.h>
#include <pta_qcom_fuse.h>
#include <pas_sig_auth.h>
#include <qcom_pas_priv.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <utee_defines.h>
#include <util.h>

/*
 * SHA-384 digest of the QTI production root certificate (DER-encoded), taken
 * verbatim from the platform's SHA-384 root-of-trust table. Used to bind the
 * QTI cert chain to the device-side anchor for double-signed images.
 */
static const uint8_t qti_root_of_trust[TEE_SHA384_HASH_SIZE] = {
	0x46, 0x7f, 0x30, 0x20, 0xc4, 0xcc, 0x78, 0x8d,
	0x2a, 0x27, 0xa6, 0xe0, 0x97, 0xff, 0xa7, 0xbf,
	0xc2, 0x4e, 0x82, 0xc2, 0xd5, 0x69, 0x53, 0xd3,
	0xb4, 0x5b, 0x49, 0x4c, 0xdb, 0xa5, 0xc2, 0x42,
	0x2a, 0x94, 0x7d, 0x2c, 0x81, 0xb5, 0x75, 0x2b,
	0x8a, 0x2a, 0xc9, 0xea, 0xc8, 0xac, 0xdf, 0x34,
};

/*
 * Accepted metadata major versions: V0 (0) and V1 (1); minor must be 0.
 */
#define SECBOOT_METADATA_MAJOR_V0	0U
#define SECBOOT_METADATA_MAJOR_V1	1U
#define SECBOOT_METADATA_MINOR		0U

/*
 * Reject metadata whose major/minor version falls outside the accepted
 * set. Must be called after signature verification so the metadata is
 * authenticated.
 */
static TEE_Result check_metadata_version(const struct pas_mbn *hs,
					 bool secboot_on)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pas_meta meta = { };

	res = pas_meta_get(hs, &meta);
	if (res == TEE_ERROR_NO_DATA)
		return TEE_SUCCESS; /* No OEM metadata (v5): nothing to check */
	if (res) {
		EMSG("PAS auth: bad OEM metadata in version check");
		return secboot_on ? res : TEE_SUCCESS;
	}

	if ((meta.major == SECBOOT_METADATA_MAJOR_V0 ||
	     meta.major == SECBOOT_METADATA_MAJOR_V1) &&
	    meta.minor == SECBOOT_METADATA_MINOR)
		return TEE_SUCCESS;

	EMSG("PAS auth: unsupported metadata version %"PRIu32".%"PRIu32,
	     meta.major, meta.minor);
	if (secboot_on)
		return TEE_ERROR_SECURITY;
	IMSG("PAS auth: metadata version mismatch tolerated");
	return TEE_SUCCESS;
}

/*
 * Bind the signed image to the peripheral being brought up: the metadata
 * SW_ID must match the value the platform assigns to this pas_id, so a
 * validly-signed image for one subsystem cannot be loaded onto another.
 * The reference implementation also compares the metadata secondary_sw_id,
 * but only against the image's own secondary_sw_id fed back from the same
 * metadata - a self-comparison that never constrains, so it is not
 * replicated here. The metadata lives inside the already
 * signature-verified region. Enforced when secure boot is on; logged
 * otherwise so unsigned-boot boards still come up.
 */
static TEE_Result check_sw_binding(const struct pas_mbn *hs,
				   uint32_t pas_id, bool secboot_on)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pas_meta meta = { };
	uint32_t expected = 0;

	res = pas_meta_get(hs, &meta);
	if (res == TEE_ERROR_NO_DATA) {
		/* No OEM metadata (MBN v5): nothing to bind. */
		return TEE_SUCCESS;
	}
	if (res) {
		EMSG("PAS auth: bad OEM metadata");
		return secboot_on ? res : TEE_SUCCESS;
	}

	res = pas_policy_expected_swid(pas_id, &expected);
	if (res) {
		EMSG("PAS auth: no SW_ID binding for pas_id %"PRIu32, pas_id);
		return secboot_on ? res : TEE_SUCCESS;
	}

	if (meta.sw_id != expected) {
		EMSG("PAS auth: SW_ID got %#"PRIx32" want %#"PRIx32,
		     meta.sw_id, expected);
		if (secboot_on)
			return TEE_ERROR_SECURITY;
		IMSG("PAS auth: SW_ID mismatch tolerated");
		return TEE_SUCCESS;
	}

	DMSG("PAS auth: SW_ID %#"PRIx32" bound to pas_id %"PRIu32, meta.sw_id,
	     pas_id);

	return TEE_SUCCESS;
}

/*
 * 2-bit option field value at @shift within @flags. Valid values are 0-2
 * (disable/enable/enable-with-serial-match) for DEBUG, root revoke/activate
 * and UIE key switch; 3 is reserved and never valid.
 */
static uint32_t pas_meta_option(uint32_t flags, uint32_t shift)
{
	return (flags >> shift) & PAS_META_OPTION_MASK;
}

/*
 * True if the 2-bit option field at @shift within @flags requests its
 * SN-gated enable value.
 */
static bool pas_meta_option_sn_gated(uint32_t flags, uint32_t shift)
{
	return pas_meta_option(flags, shift) == PAS_META_OPTION_ENABLE_SN;
}

/*
 * Reject metadata whose 2-bit option fields carry the reserved value 3.
 */
static TEE_Result check_metadata_options(const struct pas_meta *meta,
					 bool secboot_on)
{
	if (pas_meta_option(meta->flags,
			    PAS_META_FLAG_ROOT_REVOKE_ACTIVATE_SHIFT) <=
	    PAS_META_OPTION_MAX &&
	    pas_meta_option(meta->flags, PAS_META_FLAG_UIE_KEY_SWITCH_SHIFT) <=
	    PAS_META_OPTION_MAX &&
	    pas_meta_option(meta->flags, PAS_META_FLAG_DEBUG_SHIFT) <=
	    PAS_META_OPTION_MAX)
		return TEE_SUCCESS;

	EMSG("PAS auth: reserved metadata option value, flags=%#"PRIx32,
	     meta->flags);
	if (secboot_on)
		return TEE_ERROR_SECURITY;
	IMSG("PAS auth: reserved option value tolerated");
	return TEE_SUCCESS;
}

/*
 * Device-identity fields consumed by the HW binding checks below, read via
 * pas_fuse_get_hw_binding_info().
 */
struct pas_device_ids {
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t jtag_id;
	uint32_t serial_num;
};

/*
 * Bind OEM_ID and MODEL_ID to the device fuses: each field is checked
 * unless its *_INDEPENDENT flag exempts it.
 */
static TEE_Result check_oem_model_binding(const struct pas_meta *meta,
					  const struct pas_device_ids *ids,
					  bool secboot_on)
{
	bool oem_independent = meta->flags &
				BIT32(PAS_META_FLAG_OEM_ID_INDEPENDENT);
	bool model_independent = false;

	/*
	 * v0 metadata has no MODEL_ID_INDEPENDENT bit; it is implied by
	 * OEM_ID_INDEPENDENT. Reading bit 11 unconditionally wrongly
	 * enforced MODEL_ID binding on v0-signed images.
	 */
	if (meta->major == 0)
		model_independent = oem_independent;
	else
		model_independent = meta->flags &
				    BIT32(PAS_META_FLAG_MODEL_ID_INDEPENDENT);

	if (!oem_independent && meta->oem_id != ids->oem_id) {
		EMSG("PAS auth: OEM_ID got %#"PRIx32" want %#"PRIx32,
		     meta->oem_id, ids->oem_id);
		if (secboot_on)
			return TEE_ERROR_SECURITY;
		IMSG("PAS auth: OEM_ID mismatch tolerated");
	}

	if (!model_independent && meta->model_id != ids->model_id) {
		EMSG("PAS auth: MODEL_ID got %#"PRIx32" want %#"PRIx32,
		     meta->model_id, ids->model_id);
		if (secboot_on)
			return TEE_ERROR_SECURITY;
		IMSG("PAS auth: MODEL_ID mismatch tolerated");
	}

	return TEE_SUCCESS;
}

/*
 * Bind HW_ID (JTAG authentication bits) to the device fuse; checked only
 * when IN_USE_JTAG_ID is set.
 */
static TEE_Result check_jtag_binding(const struct pas_meta *meta,
				     const struct pas_device_ids *ids,
				     bool secboot_on)
{
	if (!(meta->flags & BIT32(PAS_META_FLAG_IN_USE_JTAG_ID)))
		return TEE_SUCCESS;

	if (meta->hw_id == ids->jtag_id)
		return TEE_SUCCESS;

	EMSG("PAS auth: HW_ID got %#"PRIx32" want %#"PRIx32, meta->hw_id,
	     ids->jtag_id);
	if (secboot_on)
		return TEE_ERROR_SECURITY;
	IMSG("PAS auth: HW_ID mismatch tolerated");
	return TEE_SUCCESS;
}

/*
 * Bind the device serial number against the metadata allow-list. Checked when
 * the metadata's USE_SERIAL_NUMBER flag is set, the APPS SECURE_BOOTn
 * USE_SERIAL_NUM fuse override forces it, or the DEBUG/root-revoke-activate/
 * UIE-key-switch option requests its SN-gated enable value (the reference
 * gates each of those three on a serial match, independently of whether this
 * TA acts on the requested permission). When none of those triggers apply,
 * the check is skipped entirely, matching the reference. When a trigger does
 * apply, the reference treats a device with no fused serial as unbindable
 * and fails the check rather than skipping it - a zero fused serial is not a
 * no-op here either.
 */
static TEE_Result check_serial_binding(const struct pas_meta *meta,
				       const struct pas_device_ids *ids,
				       bool use_serial_num_override,
				       bool secboot_on)
{
	static const uint32_t sn_gated_shifts[] = {
		PAS_META_FLAG_DEBUG_SHIFT,
		PAS_META_FLAG_ROOT_REVOKE_ACTIVATE_SHIFT,
		PAS_META_FLAG_UIE_KEY_SWITCH_SHIFT,
	};
	bool sn_gated = false;
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(sn_gated_shifts); i++) {
		if (pas_meta_option_sn_gated(meta->flags, sn_gated_shifts[i])) {
			sn_gated = true;
			break;
		}
	}

	if (!(meta->flags & BIT32(PAS_META_FLAG_USE_SERIAL_NUMBER)) &&
	    !use_serial_num_override && !sn_gated)
		return TEE_SUCCESS;

	if (!ids->serial_num) {
		EMSG("PAS auth: serial binding required, no fused serial");
		if (secboot_on)
			return TEE_ERROR_SECURITY;
		IMSG("PAS auth: missing fused serial tolerated");
		return TEE_SUCCESS;
	}

	for (i = 0; i < ARRAY_SIZE(meta->serial_num); i++) {
		if (meta->serial_num[i] &&
		    meta->serial_num[i] == ids->serial_num)
			return TEE_SUCCESS;
	}

	EMSG("PAS auth: serial number %#"PRIx32" not in metadata allow-list",
	     ids->serial_num);
	if (secboot_on)
		return TEE_ERROR_SECURITY;
	IMSG("PAS auth: serial number mismatch tolerated");
	return TEE_SUCCESS;
}

/*
 * Bind the SoC family|device version against the metadata allow-list;
 * checked only when IN_USE_SOC_HW_VERSION is set.
 */
static TEE_Result check_soc_vers_binding(const struct pas_meta *meta,
					 uint32_t fam_dev, bool secboot_on)
{
	size_t i = 0;

	if (!(meta->flags & BIT32(PAS_META_FLAG_IN_USE_SOC_HW_VERSION)))
		return TEE_SUCCESS;

	for (i = 0; i < ARRAY_SIZE(meta->soc_vers); i++) {
		if (meta->soc_vers[i] == fam_dev)
			return TEE_SUCCESS;
	}

	EMSG("PAS auth: SOC_HW_VERSION %#"PRIx32" not in metadata allow-list",
	     fam_dev);
	if (secboot_on)
		return TEE_ERROR_SECURITY;
	IMSG("PAS auth: SOC_HW_VERSION mismatch tolerated");
	return TEE_SUCCESS;
}

/*
 * Bind the signed image to this device's fuses and reject malformed option
 * fields (HW/OEM/MODEL/serial/SoC binding checks; UIE key-switch handling
 * excluded, out of scope for PAS peripheral images). Tolerated when secure
 * boot is off.
 */
static TEE_Result check_hw_binding(const struct pas_mbn *hs,
				   bool secboot_on)
{
	struct pas_fuse_hw_binding_info info = { };
	struct pas_device_ids ids = { };
	struct pas_meta meta = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	bool need_soc_vers = false;

	res = pas_meta_get(hs, &meta);
	if (res == TEE_ERROR_NO_DATA)
		return TEE_SUCCESS; /* No OEM metadata (v5): nothing to bind */
	if (res) {
		EMSG("PAS auth: bad OEM metadata in HW binding check");
		return secboot_on ? res : TEE_SUCCESS;
	}

	res = check_metadata_options(&meta, secboot_on);
	if (res)
		return res;

	need_soc_vers = meta.flags & BIT32(PAS_META_FLAG_IN_USE_SOC_HW_VERSION);
	res = pas_fuse_get_hw_binding_info(need_soc_vers, &info);
	if (res)
		return secboot_on ? res : TEE_SUCCESS;

	ids.oem_id = info.oem_id;
	ids.model_id = info.model_id;
	ids.jtag_id = info.jtag_id;
	ids.serial_num = info.serial_num;

	res = check_oem_model_binding(&meta, &ids, secboot_on);
	if (res)
		return res;

	res = check_jtag_binding(&meta, &ids, secboot_on);
	if (res)
		return res;

	res = check_serial_binding(&meta, &ids, info.use_serial_num_override,
				   secboot_on);
	if (res)
		return res;

	res = check_soc_vers_binding(&meta, info.soc_fam_dev, secboot_on);
	if (res)
		return res;

	DMSG("PAS auth: HW binding ok (oem=%#"PRIx32" model=%#"PRIx32")",
	     ids.oem_id, ids.model_id);

	return TEE_SUCCESS;
}

/*
 * Reject a UIE-encrypted image. The reference decrypts such an image before
 * use when the OEM_CONFIG0 image-encryption fuse is blown; image decryption is
 * not supported here, so an encrypted image cannot be authenticated as
 * plaintext. Mirror the reference gate: act only when the image carries a UIE
 * parameter block AND the encryption fuse is provisioned - an image with a UIE
 * block on a device without the fuse is used as-is on the reference too.
 */
static TEE_Result reject_if_encrypted(const struct pas_mbn *hs)
{
	if (!hs->uie_encrypted)
		return TEE_SUCCESS;

	if (!pas_fuse_get_image_encryption_en())
		return TEE_SUCCESS;

	EMSG("PAS auth: UIE image encryption not supported");

	return TEE_ERROR_NOT_SUPPORTED;
}

/*
 * Verify the QTI countersignature on a double-signed image, mirroring the
 * reference PIL signature-verification flow. No-op when no QTI material is
 * present, unless the image's SW_ID mandates DOUBLE_SIGNED, in which case
 * absent QTI material is fatal when secure boot is on. The QTI root anchor is
 * the production root from the platform's SHA-384 root-of-trust table.
 */
static TEE_Result verify_qti_countersignature(const struct pas_mbn *hs,
					      bool secboot_on)
{
	enum pas_sign_authority auth = PAS_OEM_SIGNED;
	uint32_t rot_hash_algo = TEE_ALG_SHA384;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t qsig_hash_algo = 0;
	const uint8_t *qleaf = NULL;
	const uint8_t *qroot = NULL;
	struct pas_meta meta = { };
	uint8_t *qsigned = NULL;
	size_t qsigned_len = 0;
	uint32_t qsig_algo = 0;
	uint32_t qsalt_len = 0;
	size_t qleaf_len = 0;
	size_t qroot_len = 0;

	if (pas_meta_get(hs, &meta) == TEE_SUCCESS)
		auth = pas_policy_signer(meta.sw_id);

	if (!hs->qti_certs || !hs->qti_sig) {
		if (auth != PAS_DOUBLE_SIGNED)
			return TEE_SUCCESS;
		EMSG("PAS auth: DOUBLE_SIGNED, QTI absent");
		if (secboot_on)
			return TEE_ERROR_SECURITY;
		IMSG("PAS auth: no QTI material, tolerated");
		return TEE_SUCCESS;
	}

	res = pas_sig_verify_cert_chain(hs->qti_certs, hs->qti_certs_size,
					pas_fuse_get_eku_enforcement_en(), 1,
					0, &qleaf, &qleaf_len, &qroot,
					&qroot_len);
	if (res) {
		EMSG("PAS auth: QTI cert chain invalid");
		if (secboot_on)
			return res;
		IMSG("PAS auth: QTI cert failure tolerated");
		return TEE_SUCCESS;
	}

	res = pas_sig_check_root_of_trust(rot_hash_algo,
					  sizeof(qti_root_of_trust),
					  qroot, qroot_len, qti_root_of_trust);
	if (res) {
		if (secboot_on) {
			EMSG("PAS auth: QTI root-of-trust mismatch");
			return res;
		}
		IMSG("PAS auth: QTI ROT mismatch tolerated");
	}

	res = pas_sig_algo_from_leaf(qleaf, qleaf_len, &qsig_algo,
				     &qsig_hash_algo, &qsalt_len);
	if (res) {
		EMSG("PAS auth: cannot determine QTI sig algo");
		if (secboot_on)
			return res;
		IMSG("PAS auth: QTI sig algo tolerated");
		return TEE_SUCCESS;
	}

	res = pas_meta_signed_copy(hs, PAS_SIGNER_QTI, &qsigned, &qsigned_len);
	if (res)
		return res;

	res = pas_sig_verify_signature(qsig_algo, qsig_hash_algo, qsalt_len,
				       qleaf, qleaf_len, qsigned, qsigned_len,
				       hs->qti_sig, hs->qti_sig_size);
	TEE_Free(qsigned);
	if (res) {
		EMSG("PAS auth: QTI signature verify failed");
		if (secboot_on)
			return res;
		IMSG("PAS auth: QTI sig failure tolerated");
		return TEE_SUCCESS;
	}

	return TEE_SUCCESS;
}

/*
 * Validate the certificate chain, bind its root to the device ROT and verify
 * the signature. A missing or mismatched anchor is tolerated when secure boot
 * is disabled; when enabled, every step must pass.
 */
static TEE_Result verify_authenticity(const struct pas_mbn *hs,
				      uint32_t pas_id)
{
	uint8_t anchor[PTA_QCOM_FUSE_ROOT_OF_TRUST_SIZE] = { };
	uint32_t rot_hash_algo = TEE_ALG_SHA384;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Result rc = TEE_ERROR_GENERIC;
	struct pas_fuse_mrc_info mrc = { };
	uint8_t *signed_copy = NULL;
	const uint8_t *roots = NULL;
	uint32_t sig_hash_algo = 0;
	uint32_t root_cert_sel = 0;
	struct pas_meta meta = { };
	const uint8_t *leaf = NULL;
	bool secboot_on = false;
	uint32_t sig_algo = 0;
	uint32_t salt_len = 0;
	size_t signed_len = 0;
	size_t roots_len = 0;
	size_t leaf_len = 0;

	rc = pas_fuse_get_secboot_and_root_anchor(anchor, &secboot_on);

	if (!hs->oem_certs || !hs->oem_sig || !hs->signed_region) {
		if (secboot_on) {
			EMSG("PAS auth: metadata is not OEM-signed");
			return TEE_ERROR_SECURITY;
		}
		IMSG("PAS auth: no OEM material, tolerated (NS boot)");
		return TEE_SUCCESS;
	}

	/*
	 * root_cert_sel (metadata word 28) picks which provisioned root this
	 * chain is verified against; images without OEM metadata (MBN v5)
	 * always use root 0. Selecting an index only chooses which already
	 * fuse-bound root to try - it does not grant trust by itself.
	 */
	if (pas_meta_get(hs, &meta) == TEE_SUCCESS)
		root_cert_sel = meta.root_cert_sel;

	pas_fuse_get_mrc_info(&mrc);
	if (root_cert_sel >= mrc.num_roots) {
		EMSG("PAS auth: root_cert_sel %"PRIu32" >= %"PRIu32" roots",
		     root_cert_sel, mrc.num_roots);
		if (secboot_on)
			return TEE_ERROR_SECURITY;
		IMSG("PAS auth: root selection out of range tolerated");
		root_cert_sel = 0;
		mrc.num_roots = 1;
	}

	if (mrc.num_roots > 1) {
		res = pas_sig_check_root_cert_index(root_cert_sel,
						    mrc.num_roots,
						    mrc.activation_list,
						    mrc.revocation_list);
		if (res) {
			EMSG("PAS auth: root cert %"PRIu32" not usable",
			     root_cert_sel);
			if (secboot_on)
				return res;
			IMSG("PAS auth: root selection failure tolerated");
			root_cert_sel = 0;
			mrc.num_roots = 1;
		}
	}

	res = pas_sig_verify_cert_chain(hs->oem_certs, hs->oem_certs_size,
					pas_fuse_get_eku_enforcement_en(),
					mrc.num_roots, root_cert_sel, &leaf,
					&leaf_len, &roots, &roots_len);
	if (res) {
		EMSG("PAS auth: OEM cert chain invalid: %#"PRIx32, res);
		if (secboot_on)
			return res;
		IMSG("PAS auth: cert chain failure tolerated (NS boot)");
		return TEE_SUCCESS;
	}

	if (!rc) {
		/*
		 * The root-of-trust digest covers every provisioned root
		 * concatenated (a single root when selection is disabled),
		 * matching how the anchor fuse is provisioned.
		 */
		res = pas_sig_check_root_of_trust(rot_hash_algo,
						  sizeof(anchor), roots,
						  roots_len, anchor);
		if (res && secboot_on) {
			EMSG("PAS auth: root-of-trust mismatch");
			goto out;
		}
		if (res)
			IMSG("PAS auth: root-of-trust mismatch tolerated");
	} else if (secboot_on) {
		EMSG("PAS auth: root-of-trust unavailable, secure boot on");
		res = rc;
		goto out;
	} else {
		IMSG("PAS auth: root-of-trust anchor unavailable");
	}

	/* Metadata is authenticated now; bind it to this peripheral. */
	res = check_metadata_version(hs, secboot_on);
	if (res)
		goto out;

	res = check_sw_binding(hs, pas_id, secboot_on);
	if (res)
		goto out;

	res = check_hw_binding(hs, secboot_on);
	if (res)
		goto out;

	res = pas_sig_algo_from_leaf(leaf, leaf_len, &sig_algo,
				     &sig_hash_algo, &salt_len);
	if (res) {
		EMSG("PAS auth: cannot determine signature algorithm: %#"PRIx32,
		     res);
		if (secboot_on)
			goto out;
		IMSG("PAS auth: sig algo failure tolerated (NS boot)");
		res = TEE_SUCCESS;
		goto out;
	}

	res = pas_meta_signed_copy(hs, PAS_SIGNER_OEM, &signed_copy,
				   &signed_len);
	if (res)
		goto out;

	res = pas_sig_verify_signature(sig_algo, sig_hash_algo, salt_len, leaf,
				       leaf_len, signed_copy, signed_len,
				       hs->oem_sig, hs->oem_sig_size);
	TEE_Free(signed_copy);
	if (res) {
		EMSG("PAS auth: OEM signature verify failed: %#"PRIx32, res);
		if (secboot_on)
			goto out;
		IMSG("PAS auth: signature failure tolerated (NS boot)");
		res = TEE_SUCCESS;
		goto out;
	}

	res = verify_qti_countersignature(hs, secboot_on);
	if (res)
		goto out;

	DMSG("PAS auth: authenticity verified");
out:
	memzero_explicit(anchor, sizeof(anchor));

	return res;
}

/*
 * Mirror the reference PIL anti-rollback check: reject firmware whose
 * anti_rollback field in the OEM metadata is below the device version fused
 * in QFPROM, then advance the fuse when the image is newer. Fuse PTA open
 * and read failures are non-fatal: ARB enforcement requires secure boot,
 * which requires an accessible QFPROM. MBN v5 images without OEM metadata
 * skip the check.
 */
static TEE_Result check_anti_rollback(const struct pas_mbn *hs)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pas_meta meta = { };
	uint32_t dev_ver = 0;

	res = pas_meta_get(hs, &meta);
	if (res == TEE_ERROR_NO_DATA) {
		/* No OEM metadata (MBN v5): no ARB field to check. */
		return TEE_SUCCESS;
	}
	if (res) {
		EMSG("PAS ARB: bad OEM metadata");
		return res;
	}

	res = pas_fuse_get_pil_rollback_version(&dev_ver);
	if (res)
		return TEE_SUCCESS; /* Non-fatal: ARB requires secure boot */

	if (!dev_ver)
		return TEE_SUCCESS; /* ARB enforcement disabled in fuses */

	if (meta.anti_rollback < dev_ver) {
		EMSG("PAS ARB: image version %"PRIu32" < device %"PRIu32,
		     meta.anti_rollback, dev_ver);
		return TEE_ERROR_SECURITY;
	}

	if (meta.anti_rollback > dev_ver)
		pas_fuse_blow_pil_rollback_version(meta.anti_rollback);

	DMSG("PAS ARB: image version %"PRIu32" >= device %"PRIu32,
	     meta.anti_rollback, dev_ver);
	return TEE_SUCCESS;
}

/*
 * Determine the per-segment hash digest size for @slot's metadata, mirroring
 * the reference segment-hash-algorithm selection: the OEM metadata's
 * root_cert_sel (word 28) selects the fuse-configured algorithm via the fuse
 * PTA on platforms that implement the field; images without OEM metadata
 * (MBN v5) or without the fuse field use the reference default
 * root_cert_sel of 0.
 */
#define SECBOOT_DEFAULT_ROOT_CERT_SEL	0U

TEE_Result pas_sig_auth_hash_size(const struct pas_md_slot *slot,
				  uint32_t *hash_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t root_cert_sel = SECBOOT_DEFAULT_ROOT_CERT_SEL;
	uint32_t version = 0;

	/*
	 * MBN v5 hash tables are always SHA-256 by format definition; the
	 * fuse-selected digest applies only to v6. Read the version first and
	 * short-circuit v5 before consulting the fuse.
	 */
	res = pas_meta_peek_version(slot->md, slot->md_size, &version);
	if (res)
		return res;
	if (version == PAS_MBN_VERSION_5) {
		*hash_size = TEE_SHA256_HASH_SIZE;
		return TEE_SUCCESS;
	}

	res = pas_meta_peek_root_cert_sel(slot->md, slot->md_size,
					  &root_cert_sel);
	if (res == TEE_ERROR_NO_DATA)
		root_cert_sel = SECBOOT_DEFAULT_ROOT_CERT_SEL;
	else if (res)
		return res;

	res = pas_fuse_get_segment_hash_size(root_cert_sel, hash_size);
	if (res) {
		/*
		 * No accessible fuse PTA (absent from the build, or the read
		 * itself failed): fall back to the pre-secure-boot default
		 * rather than aborting authentication, matching how every
		 * other fuse consultation in this file treats an
		 * unavailable fuse PTA as "secure boot is not enforced"
		 * instead of a hard failure.
		 */
		IMSG("PAS auth: hash size unavailable, using SHA-384: %#"PRIx32,
		     res);
		*hash_size = TEE_SHA384_HASH_SIZE;
		return TEE_SUCCESS;
	}

	return TEE_SUCCESS;
}

TEE_Result pas_sig_auth_authenticate(const struct pas_mbn *hs,
				     const uint8_t *md, size_t md_size,
				     uint32_t pas_id, uint32_t hash_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = reject_if_encrypted(hs);
	if (res) {
		EMSG("PAS auth: reject_if_encrypted failed: %#"PRIx32, res);
		return res;
	}

	res = verify_authenticity(hs, pas_id);
	if (res) {
		EMSG("PAS auth: verify_authenticity failed: %#"PRIx32, res);
		return res;
	}

	res = pas_meta_verify_preamble(md, md_size, hs->hash_table, hash_size);
	if (res) {
		EMSG("PAS auth: pas_meta_verify_preamble failed: %#"PRIx32,
		     res);
		return res;
	}

	res = check_anti_rollback(hs);
	if (res) {
		EMSG("PAS auth: check_anti_rollback failed: %#"PRIx32, res);
		return res;
	}

	return TEE_SUCCESS;
}

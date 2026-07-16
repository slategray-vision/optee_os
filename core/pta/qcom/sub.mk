subdirs-$(CFG_QCOM_PAS_PTA) += pas

# Exposes qfprom-backed fuse reads (secure-boot state, root-of-trust,
# anti-rollback version, MRC info, EKU/UIE enable bits) to user TAs.
# Forced alongside CFG_QCOM_QFPROM in the platform target.mk.
CFG_QCOM_FUSE_PTA ?= n
subdirs-$(CFG_QCOM_FUSE_PTA) += fuse

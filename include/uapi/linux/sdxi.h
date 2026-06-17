/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
#ifndef __LINUX_SDXI_H
#define __LINUX_SDXI_H

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * SDXI userspace ABI.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 *
 * All ioctls below use a struct whose first field is @argsz, the size of
 * the struct in bytes. The kernel rejects @argsz smaller than the minimum
 * it requires with -EINVAL, and uses @argsz to determine the layout
 * version supplied by userspace. Fields not understood by an older kernel
 * are ignored on input and zeroed on output, allowing additive UAPI
 * extensions under a single ioctl number; incompatible changes bump
 * SDXI_UAPI_MAJOR.
 *
 * Field direction is annotated with one of:
 *   IN     - userspace -> kernel.
 *   OUT    - kernel -> userspace.
 *   IN/OUT - both directions in the same field.
 * For fields whose direction depends on flags or ioctl, the per-call
 * directions are called out in the kernel-doc block.
 *
 * Reserved fields must be zero on input; the kernel zeroes them on output.
 * The @flags field of every struct must be zero unless documented bits are
 * set; unknown bits return -EINVAL.
 */

/* UAPI version and capability discovery. */
#define SDXI_UAPI_MAJOR		1
#define SDXI_UAPI_MINOR		0

#define SDXI_UAPI_CAP_WORDS	4U

#define SDXI_UAPI_CAP_DEV_INFO		(1ULL << 0)
#define SDXI_UAPI_CAP_DEV_ATTR_MGMT	(1ULL << 1)
#define SDXI_UAPI_CAP_RKEY_MGMT		(1ULL << 2)
#define SDXI_UAPI_CAP_CXT_CREATE	(1ULL << 3)
#define SDXI_UAPI_CAP_CXT_EVENTFD	(1ULL << 4)
#define SDXI_UAPI_CAP_AKEY_MGMT		(1ULL << 5)
#define SDXI_UAPI_CAP_ADMIN_DISC	(1ULL << 6)
#define SDXI_UAPI_CAP_ADMIN_VENDOR	(1ULL << 7)

/**
 * struct sdxi_uapi_info_args - argument for SDXI_GET_UAPI_INFO.
 * @argsz:      IN/OUT: size of this struct in bytes.
 * @flags:      IN: must be zero.
 * @uapi_major: OUT: UAPI generation.
 * @uapi_minor: OUT: UAPI revision.
 * @cap_words:  OUT: number of valid 64-bit words in @caps.
 * @rsvd0:      reserved, must be zero.
 * @caps:       OUT: bitmap of SDXI_UAPI_CAP_* features advertised by the
 *              kernel. @cap_words gives the number of words populated;
 *              trailing words are zero.
 */
struct sdxi_uapi_info_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u16 uapi_major;			/* out */
	__u16 uapi_minor;			/* out */
	__u16 cap_words;			/* out */
	__u16 rsvd0;				/* reserved */

	__aligned_u64 caps[SDXI_UAPI_CAP_WORDS];/* out */
};

/***************/
/* DEVICE INFO */
/***************/
/**
 * struct sdxi_dev_info_args - argument for SDXI_GET_DEV_INFO.
 * @argsz:    IN/OUT: size of this struct in bytes.
 * @flags:    IN: must be zero.
 * @hw_major: OUT: MMIO_VERSION.major.
 * @hw_minor: OUT: MMIO_VERSION.minor.
 * @rsvd0:    reserved, must be zero.
 * @cap0:     OUT: raw MMIO_CAP0.
 * @cap1:     OUT: raw MMIO_CAP1.
 * @sts0:     OUT: raw MMIO_STS0, read upon ioctl entry.
 * @rsvd1:    reserved for future fields, must be zero.
 */
struct sdxi_dev_info_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u16 hw_major;				/* out */
	__u16 hw_minor;				/* out */
	__u32 rsvd0;				/* reserved */

	__aligned_u64 cap0;			/* out */
	__aligned_u64 cap1;			/* out */
	__aligned_u64 sts0;			/* out */

	__aligned_u64 rsvd1[4];			/* reserved */
};

/*********************/
/* DEVICE ATTRIBUTES */
/*********************/
/* Device attribute selectors used with SDXI_{GET,SET}_DEV_ATTR. */
enum sdxi_dev_attr {
	SDXI_DEV_ATTR_GSR         = 1,	/* MMIO_CTL0.fn_gsr */
	SDXI_DEV_ATTR_GRP_ID      = 2,	/* MMIO_CTL0.fn_grp_id */
	SDXI_DEV_ATTR_MAX_BUFFER  = 3,	/* MMIO_CTL2.max_buffer */
	SDXI_DEV_ATTR_MAX_AKEY_SZ = 4,	/* MMIO_CTL2.max_akey_sz */
	SDXI_DEV_ATTR_MAX_RKEY_SZ = 5,	/* MMIO_RKEY.max_rkey_sz */
	SDXI_DEV_ATTR_MAX_CXT     = 6,	/* MMIO_CTL2.max_cxt */
};

/**
 * struct sdxi_dev_attr_args - argument for SDXI_{GET,SET}_DEV_ATTR.
 * @argsz: IN/OUT: size of this struct in bytes.
 * @flags: IN: must be zero. Unknown bits return -EINVAL.
 * @attr:  IN: attribute selector, see enum sdxi_dev_attr. Unknown values
 *         return -EOPNOTSUPP.
 * @val:   GET: OUT: current value.
 *         SET: IN: requested value; OUT: value actually applied.
 * @rsvd0: reserved, must be zero.
 */
struct sdxi_dev_attr_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__aligned_u64 attr;			/* in */
	__aligned_u64 val;			/* in/out: see ioctl */
	__aligned_u64 rsvd0[4];			/* reserved */
};

/******************/
/* KEY MANAGEMENT */
/******************/
/*
 * Key tables (RKey and AKey).
 *
 * RKey and AKey tables share the same wire format below; the table being
 * addressed is selected by the fd and the ioctl number, not by any field
 * in the struct:
 *
 *   RKey (per-device, CAP_SYS_ADMIN), device fd:
 *     SDXI_GET_RKEY_LIST, SDXI_GET_RKEYS, SDXI_SET_RKEYS.
 *   AKey (per-context, user-accessible), context fd:
 *     SDXI_GET_AKEY_LIST, SDXI_GET_AKEYS, SDXI_SET_AKEYS.
 *
 * Typical usage:
 *   1) *_LIST returns the table size and a bitmap of valid indices. Pass
 *      buf_size = 0 to learn the required size, then re-issue with a
 *      sized buffer.
 *   2) GET_*KEYS: caller fills entries[i].index for each row of interest;
 *      the kernel fills entries[i].data[] in place.
 *   3) SET_*KEYS: caller supplies fully populated entries[]; the kernel
 *      writes them to the table and reports a commit summary.
 *
 * For all key-table structs @argsz covers only the fixed header, not the
 * trailing flexible array.
 */

/**
 * struct sdxi_key_entry - one RKEY_ENT/AKEY_ENT exchanged with userspace.
 * @index: IN: table index.
 * @rsvd0: reserved, must be zero.
 * @data:  raw entry dwords in little-endian wire order, used by GET/SET ioctls.
 */
struct sdxi_key_entry {
	__u32 index;				/* in */
	__u32 rsvd0;				/* reserved */
	__u32 data[4];				/* in/out: see ioctl */
};

/**
 * struct sdxi_key_list_args - argument for SDXI_GET_{R,A}KEY_LIST.
 * @argsz:    IN/OUT: size of the fixed header in bytes (excludes @data).
 * @flags:    IN: must be zero.
 * @buf_size: IN: bytes available in @data; OUT: bytes required for the
 *            full bitmap (i.e. ceil(@nentries / 8)).
 * @nentries: OUT: total number of entries in the table.
 * @nvalid:   OUT: number of valid entries (popcount of the full bitmap),
 *            independent of how many bytes fit in @data.
 * @rsvd0:    reserved, must be zero.
 * @data:     OUT: valid bitmap. Index N is valid iff bit (N % 8) of
 *            byte (N / 8) is set.
 *
 * If the supplied buffer is too small the ioctl returns -ENOSPC, leaves
 * @data untouched and updates @buf_size, @nentries and @nvalid so the
 * caller can resize and retry.
 */
struct sdxi_key_list_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u32 buf_size;				/* in/out */
	__u32 nentries;				/* out */
	__u32 nvalid;				/* out */
	__u32 rsvd0;				/* reserved */

	__u8  data[];				/* out */
};

/**
 * struct sdxi_get_keys_args - argument for SDXI_GET_{R,A}KEYS.
 * @argsz:   IN/OUT: size of the fixed header in bytes (excludes @entries).
 * @flags:   IN: must be zero.
 * @nkeys:   IN: number of entries requested; OUT: number of entries
 *           actually populated. Entries beyond the returned @nkeys are
 *           left untouched.
 * @rsvd0:   reserved, must be zero.
 * @entries: IN: caller writes @entries[i].index to select rows.
 *           OUT: kernel fills @entries[i].data[] in place.
 */
struct sdxi_get_keys_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u32 nkeys;				/* in/out */
	__u32 rsvd0;				/* reserved */

	struct sdxi_key_entry entries[];	/* in/out */
};

/* Commit outcome reported by SDXI_SET_{R,A}KEYS in @commit_state. */
enum sdxi_key_commit_state {
	/* No entry bytes were written. Safe default for pre-zeroed args. */
	SDXI_KEY_COMMIT_NONE	 = 0,
	/* All requested entries committed. */
	SDXI_KEY_COMMIT_ALL	 = 1,
	/*
	 * One or more entries were written but the driver could not confirm
	 * the final hardware-visible state. @first_failed_index names the
	 * lowest entries[] slot whose commit is unconfirmed; entries below
	 * it are guaranteed committed.
	 */
	SDXI_KEY_COMMIT_PARTIAL	 = 2,
};

/* @timeout_ms sentinel: 0 selects the driver default. */
#define SDXI_KEY_TIMEOUT_DEFAULT	0U

/**
 * struct sdxi_set_keys_args - argument for SDXI_SET_{R,A}KEYS.
 * @argsz:              IN/OUT: size of the fixed header in bytes
 *                      (excludes @entries).
 * @flags:              IN: must be zero.
 * @timeout_ms:         IN: per-call timeout, see SDXI_KEY_TIMEOUT_DEFAULT.
 * @nkeys:              IN: number of entries to write.
 * @cst_flags:          OUT: reserved for SDXI_KEY_CST_F_* completion bits;
 *                      none defined yet. Kernel writes zero; userspace
 *                      must ignore unknown bits.
 * @commit_state:       OUT: enum sdxi_key_commit_state.
 * @first_failed_index: OUT: valid only when @commit_state ==
 *                      SDXI_KEY_COMMIT_PARTIAL.
 * @rsvd0:              reserved, must be zero.
 * @entries:            IN: entries to commit, written to the table in
 *                      order. On partial failure, userspace can retry
 *                      starting from @first_failed_index without
 *                      re-issuing earlier entries. After updating the
 *                      software table, the driver implicitly submits
 *                      the matching DSC_{R,A}KEY_UPD followed by
 *                      DSC_SYNC so userspace does not need separate
 *                      admin update/sync ioctls.
 */
struct sdxi_set_keys_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u32 timeout_ms;			/* in */
	__u32 nkeys;				/* in */

	__u32 cst_flags;			/* out */
	__u32 commit_state;			/* out */
	__u32 first_failed_index;		/* out */
	__u32 rsvd0[5];				/* reserved */

	struct sdxi_key_entry entries[];	/* in */
};

/**********************/
/* CONTEXT MANAGEMENT */
/**********************/
/**
 * struct sdxi_create_cxt_args - argument for SDXI_CREATE_CXT.
 * @argsz:              IN/OUT: size of this struct in bytes.
 * @flags:              IN: must be zero.
 * @opb_000_enb:        IN/OUT: requested operation-group enable mask for the
 *                      context, using the raw SDXI opb_000 bit positions used
 *                      by MMIO_CAP1.opb_000_cap, MMIO_CTL2.opb_000_avl, and
 *                      CXT_L1_ENT.opb_000_enb. Bit N requests opcode type N
 *                      for opcode types 0..31. Function-assigned opcode type
 *                      values are discovered with SDXI_ADMIN_DISC. A value of
 *                      0 requests the driver default; the kernel returns the
 *                      applied raw mask.
 * @pasid:              OUT: PASID bound to the owning process/mm for this
 *                      context.
 * @ds_ring_entries:    IN/OUT: requested descriptor-ring entry count. A value
 *                      of 0 selects the driver default; the kernel returns
 *                      the actual entry count.
 * @rsvd0:              reserved, must be zero.
 * @ds_ring_base:       IN: userspace descriptor-ring base address.
 * @cxt_sts_base:       IN: userspace context-status base address.
 * @write_index_base:   IN: userspace write-index base address.
 * @doorbell_mmap_base: OUT: mmap token for this context's doorbell region.
 * @cxt_fd:             OUT: context file descriptor returned on success.
 * @rsvd1:              reserved, must be zero.
 *
 * Issued on the device fd to create a new userspace context. On success the
 * driver has already programmed the context hierarchy, started the context,
 * and issued an internal context-sync for the new context before returning
 * the resulting cxt_fd to userspace.
 */
struct sdxi_create_cxt_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u32 opb_000_enb;			/* in/out */

	__u32 pasid;				/* out */
	__u32 ds_ring_entries;			/* in/out */
	__u32 rsvd0;				/* reserved */
	__aligned_u64 ds_ring_base;		/* in */
	__aligned_u64 cxt_sts_base;		/* in */
	__aligned_u64 write_index_base;		/* in */
	__aligned_u64 doorbell_mmap_base;	/* out */

	__s32 cxt_fd;				/* out */
	__u32 rsvd1;				/* reserved */
};

/**
 * struct sdxi_cxt_eventfd_args - argument for SDXI_CXT_EVENTFD.
 * @argsz:     IN/OUT: size of this struct in bytes.
 * @flags:     IN: must be zero.
 * @eventfd:   IN: eventfd file descriptor used for context interrupt
 *             delivery. A negative value disables the current binding.
 * @intr_akey: OUT: driver-reserved AKey slot used for userspace interrupt
 *             delivery when a binding is active; zero when disabled.
 * @rsvd0:     reserved, must be zero.
 * @intr_num:  OUT: MSI/MSI-X message/vector assigned to this context when a
 *             binding is active; zero when disabled.
 * @rsvd1:     reserved, must be zero.
 *
 * Issued on a context fd returned by SDXI_CREATE_CXT. Binds or unbinds the
 * userspace eventfd used for context interrupts (for example DSC_INTR).
 */
struct sdxi_cxt_eventfd_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__s32 eventfd;				/* in */
	__u16 intr_akey;			/* out */
	__u16 rsvd0;				/* reserved */
	__u32 intr_num;				/* out */

	__u32 rsvd1[4];				/* reserved */
};

/* @timeout_ms sentinel: 0 selects the driver default. */
#define SDXI_CXT_QUIESCE_TIMEOUT_DEFAULT	0U

/**
 * struct sdxi_quiesce_cxt_args - argument for SDXI_QUIESCE_CXT.
 * @argsz:      IN/OUT: size of this struct in bytes.
 * @flags:      IN: must be zero.
 * @timeout_ms: IN: timeout in milliseconds, or
 *              SDXI_CXT_QUIESCE_TIMEOUT_DEFAULT (0) for the driver default.
 * @cst_flags:  OUT: completion status flags returned by the stop-sync path.
 *
 * Issued on a context fd returned by SDXI_CREATE_CXT. Synchronously stops
 * the context so no further DMA traffic is expected from it. The driver
 * issues the internal stop plus stop-sync sequence before reporting success.
 * The ioctl does not destroy the context; close(2) drops the userspace
 * handle and the driver completes final cleanup once the context is
 * quiesced and no context mappings remain.
 */
struct sdxi_quiesce_cxt_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u32 timeout_ms;			/* in */
	__u32 cst_flags;			/* out */
};

/******************/
/* ADMIN DSC_DISC */
/******************/
/* @timeout_ms sentinel for admin ioctls: 0 selects the driver default. */
#define SDXI_ADMIN_TIMEOUT_DEFAULT	0U

/**
 * struct sdxi_admin_range - inclusive 16-bit range for admin ioctls.
 * @start: IN: first index in the range.
 * @end:   IN: last index in the range.
 */
struct sdxi_admin_range {
	__u16 start;				/* in */
	__u16 end;				/* in */
};

/**
 * struct sdxi_admin_disc_args - argument for SDXI_ADMIN_DISC.
 * @argsz:      IN/OUT: size of this struct in bytes.
 * @flags:      IN: SDXI_ADMIN_DISC_F_* (none defined yet); must be zero.
 * @timeout_ms: IN: per-call timeout, see SDXI_ADMIN_TIMEOUT_DEFAULT.
 * @cst_flags:  OUT: reserved for SDXI_ADMIN_DISC_CST_F_* completion bits;
 *              none defined yet. Kernel writes zero; userspace must
 *              ignore unknown bits.
 * @index:      IN: inclusive [start, end] discovery index range.
 * @buf_size:   IN: bytes available at @buf_uptr; OUT: bytes the kernel
 *              would have written.
 * @buf_uptr:   IN: userspace VA of the result buffer.
 * @rsvd0:      reserved, must be zero.
 *
 * Issues an SDXI discovery command on the device's admin context and
 * copies the resulting records describing installed components for the
 * requested index range into @buf_uptr. This read-only discovery ioctl is
 * valid only on the device fd and is supported only on SDXI 1.1+ devices.
 * It is available to callers that can open the delegated device node;
 * discovering an operation group does not by itself authorize a context to
 * enable or submit that operation group.
 *
 * If @buf_size on input is smaller than the required size, the ioctl
 * returns -ENOSPC, leaves @buf_uptr untouched, and updates @buf_size so
 * the caller can resize and retry.
 */
struct sdxi_admin_disc_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u32 timeout_ms;			/* in */
	__u32 cst_flags;			/* out */

	struct sdxi_admin_range index;		/* in */

	__u32 buf_size;				/* in/out */
	__aligned_u64 buf_uptr;			/* in */

	__u32 rsvd0[6];				/* reserved */
};

/**************************/
/* ADMIN VENDOR OPERATION */
/**************************/
/* Reserved opcode for SDXI_ADMIN_VENDOR capability probing. */
#define SDXI_ADMIN_VENDOR_PROBE		0U

/**
 * struct sdxi_admin_vendor_args - argument for SDXI_ADMIN_VENDOR.
 * @argsz:      IN/OUT: size of this struct in bytes.
 * @flags:      IN: SDXI_ADMIN_VENDOR_F_* (none defined yet); must be zero.
 * @guid:       IN: 16-byte vendor feature GUID, as returned by
 *              SDXI_ADMIN_DISC for an opcode type implementing this
 *              feature. Stored in SDXI spec discovery record byte order;
 *              userspace passes the bytes verbatim.
 * @op:         IN: vendor-defined operation. SDXI_ADMIN_VENDOR_PROBE is
 *              reserved for capability probing (see below).
 * @timeout_ms: IN: per-call timeout, see SDXI_ADMIN_TIMEOUT_DEFAULT.
 * @cst_flags:  OUT: reserved for SDXI_ADMIN_VENDOR_CST_F_* completion bits;
 *              none defined yet. Kernel writes zero; userspace must
 *              ignore unknown bits.
 * @rsvd0:      reserved, must be zero.
 * @in_uptr:    IN: userspace VA of structured input (0 if unused).
 * @in_size:    IN: input size in bytes (0 if unused).
 * @rsvd1:      reserved, must be zero.
 * @out_uptr:   IN: userspace VA of the output buffer (0 if unused).
 * @out_size:   IN: bytes available at @out_uptr; OUT: bytes required.
 * @rsvd2:      reserved, must be zero.
 *
 * Typed transport for the SDXI vendor operation group. The kernel never
 * accepts a wire descriptor from userspace: the caller passes (@guid,
 * @op, structured input, output buffer); the kernel-resident vendor
 * handler composes the SDXI descriptor, submits it on the device's admin
 * context, and copies decoded results back. Reserved descriptor bits,
 * function-targeting bits, and the completion-status block are not under
 * userspace control.
 *
 * Privilege:
 *   Holding the device fd is required. Per-op privilege escalation
 *   is enforced by the vendor handler. Read-only telemetry ops MAY be
 *   allowed without CAP_SYS_ADMIN at the handler's discretion.
 *
 * Discovery:
 *   1. SDXI_ADMIN_DISC enumerates vendor GUIDs installed on the device.
 *   2. SDXI_ADMIN_VENDOR with @op == SDXI_ADMIN_VENDOR_PROBE returns 0 if the
 *      kernel has a registered handler for @guid on this device, or
 *      -EOPNOTSUPP otherwise. PROBE has no in/out payload.
 *   3. Per-op input/output schemas are vendor-specific.
 *
 * Output buffer sizing:
 *   Pass @out_size = 0 to learn the required size; the ioctl returns
 *   -ENOSPC, updates @out_size, and leaves @out_uptr untouched. If
 *   @out_size is non-zero but smaller than required, the ioctl behaves
 *   the same way.
 *
 * Return:
 *   0          - descriptor completed; @out_uptr contains valid data.
 *   -ENOSPC    - @out_size too small; @out_size updated, @out_uptr
 *                untouched.
 *   -EIO       - device reported a CSB error; @cst_flags may carry
 *                vendor-specific details.
 *   -ETIMEDOUT - submission may have reached the device but the kernel
 *                could not confirm completion; callers should treat
 *                device state as undefined and may retry idempotent ops.
 *   other      - request was rejected before submission; device state
 *                is unchanged.
 */
struct sdxi_admin_vendor_args {
	__u32 argsz;				/* in/out */
	__u32 flags;				/* in */

	__u8  guid[16];				/* in */

	__u32 op;				/* in */
	__u32 timeout_ms;			/* in */

	__u32 cst_flags;			/* out */
	__u32 rsvd0;				/* reserved */

	__aligned_u64 in_uptr;			/* in */
	__u32 in_size;				/* in */
	__u32 rsvd1;				/* reserved */

	__aligned_u64 out_uptr;			/* in */
	__u32 out_size;				/* in/out */
	__u32 rsvd2[7];				/* reserved */
};

/*******************/
/* IOCTL FUNCTIONS */
/*******************/
#define SDXI_IOCTL_BASE 'S'
#define SDXI_IO(nr)			_IO(SDXI_IOCTL_BASE, nr)
#define SDXI_IOR(nr, type)		_IOR(SDXI_IOCTL_BASE, nr, type)
#define SDXI_IOW(nr, type)		_IOW(SDXI_IOCTL_BASE, nr, type)
#define SDXI_IOWR(nr, type)		_IOWR(SDXI_IOCTL_BASE, nr, type)

#define SDXI_GET_UAPI_INFO			\
		SDXI_IOWR(0x01, struct sdxi_uapi_info_args)
#define SDXI_GET_DEV_INFO			\
		SDXI_IOWR(0x02, struct sdxi_dev_info_args)
#define SDXI_GET_DEV_ATTR			\
		SDXI_IOWR(0x03, struct sdxi_dev_attr_args)
#define SDXI_SET_DEV_ATTR			\
		SDXI_IOWR(0x04, struct sdxi_dev_attr_args)
#define SDXI_GET_RKEY_LIST			\
		SDXI_IOWR(0x05, struct sdxi_key_list_args)
#define SDXI_GET_RKEYS				\
		SDXI_IOWR(0x06, struct sdxi_get_keys_args)
#define SDXI_SET_RKEYS				\
		SDXI_IOWR(0x07, struct sdxi_set_keys_args)
#define SDXI_CREATE_CXT				\
		SDXI_IOWR(0x08, struct sdxi_create_cxt_args)
#define SDXI_CXT_EVENTFD			\
		SDXI_IOWR(0x09, struct sdxi_cxt_eventfd_args)
#define SDXI_GET_AKEY_LIST			\
		SDXI_IOWR(0x0A, struct sdxi_key_list_args)
#define SDXI_GET_AKEYS				\
		SDXI_IOWR(0x0B, struct sdxi_get_keys_args)
#define SDXI_SET_AKEYS				\
		SDXI_IOWR(0x0C, struct sdxi_set_keys_args)
#define SDXI_ADMIN_DISC				\
		SDXI_IOWR(0x0D, struct sdxi_admin_disc_args)
#define SDXI_ADMIN_VENDOR			\
		SDXI_IOWR(0x0E, struct sdxi_admin_vendor_args)
#define SDXI_QUIESCE_CXT			\
		SDXI_IOWR(0x0F, struct sdxi_quiesce_cxt_args)

#endif /* __LINUX_SDXI_H */

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_SDXI_H
#define __LINUX_SDXI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define SDXI_MAJOR_VERSION	0
#define SDXI_MINOR_VERSION	1

struct sdxi_get_version_args {
	__u32 major_version;		/* from SDXI */
	__u32 minor_version;		/* from SDXI */
};

/* For sdxi_get_dev_info_args.dev_supported_op_grps */
#define SDXI_DMA_OP_GROUP	(1U << 0)
#define SDXI_ADMIN_OP_GROUP	(1U << 1)
#define SDXI_ATOMIC_OP_GROUP	(1U << 2)
#define SDXI_INTR_OP_GROUP	(1U << 3)
#define SDXI_CONN_OP_GROUP	(1U << 4)
#define SDXI_VENDOR_OP_GROUP	(1U << 5)

struct sdxi_get_dev_info_args {
	__u32 dev_max_buff_size;	/* from SDXI */
	__u64 dev_supported_op_grps;	/* from SDXI */
	__u32 cxt_max_ring_entries;	/* from SDXI */
	__u32 cxt_max_akey_entries;	/* from SDXI */
};

/* For sdxi_create_cxt_args.cxt_type */
#define SDXI_CXT_TYPE_USER	0x0
#define SDXI_CXT_TYPE_KERNEL	0x1

struct sdxi_create_cxt_args {
	__u32 cxt_type;			/* to SDXI */
	__u32 ring_entries;		/* to/from SDXI */

	__u32 cxt_id;			/* from SDXI */
	__u32 pasid;			/* from SDXI */
	__u64 cxt_status_mmap_base;	/* from SDXI */
	__u64 desc_ring_mmap_base;	/* from SDXI */
	__u64 write_index_mmap_base;	/* from SDXI */
	__u64 doorbell_mmap_base;	/* from SDXI */
};

struct sdxi_close_cxt_args {
	__u32 cxt_id;			/* to SDXI */
	__u32 pad;
};

#define SDXI_IOCTL_BASE 'S'
#define SDXI_IO(nr)			_IO(SDXI_IOCTL_BASE, nr)
#define SDXI_IOR(nr, type)		_IOR(SDXI_IOCTL_BASE, nr, type)
#define SDXI_IOW(nr, type)		_IOW(SDXI_IOCTL_BASE, nr, type)
#define SDXI_IOWR(nr, type)		_IOWR(SDXI_IOCTL_BASE, nr, type)

#define SDXI_GET_VERSION			\
		SDXI_IOR(0x01, struct sdxi_get_version_args)

#define SDXI_GET_DEV_INFO			\
		SDXI_IOR(0x02, struct sdxi_get_dev_info_args)

#define SDXI_CREATE_CXT			\
		SDXI_IOWR(0x03, struct sdxi_create_cxt_args)

#define SDXI_CLOSE_CXT				\
		SDXI_IOWR(0x04, struct sdxi_close_cxt_args)

#endif /* __LINUX_SDXI_H */

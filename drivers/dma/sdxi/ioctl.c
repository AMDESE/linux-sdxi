// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI character device support.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/cdev.h>
#include <linux/bitfield.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/anon_inodes.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uuid.h>
#include <uapi/linux/sdxi.h>

#include "admin.h"
#include "context.h"
#include "intr.h"
#include "ioctl.h"
#include "keys.h"
#include "mmio.h"
#include "process.h"
#include "sdxi.h"
#include "sysfs.h"
#include "vendor.h"

#define SDXI_MAX_MINORS	256

static dev_t sdxi_devt;
static struct class *sdxi_class;
static DEFINE_IDA(sdxi_minor_ida);
static const struct file_operations sdxi_cxt_fops;

static void sdxi_cxt_vma_open_cb(struct vm_area_struct *vma)
{
	sdxi_cxt_vma_open(vma->vm_private_data);
}

static void sdxi_cxt_vma_close_cb(struct vm_area_struct *vma)
{
	sdxi_cxt_vma_close(vma->vm_private_data);
}

static const struct vm_operations_struct sdxi_cxt_vm_ops = {
	.open = sdxi_cxt_vma_open_cb,
	.close = sdxi_cxt_vma_close_cb,
};

static void sdxi_cxt_vma_attach(struct vm_area_struct *vma,
				struct sdxi_cxt *cxt)
{
	vma->vm_ops = &sdxi_cxt_vm_ops;
	vma->vm_private_data = cxt;
}

static int sdxi_file_check_owner(const struct sdxi_process *process)
{
	if (process->lead_thread != current->group_leader ||
	    process->mm != current->mm)
		return -EBADF;

	return 0;
}

static int sdxi_ioctl_get_uapi_info(struct file *file, struct sdxi_file *sf,
				    void *data)
{
	struct sdxi_uapi_info_args *args = data;

	if (args->argsz < sizeof(*args) || args->flags || args->rsvd0)
		return -EINVAL;

	*args = (typeof(*args)) {
		.argsz = sizeof(*args),
		.uapi_major = SDXI_UAPI_MAJOR,
		.uapi_minor = SDXI_UAPI_MINOR,
		.cap_words = SDXI_UAPI_CAP_WORDS,
		.caps = {
			SDXI_UAPI_CAP_DEV_INFO |
			SDXI_UAPI_CAP_DEV_ATTR_MGMT |
			SDXI_UAPI_CAP_RKEY_MGMT |
			SDXI_UAPI_CAP_CXT_CREATE |
			SDXI_UAPI_CAP_CXT_EVENTFD |
			SDXI_UAPI_CAP_AKEY_MGMT |
			SDXI_UAPI_CAP_ADMIN_DISC |
			SDXI_UAPI_CAP_ADMIN_VENDOR,
		},
	};

	return 0;
}

static int sdxi_ioctl_get_dev_info(struct file *file, struct sdxi_file *sf,
				   void *data)
{
	struct sdxi_dev_info_args *args = data;
	struct sdxi_dev *sdxi = sf->process->sdxi;
	size_t i;

	if (args->argsz < sizeof(*args) || args->flags)
		return -EINVAL;
	if (args->rsvd0)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(args->rsvd1); i++)
		if (args->rsvd1[i])
			return -EINVAL;

	*args = (typeof(*args)) {
		.argsz = sizeof(*args),
		.hw_major = sdxi->sdxi_version.major,
		.hw_minor = sdxi->sdxi_version.minor,
		.cap0 = sdxi_read64(sdxi, SDXI_MMIO_CAP0),
		.cap1 = sdxi_read64(sdxi, SDXI_MMIO_CAP1),
		.sts0 = sdxi_read64(sdxi, SDXI_MMIO_STS0),
	};

	return 0;
}

enum {
	SDXI_DEV_ATTR_F_RO = BIT(0),
};

struct sdxi_dev_attr_desc {
	u32 reg;
	u64 mask;
	u32 cap_reg;
	u64 cap_mask;
	unsigned int flags;
	int (*get)(struct sdxi_dev *sdxi, u64 *value);
};

static int sdxi_dev_attr_get_rkey_entries(struct sdxi_dev *sdxi, u64 *value)
{
	*value = sdxi->rkey_cap ? sdxi->rkey_entries : 0;
	return 0;
}

static const struct sdxi_dev_attr_desc sdxi_dev_attrs[] = {
	[SDXI_DEV_ATTR_GSR] = {
		.reg = SDXI_MMIO_CTL0,
		.mask = SDXI_MMIO_CTL0_FN_GSR,
		.flags = SDXI_DEV_ATTR_F_RO,
	},
	[SDXI_DEV_ATTR_GRP_ID] = {
		.reg = SDXI_MMIO_CTL0,
		.mask = SDXI_MMIO_CTL0_FN_GRP_ID,
	},
	[SDXI_DEV_ATTR_MAX_BUFFER] = {
		.reg = SDXI_MMIO_CTL2,
		.mask = SDXI_MMIO_CTL2_MAX_BUFFER,
		.cap_reg = SDXI_MMIO_CAP1,
		.cap_mask = SDXI_MMIO_CAP1_MAX_BUFFER,
	},
	[SDXI_DEV_ATTR_MAX_AKEY_SZ] = {
		.reg = SDXI_MMIO_CTL2,
		.mask = SDXI_MMIO_CTL2_MAX_AKEY_SZ,
		.cap_reg = SDXI_MMIO_CAP1,
		.cap_mask = SDXI_MMIO_CAP1_MAX_AKEY_SZ,
	},
	[SDXI_DEV_ATTR_MAX_RKEY_SZ] = {
		.flags = SDXI_DEV_ATTR_F_RO,
		.get = sdxi_dev_attr_get_rkey_entries,
	},
	[SDXI_DEV_ATTR_MAX_CXT] = {
		.reg = SDXI_MMIO_CTL2,
		.mask = SDXI_MMIO_CTL2_MAX_CXT,
		.cap_reg = SDXI_MMIO_CAP1,
		.cap_mask = SDXI_MMIO_CAP1_MAX_CXT,
	},
};

static const struct sdxi_dev_attr_desc *sdxi_dev_attr_lookup(u64 attr)
{
	const struct sdxi_dev_attr_desc *desc;

	if (!attr || attr >= ARRAY_SIZE(sdxi_dev_attrs))
		return NULL;

	desc = &sdxi_dev_attrs[attr];
	if (!desc->mask && !desc->get)
		return NULL;

	return desc;
}

static int sdxi_dev_attr_read(struct sdxi_dev *sdxi,
			      const struct sdxi_dev_attr_desc *desc, u64 *value)
{
	unsigned int shift;

	if (desc->get)
		return desc->get(sdxi, value);

	shift = __ffs64(desc->mask);
	*value = (sdxi_read64(sdxi, desc->reg) & desc->mask) >> shift;
	return 0;
}

static int sdxi_dev_attr_write(struct sdxi_dev *sdxi,
			       const struct sdxi_dev_attr_desc *desc, u64 value)
{
	unsigned int shift;
	u64 maximum;
	u64 register_value;

	if (desc->flags & SDXI_DEV_ATTR_F_RO)
		return -EOPNOTSUPP;

	shift = __ffs64(desc->mask);
	maximum = desc->mask >> shift;
	if (value > maximum)
		return -EINVAL;

	mutex_lock(&sdxi->reg_lock);
	if (desc->cap_reg) {
		u64 capability;

		capability = (sdxi_read64(sdxi, desc->cap_reg) &
			      desc->cap_mask) >> __ffs64(desc->cap_mask);
		if (value > capability) {
			mutex_unlock(&sdxi->reg_lock);
			return -EINVAL;
		}
	}

	register_value = sdxi_read64(sdxi, desc->reg);
	register_value &= ~desc->mask;
	register_value |= (value << shift) & desc->mask;
	sdxi_write64(sdxi, desc->reg, register_value);
	if (desc == &sdxi_dev_attrs[SDXI_DEV_ATTR_MAX_BUFFER]) {
		WRITE_ONCE(sdxi->max_buffer, (u8)value);
		dma_set_max_seg_size(sdxi->dev,
				     min((u64)SZ_2M << value, (u64)U32_MAX));
	} else if (desc == &sdxi_dev_attrs[SDXI_DEV_ATTR_MAX_CXT]) {
		WRITE_ONCE(sdxi->max_cxtid, (u16)value);
	}
	mutex_unlock(&sdxi->reg_lock);
	return 0;
}

static bool sdxi_dev_attr_args_valid(const struct sdxi_dev_attr_args *args)
{
	size_t i;

	if (args->argsz < sizeof(*args) || args->flags)
		return false;
	for (i = 0; i < ARRAY_SIZE(args->rsvd0); i++)
		if (args->rsvd0[i])
			return false;

	return true;
}

static int sdxi_ioctl_get_dev_attr(struct file *file, struct sdxi_file *sf,
				   void *data)
{
	struct sdxi_dev_attr_args *args = data;
	const struct sdxi_dev_attr_desc *desc;
	int ret;

	if (!sdxi_dev_attr_args_valid(args))
		return -EINVAL;

	desc = sdxi_dev_attr_lookup(args->attr);
	if (!desc)
		return -EOPNOTSUPP;

	ret = sdxi_dev_attr_read(sf->process->sdxi, desc, &args->val);
	if (!ret)
		args->argsz = sizeof(*args);
	return ret;
}

static int sdxi_ioctl_set_dev_attr(struct file *file, struct sdxi_file *sf,
				   void *data)
{
	struct sdxi_dev_attr_args *args = data;
	const struct sdxi_dev_attr_desc *desc;
	int ret;

	if (!sdxi_dev_attr_args_valid(args))
		return -EINVAL;

	desc = sdxi_dev_attr_lookup(args->attr);
	if (!desc)
		return -EOPNOTSUPP;

	ret = sdxi_dev_attr_write(sf->process->sdxi, desc, args->val);
	if (ret)
		return ret;

	args->argsz = sizeof(*args);
	return sdxi_dev_attr_read(sf->process->sdxi, desc, &args->val);
}

static bool sdxi_u32_array_zero(const u32 *values, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (values[i])
			return false;

	return true;
}

enum sdxi_op_group_policy {
	SDXI_OP_GROUP_UNKNOWN,
	SDXI_OP_GROUP_USER,
	SDXI_OP_GROUP_ADMIN_ONLY,
};

struct sdxi_op_group_policy_entry {
	guid_t guid;
	enum sdxi_op_group_policy policy;
};

static const struct sdxi_op_group_policy_entry sdxi_op_group_policy[] = {
	{ GUID_INIT(0x193259fe, 0x150b, 0x4008, 0xa8, 0x3f, 0x6f, 0xaf, 0x59,
		    0xf5, 0x27, 0x2a), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0xd9bc29a1, 0x91dc, 0x4243, 0x97, 0x51, 0xb6, 0xb0, 0x32,
		    0x9d, 0xaf, 0xe1), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x3ac7630e, 0x7009, 0x424b, 0x82, 0x99, 0x20, 0xe2, 0x90,
		    0x1e, 0xcc, 0x5e), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x7fb16347, 0x4c3a, 0x4d16, 0x84, 0x42, 0xcb, 0xa5, 0x1e,
		    0x34, 0x08, 0x80), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x0af23293, 0x7595, 0x4939, 0xb0, 0x8a, 0x1c, 0x72, 0x93,
		    0xc2, 0xe9, 0x75), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x989b9a64, 0x28d9, 0x4294, 0x9c, 0x7b, 0x9a, 0x3f, 0x27,
		    0xaf, 0xaf, 0x5c), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x15114db9, 0x4a7e, 0x47ab, 0x97, 0xdd, 0xea, 0x86, 0xed,
		    0xa1, 0x0b, 0x6e), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0xb3e551a3, 0xf1a9, 0x4c9a, 0x82, 0x52, 0xda, 0xf5, 0xc0,
		    0xd9, 0x1a, 0x44), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0x2595c4dc, 0x6fac, 0x49d2, 0xa3, 0x31, 0xb1, 0x40, 0x0a,
		    0x7f, 0x69, 0x0f), SDXI_OP_GROUP_USER },
	{ GUID_INIT(0xf5b7610b, 0x0dc6, 0x4c03, 0xab, 0x79, 0x65, 0xf1, 0xf4,
		    0xef, 0xcf, 0x4c), SDXI_OP_GROUP_ADMIN_ONLY },
};

static enum sdxi_op_group_policy
sdxi_op_group_lookup(const guid_t *guid)
{
	size_t i;

	if (guid_is_null(guid))
		return SDXI_OP_GROUP_UNKNOWN;

	for (i = 0; i < ARRAY_SIZE(sdxi_op_group_policy); i++)
		if (guid_equal(guid, &sdxi_op_group_policy[i].guid))
			return sdxi_op_group_policy[i].policy;

	return SDXI_OP_GROUP_UNKNOWN;
}

#define SDXI_DISC_TIMEOUT_MS	5000U

static int sdxi_discover_user_op_groups(struct sdxi_dev *sdxi, u32 available,
					u32 *allowed, u32 *denied)
{
	const u16 first = 1;
	const u16 last = 31;
	const size_t record_size = sizeof(guid_t);
	const size_t size = (last - first + 1) * record_size;
	dma_addr_t dma;
	u8 *records;
	u16 index;
	int ret;

	if (!sdxi_dev_compatible(sdxi, SDXI_VERSION_1_1) ||
	    !(available & SDXI_OPB_000_DISC_MASK))
		return 0;

	records = dma_alloc_coherent(sdxi->dev, size, &dma, GFP_KERNEL);
	if (!records)
		return -ENOMEM;

	ret = sdxi_adm_disc(sdxi, first, last, dma, SDXI_DISC_TIMEOUT_MS,
			    NULL);
	if (ret)
		goto free_records;

	dma_rmb();
	for (index = first; index <= last; index++) {
		enum sdxi_op_group_policy policy;
		guid_t guid;
		u32 bit = BIT(index);

		if (!(available & bit))
			continue;

		import_guid(&guid, records + (index - first) * record_size);
		policy = sdxi_op_group_lookup(&guid);
		if (policy == SDXI_OP_GROUP_USER)
			*allowed |= bit;
		else if (policy == SDXI_OP_GROUP_ADMIN_ONLY)
			*denied |= bit;
	}

free_records:
	dma_free_coherent(sdxi->dev, size, records, dma);
	return ret;
}

static int sdxi_user_op_groups(struct sdxi_dev *sdxi, u32 requested,
			       u32 *applied)
{
	u32 available;
	u32 allowed;
	u32 denied = SDXI_OPB_000_ADMIN;
	bool use_default = !requested;
	int ret;

	available = FIELD_GET(SDXI_MMIO_CTL2_OPB_000_AVL,
			      sdxi_read64(sdxi, SDXI_MMIO_CTL2));
	allowed = available & SDXI_OPB_000_INTR;
	if (sdxi->atomic_ops_enabled)
		allowed |= available & SDXI_OPB_000_ATOMIC;

	ret = sdxi_discover_user_op_groups(sdxi, available, &allowed,
					   &denied);
	if (ret && !use_default &&
	    (requested & SDXI_OPB_000_DISC_MASK))
		return ret;

	if (use_default)
		requested = allowed;
	if (requested & denied)
		return -EPERM;
	if (requested & ~available)
		return -EINVAL;
	if ((requested & SDXI_OPB_000_ATOMIC) &&
	    !sdxi->atomic_ops_enabled)
		return -EOPNOTSUPP;
	if (requested & ~allowed)
		return -EOPNOTSUPP;

	*applied = requested;
	return 0;
}

static int sdxi_ioctl_create_cxt(struct file *file, struct sdxi_file *sf,
				 void *data)
{
	struct sdxi_create_cxt_args *args = data;
	struct sdxi_process *process = sf->process;
	struct iommu_sva *unbind_sva = NULL;
	struct sdxi_file *cxt_sf = NULL;
	struct sdxi_cxt *cxt = NULL;
	struct file *cxt_file;
	u32 unbind_pasid = 0;
	u32 ring_entries;
	u32 op_groups;
	size_t ring_bytes;
	bool bound = false;
	u16 akey_flags;
	int cxt_fd;
	int ret;

	if (args->argsz < sizeof(*args) || args->flags)
		return -EINVAL;
	if (process->sdxi->db_stride < PAGE_SIZE ||
	    !IS_ALIGNED(process->sdxi->db_stride, PAGE_SIZE))
		return -EOPNOTSUPP;

	ret = sdxi_user_op_groups(process->sdxi, args->opb_000_enb,
				  &op_groups);
	if (ret)
		return ret;

	ring_entries = args->ds_ring_entries ?: SZ_1K;
	if (ring_entries < SZ_1K ||
	    ring_entries > process->sdxi->max_ring_entries)
		return -EINVAL;
	if (check_mul_overflow((size_t)ring_entries,
			       sizeof(struct sdxi_desc), &ring_bytes))
		return -EOVERFLOW;

	if (!args->ds_ring_base || !args->write_index_base ||
	    !args->cxt_sts_base)
		return -EINVAL;
	if (!IS_ALIGNED(args->ds_ring_base,
			BIT_ULL(DESC_RING_BASE_PTR_SHIFT)) ||
	    !IS_ALIGNED(args->write_index_base,
			BIT_ULL(WRT_INDEX_PTR_SHIFT)) ||
	    !IS_ALIGNED(args->cxt_sts_base,
			BIT_ULL(CXT_STATUS_PTR_SHIFT)))
		return -EINVAL;
	if (!access_ok(u64_to_user_ptr(args->ds_ring_base), ring_bytes) ||
	    !access_ok(u64_to_user_ptr(args->write_index_base),
		       sizeof(__le64)) ||
	    !access_ok(u64_to_user_ptr(args->cxt_sts_base),
		       sizeof(struct sdxi_cxt_sts)))
		return -EFAULT;

	if (clear_user(u64_to_user_ptr(args->write_index_base),
		       sizeof(__le64)) ||
	    clear_user(u64_to_user_ptr(args->cxt_sts_base),
		       sizeof(struct sdxi_cxt_sts)))
		return -EFAULT;

	mutex_lock(&process->mutex);
	if (process->cxt) {
		ret = -EBUSY;
		goto out_unlock;
	}

	if (!process->sva) {
		ret = sdxi_process_bind(process);
		if (ret)
			goto out_unlock;
		bound = true;
	}
	if (!FIELD_FIT(SDXI_AKEY_ENT_PASID, process->pasid)) {
		ret = -ERANGE;
		goto out_unbind;
	}

	cxt = sdxi_ucxt_new(process->sdxi, ring_entries,
			    args->ds_ring_base, args->write_index_base,
			    args->cxt_sts_base, process->pasid, op_groups);
	if (!cxt) {
		ret = -ENOMEM;
		goto out_unbind;
	}

	/* Subsequent failure cleanup now owns the context and SVA lifetime. */
	cxt->process = process;
	process->cxt = cxt;
	sdxi_process_get(process);

	akey_flags = SDXI_AKEY_ENT_VL | SDXI_AKEY_ENT_PV;
	cxt->akey_table->entry[1] = (struct sdxi_akey_ent) {
		.intr_num = cpu_to_le16(akey_flags),
		.pasid = cpu_to_le32(FIELD_PREP(SDXI_AKEY_ENT_PASID,
						process->pasid)),
	};
	dma_wmb();

	if (op_groups & SDXI_OPB_000_INTR) {
		ret = sdxi_cxt_init_intr(cxt);
		if (ret)
			goto out_exit_cxt;
	}

	ret = sdxi_adm_start_cxt(cxt);
	if (ret)
		goto out_exit_cxt;

	cxt_sf = kzalloc_obj(*cxt_sf, GFP_KERNEL);
	if (!cxt_sf) {
		ret = -ENOMEM;
		goto out_exit_cxt;
	}

	cxt_sf->type = SDXI_FILE_CONTEXT;
	cxt_sf->process = process;
	cxt_sf->cxt = cxt;

	cxt_fd = get_unused_fd_flags(O_CLOEXEC);
	if (cxt_fd < 0) {
		ret = cxt_fd;
		goto out_exit_cxt;
	}

	cxt_file = anon_inode_create_getfile("sdxi-context", &sdxi_cxt_fops,
					     cxt_sf, O_RDWR, NULL);
	if (IS_ERR(cxt_file)) {
		put_unused_fd(cxt_fd);
		ret = PTR_ERR(cxt_file);
		goto out_exit_cxt;
	}
	cxt->mapping_inode = file_inode(cxt_file);
	ihold(cxt->mapping_inode);

	sdxi_process_get(process);
	sdxi_cxt_get(cxt);
	fd_install(cxt_fd, cxt_file);

	*args = (typeof(*args)) {
		.argsz = sizeof(*args),
		.opb_000_enb = op_groups,
		.pasid = process->pasid,
		.ds_ring_entries = ring_entries,
		.ds_ring_base = args->ds_ring_base,
		.cxt_sts_base = args->cxt_sts_base,
		.write_index_base = args->write_index_base,
		.doorbell_mmap_base =
			sdxi_mmap_token(SDXI_MMAP_TYPE_DOORBELL, cxt->id,
					cxt->mmap_gen),
		.cxt_fd = cxt_fd,
	};
	mutex_unlock(&process->mutex);
	return 0;

out_exit_cxt:
	mutex_unlock(&process->mutex);
	sdxi_cxt_abort(cxt);
	kfree(cxt_sf);
	return ret;
out_unbind:
	if (bound)
		unbind_sva = sdxi_process_detach_sva_locked(process,
							    &unbind_pasid);
out_unlock:
	mutex_unlock(&process->mutex);
	if (unbind_sva)
		sdxi_process_unbind_sva(process, unbind_sva, unbind_pasid);
	kfree(cxt_sf);
	return ret;
}

static int sdxi_ioctl_cxt_eventfd(struct file *file, struct sdxi_file *sf,
				  void *data)
{
	struct sdxi_cxt_eventfd_args *args = data;
	int ret;

	if (args->argsz < sizeof(*args) || args->flags || args->rsvd0 ||
	    !sdxi_u32_array_zero(args->rsvd1, ARRAY_SIZE(args->rsvd1)))
		return -EINVAL;
	if (!sf->cxt)
		return -ENODEV;

	ret = sdxi_cxt_set_intr_fd(sf->cxt, args->eventfd,
				   &args->intr_akey, &args->intr_num);
	if (!ret)
		args->argsz = sizeof(*args);
	return ret;
}

static int sdxi_ioctl_quiesce_cxt(struct file *file, struct sdxi_file *sf,
				  void *data)
{
	struct sdxi_quiesce_cxt_args *args = data;
	int ret;

	if (args->argsz < sizeof(*args) || args->flags)
		return -EINVAL;
	if (!sf->cxt)
		return -ENODEV;

	ret = sdxi_cxt_quiesce(sf->cxt, args->timeout_ms,
			       &args->cst_flags);
	if (!ret)
		args->argsz = sizeof(*args);
	return ret;
}

static int sdxi_ioctl_admin_disc(struct file *file, struct sdxi_file *sf,
				 void *data)
{
	struct sdxi_admin_disc_args *args = data;
	size_t required;
	dma_addr_t dma;
	void *buffer;
	u16 start;
	u16 end;
	u32 timeout_ms;
	int ret;

	if (args->argsz < sizeof(*args) || args->flags ||
	    !sdxi_u32_array_zero(args->rsvd0, ARRAY_SIZE(args->rsvd0)))
		return -EINVAL;
	if (!sdxi_dev_compatible(sf->process->sdxi, SDXI_VERSION_1_1))
		return -EOPNOTSUPP;

	start = args->index.start;
	end = args->index.end;
	if (start > end || end > 2047)
		return -EINVAL;

	required = (size_t)(end - start + 1) * sizeof(guid_t);
	args->argsz = sizeof(*args);
	args->cst_flags = 0;
	if (args->buf_size < required) {
		args->buf_size = required;
		return -ENOSPC;
	}
	if (!args->buf_uptr)
		return -EINVAL;

	buffer = dma_alloc_coherent(sf->process->sdxi->dev, required, &dma,
				    GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	timeout_ms = args->timeout_ms ?: SDXI_DISC_TIMEOUT_MS;
	if (!capable(CAP_SYS_ADMIN))
		timeout_ms = min(timeout_ms, SDXI_DISC_TIMEOUT_MS);
	ret = sdxi_adm_disc(sf->process->sdxi, start, end, dma,
			    timeout_ms, &args->cst_flags);
	if (!ret) {
		dma_rmb();
		if (copy_to_user(u64_to_user_ptr(args->buf_uptr), buffer,
				 required))
			ret = -EFAULT;
	}

	dma_free_coherent(sf->process->sdxi->dev, required, buffer, dma);
	args->buf_size = required;
	return ret;
}

static bool
sdxi_admin_vendor_reserved_zero(const struct sdxi_admin_vendor_args *args)
{
	return !args->flags && !args->rsvd0 && !args->rsvd1 &&
	       sdxi_u32_array_zero(args->rsvd2, ARRAY_SIZE(args->rsvd2));
}

static unsigned int sdxi_admin_timeout(u32 timeout_ms)
{
	return clamp_val(timeout_ms ?: 5000U, 1U, 60000U);
}

static int sdxi_ioctl_admin_vendor(struct file *file, struct sdxi_file *sf,
				   void *data)
{
	struct sdxi_admin_vendor_args *args = data;
	const struct sdxi_vendor_handler *handler;
	struct sdxi_dev *sdxi = sf->process->sdxi;
	unsigned int timeout_ms;
	u16 opcode_type;
	int ret;

	if (args->argsz < sizeof(*args) ||
	    !sdxi_admin_vendor_reserved_zero(args))
		return -EINVAL;

	args->argsz = sizeof(*args);
	args->cst_flags = 0;
	timeout_ms = sdxi_admin_timeout(args->timeout_ms);

	ret = sdxi_vendor_get(args->guid, &handler);
	if (ret)
		return ret;

	ret = sdxi_vendor_find_opcode_type(sdxi, args->guid, timeout_ms,
					   &opcode_type);
	if (ret)
		goto put_handler;

	if (args->op == SDXI_ADMIN_VENDOR_PROBE) {
		if (args->in_size || args->in_uptr ||
		    args->out_size || args->out_uptr)
			ret = -EINVAL;
		goto put_handler;
	}

	ret = handler->ops->exec(sdxi, opcode_type, args, timeout_ms);

put_handler:
	sdxi_vendor_put(handler);
	return ret;
}

#define SDXI_IOCTL_DEF(_nr, _cmd, _func, _files, _access)	\
	[_nr] = {						\
		.cmd = (_cmd),					\
		.file_flags = (_files),				\
		.access = (_access),				\
		.func = (_func),					\
	}

static const struct sdxi_ioctl_desc sdxi_ioctls[] = {
	SDXI_IOCTL_DEF(0x01, SDXI_GET_UAPI_INFO, sdxi_ioctl_get_uapi_info,
		       SDXI_IOCTL_F_DEVICE | SDXI_IOCTL_F_CONTEXT,
		       SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x02, SDXI_GET_DEV_INFO, sdxi_ioctl_get_dev_info,
		       SDXI_IOCTL_F_DEVICE | SDXI_IOCTL_F_CONTEXT,
		       SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x03, SDXI_GET_DEV_ATTR, sdxi_ioctl_get_dev_attr,
		       SDXI_IOCTL_F_DEVICE | SDXI_IOCTL_F_CONTEXT,
		       SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x04, SDXI_SET_DEV_ATTR, sdxi_ioctl_set_dev_attr,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x05, SDXI_GET_RKEY_LIST, sdxi_ioctl_get_rkey_list,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x06, SDXI_GET_RKEYS, sdxi_ioctl_get_rkeys,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x07, SDXI_SET_RKEYS, sdxi_ioctl_set_rkeys,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x08, SDXI_CREATE_CXT, sdxi_ioctl_create_cxt,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x09, SDXI_CXT_EVENTFD, sdxi_ioctl_cxt_eventfd,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0a, SDXI_GET_AKEY_LIST, sdxi_ioctl_get_akey_list,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0b, SDXI_GET_AKEYS, sdxi_ioctl_get_akeys,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0c, SDXI_SET_AKEYS, sdxi_ioctl_set_akeys,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0d, SDXI_ADMIN_DISC, sdxi_ioctl_admin_disc,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x0e, SDXI_ADMIN_VENDOR, sdxi_ioctl_admin_vendor,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_VENDOR_HANDLER),
	SDXI_IOCTL_DEF(0x0f, SDXI_QUIESCE_CXT, sdxi_ioctl_quiesce_cxt,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
};

static int sdxi_ioctl_pre_permit(const struct sdxi_ioctl_desc *desc)
{
	if (desc->access == SDXI_IOCTL_A_ADMIN_DEVICE)
		return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;

	return 0;
}

static int sdxi_ioctl_permit(const struct sdxi_ioctl_desc *desc,
			     struct sdxi_file *sf, void *data)
{
	const struct sdxi_vendor_handler *handler;
	struct sdxi_admin_vendor_args *args;
	int ret;

	if (desc->access != SDXI_IOCTL_A_VENDOR_HANDLER)
		return 0;

	args = data;
	if (!args || args->argsz < sizeof(*args) ||
	    !sdxi_admin_vendor_reserved_zero(args))
		return -EINVAL;

	ret = sdxi_vendor_get(args->guid, &handler);
	if (ret)
		return ret;
	ret = handler->ops->authorize(sf->process->sdxi, args);
	sdxi_vendor_put(handler);
	return ret;
}

static bool sdxi_ioctl_has_trailing_payload(unsigned int cmd)
{
	return cmd == SDXI_GET_RKEY_LIST || cmd == SDXI_GET_RKEYS ||
	       cmd == SDXI_SET_RKEYS || cmd == SDXI_GET_AKEY_LIST ||
	       cmd == SDXI_GET_AKEYS || cmd == SDXI_SET_AKEYS;
}

static bool sdxi_key_list_cmd(unsigned int cmd)
{
	return cmd == SDXI_GET_RKEY_LIST || cmd == SDXI_GET_AKEY_LIST;
}

static bool sdxi_key_entries_cmd(unsigned int cmd)
{
	return cmd == SDXI_GET_RKEYS || cmd == SDXI_SET_RKEYS ||
	       cmd == SDXI_GET_AKEYS || cmd == SDXI_SET_AKEYS;
}

static u32 sdxi_key_table_entries(unsigned int cmd, struct sdxi_file *sf)
{
	if (cmd == SDXI_GET_RKEY_LIST || cmd == SDXI_GET_RKEYS ||
	    cmd == SDXI_SET_RKEYS)
		return sf->process->sdxi->rkey_entries;

	if (!sf->cxt || !sf->cxt->akey_table)
		return 0;
	return ARRAY_SIZE(sf->cxt->akey_table->entry);
}

static int sdxi_key_ioctl_sizes(unsigned int cmd, struct sdxi_file *sf,
				const void *header, size_t header_size,
				size_t *copyin_size, size_t *copyout_size,
				size_t *allocation_size)
{
	size_t payload_size;
	u32 nentries;
	u32 nkeys;

	nentries = sdxi_key_table_entries(cmd, sf);

	if (sdxi_key_list_cmd(cmd)) {
		const struct sdxi_key_list_args *args = header;
		size_t required = DIV_ROUND_UP(nentries, 8);

		*copyin_size = header_size;
		*copyout_size = header_size + min_t(size_t, args->buf_size,
						    required);
		*allocation_size = *copyout_size;
		return 0;
	}

	if (cmd == SDXI_GET_RKEYS || cmd == SDXI_GET_AKEYS)
		nkeys = ((const struct sdxi_get_keys_args *)header)->nkeys;
	else
		nkeys = ((const struct sdxi_set_keys_args *)header)->nkeys;

	if (nkeys > min_t(u32, nentries, 4096))
		return -EINVAL;
	if (check_mul_overflow((size_t)nkeys, sizeof(struct sdxi_key_entry),
			       &payload_size) ||
	    check_add_overflow(header_size, payload_size, allocation_size))
		return -EOVERFLOW;

	*copyin_size = *allocation_size;
	if (cmd == SDXI_GET_RKEYS || cmd == SDXI_GET_AKEYS)
		*copyout_size = *allocation_size;
	else
		*copyout_size = header_size;
	return 0;
}

static long sdxi_ioctl_live(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	const struct sdxi_ioctl_desc *desc;
	struct sdxi_file *sf = file->private_data;
	size_t copyout_size;
	size_t copyin_size;
	unsigned int canonical_size;
	unsigned int user_size;
	size_t size;
	unsigned int nr;
	char stack_data[128];
	void *data = stack_data;
	bool header_copied = false;
	bool variable;
	bool allowed;
	int ret;

	if (_IOC_TYPE(cmd) != SDXI_IOCTL_BASE)
		return -ENOTTY;

	nr = _IOC_NR(cmd);
	if (nr >= ARRAY_SIZE(sdxi_ioctls) || !sdxi_ioctls[nr].cmd)
		return -ENOTTY;

	desc = &sdxi_ioctls[nr];
	if (_IOC_DIR(cmd) != _IOC_DIR(desc->cmd))
		return -ENOTTY;
	if (!sf || !sf->process)
		return -EINVAL;

	ret = sdxi_file_check_owner(sf->process);
	if (ret)
		return ret;

	switch (sf->type) {
	case SDXI_FILE_DEVICE:
		allowed = desc->file_flags & SDXI_IOCTL_F_DEVICE;
		break;
	case SDXI_FILE_CONTEXT:
		allowed = desc->file_flags & SDXI_IOCTL_F_CONTEXT;
		break;
	default:
		allowed = false;
		break;
	}
	if (!allowed)
		return -ENOTTY;

	ret = sdxi_ioctl_pre_permit(desc);
	if (ret)
		return ret;

	canonical_size = _IOC_SIZE(desc->cmd);
	user_size = _IOC_SIZE(cmd);
	copyin_size = (_IOC_DIR(cmd) & _IOC_WRITE) ? user_size : 0;
	copyout_size = (_IOC_DIR(cmd) & _IOC_READ) ? user_size : 0;
	size = max_t(size_t, canonical_size, user_size);

	variable = sdxi_key_list_cmd(desc->cmd) ||
		   sdxi_key_entries_cmd(desc->cmd);
	if (variable) {
		if (user_size < canonical_size)
			return -EINVAL;
		if (canonical_size > sizeof(stack_data))
			return -E2BIG;
		if (copy_from_user(stack_data, (void __user *)arg,
				   canonical_size))
			return -EFAULT;
		header_copied = true;
		ret = sdxi_key_ioctl_sizes(desc->cmd, sf, stack_data,
					   canonical_size, &copyin_size,
					   &copyout_size, &size);
		if (ret)
			return ret;
	}

	if (size > SZ_1M)
		return -E2BIG;

	if (size > sizeof(stack_data)) {
		data = kzalloc(size, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
	} else if (!header_copied) {
		memset(data, 0, size);
	} else if (size > canonical_size) {
		memset(data + canonical_size, 0, size - canonical_size);
	}

	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		if (header_copied) {
			if (data != stack_data)
				memcpy(data, stack_data, canonical_size);
			if (copyin_size > canonical_size &&
			    copy_from_user(data + canonical_size,
					   (void __user *)(arg + canonical_size),
					   copyin_size - canonical_size)) {
				ret = -EFAULT;
				goto out;
			}
		} else if (copy_from_user(data, (void __user *)arg,
					  copyin_size)) {
			ret = -EFAULT;
			goto out;
		}
	}

	ret = sdxi_ioctl_permit(desc, sf, data);
	if (ret)
		goto out;

	ret = desc->func(file, sf, data);

	if (ret == -ENOSPC && sdxi_key_list_cmd(desc->cmd))
		copyout_size = canonical_size;
	if ((_IOC_DIR(cmd) & _IOC_READ) && user_size > canonical_size &&
	    !sdxi_ioctl_has_trailing_payload(desc->cmd))
		memset((u8 *)data + canonical_size, 0,
		       user_size - canonical_size);
	if ((_IOC_DIR(cmd) & _IOC_READ) &&
	    copy_to_user((void __user *)arg, data, copyout_size))
		ret = -EFAULT;

out:
	if (data != stack_data)
		kfree(data);
	return ret;
}

static long sdxi_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sdxi_file *sf = file->private_data;
	struct sdxi_dev *sdxi;
	long ret;

	if (!sf || !sf->process)
		return -EINVAL;
	sdxi = sf->process->sdxi;

	down_read(&sdxi->state_lock);
	ret = sdxi->online ? sdxi_ioctl_live(file, cmd, arg) : -ENODEV;
	up_read(&sdxi->state_lock);
	return ret;
}

static int sdxi_mmap_live(struct file *file, struct vm_area_struct *vma)
{
	struct sdxi_file *sf = file->private_data;
	struct sdxi_cxt *cxt;
	u64 allowed_mask;
	u64 token;
	u64 type;
	u32 generation;
	int ret;

	if (!sf || sf->type != SDXI_FILE_CONTEXT || !sf->process)
		return -EINVAL;

	ret = sdxi_file_check_owner(sf->process);
	if (ret)
		return ret;

	cxt = sf->cxt;
	if (!cxt || !cxt->id)
		return -EINVAL;
	if (sdxi_cxt_is_fatal(cxt) || READ_ONCE(cxt->resources_released))
		return -ENODEV;

	token = (u64)vma->vm_pgoff << PAGE_SHIFT;
	allowed_mask = SDXI_MMAP_TYPE_MASK | SDXI_MMAP_CXT_ID_MASK |
		       SDXI_MMAP_GEN_MASK;
	if (token & ~allowed_mask)
		return -EINVAL;

	type = token & SDXI_MMAP_TYPE_MASK;
	generation = cxt->mmap_gen &
		     (SDXI_MMAP_GEN_MASK >> SDXI_MMAP_GEN_SHIFT);
	if (type != SDXI_MMAP_TYPE_DOORBELL ||
	    sdxi_mmap_token_cxt_id(token) != cxt->id ||
	    sdxi_mmap_token_gen(token) != generation)
		return -EINVAL;

	if (vma->vm_end - vma->vm_start != cxt->sdxi->db_stride)
		return -EINVAL;
	if (!(vma->vm_flags & VM_WRITE) || vma->vm_flags & VM_EXEC)
		return -EPERM;
	if (!cxt->sdxi->bus_ops->mmap_doorbell)
		return -EOPNOTSUPP;
	ret = sdxi_cxt_vma_acquire(cxt);
	if (ret)
		return ret;

	vm_flags_set(vma, VM_IO | VM_DONTCOPY | VM_DONTEXPAND |
		     VM_DONTDUMP | VM_PFNMAP);
	vm_flags_clear(vma, VM_MAYEXEC);
	vma->vm_pgoff = 0;
	ret = cxt->sdxi->bus_ops->mmap_doorbell(cxt->sdxi, cxt, vma);
	if (!ret)
		sdxi_cxt_vma_attach(vma, cxt);
	else
		sdxi_cxt_vma_close(cxt);
	return ret;
}

static int sdxi_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sdxi_file *sf = file->private_data;
	struct sdxi_dev *sdxi;
	int ret;

	if (!sf || !sf->process)
		return -EINVAL;
	sdxi = sf->process->sdxi;

	if (!down_read_trylock(&sdxi->state_lock))
		return -EAGAIN;
	ret = sdxi->online ? sdxi_mmap_live(file, vma) : -ENODEV;
	up_read(&sdxi->state_lock);
	return ret;
}

static __poll_t sdxi_cxt_poll_live(struct file *file, poll_table *wait)
{
	struct sdxi_file *sf = file->private_data;
	struct sdxi_cxt *cxt;
	__poll_t mask = 0;

	if (!sf || sf->type != SDXI_FILE_CONTEXT || !sf->process)
		return EPOLLERR;
	if (sdxi_file_check_owner(sf->process))
		return EPOLLERR;

	cxt = sf->cxt;
	if (!cxt)
		return EPOLLERR | EPOLLHUP;

	poll_wait(file, &cxt->poll_wq, wait);
	if (sdxi_cxt_is_fatal(cxt))
		mask |= EPOLLERR;
	if (READ_ONCE(cxt->resources_released))
		mask |= EPOLLHUP;

	return mask;
}

static __poll_t sdxi_cxt_poll(struct file *file, poll_table *wait)
{
	struct sdxi_file *sf = file->private_data;
	struct sdxi_dev *sdxi;
	__poll_t mask;

	if (!sf || !sf->process)
		return EPOLLERR | EPOLLHUP;
	sdxi = sf->process->sdxi;

	down_read(&sdxi->state_lock);
	mask = sdxi->online ? sdxi_cxt_poll_live(file, wait) :
			      EPOLLERR | EPOLLHUP;
	up_read(&sdxi->state_lock);
	return mask;
}

static int sdxi_open(struct inode *inode, struct file *file)
{
	struct sdxi_dev *sdxi;
	struct sdxi_process *process;
	struct sdxi_file *sf;

	if (!inode->i_cdev)
		return -ENODEV;

	sdxi = container_of(inode->i_cdev, struct sdxi_dev, cdev);
	down_read(&sdxi->state_lock);
	if (!sdxi->online) {
		up_read(&sdxi->state_lock);
		return -ENODEV;
	}
	process = sdxi_process_create(sdxi);
	up_read(&sdxi->state_lock);
	if (IS_ERR(process))
		return PTR_ERR(process);

	sf = kzalloc_obj(*sf, GFP_KERNEL);
	if (!sf) {
		sdxi_process_put(process);
		return -ENOMEM;
	}

	sf->type = SDXI_FILE_DEVICE;
	sf->process = process;
	file->private_data = sf;
	return 0;
}

static int sdxi_release(struct inode *inode, struct file *file)
{
	struct sdxi_file *sf = file->private_data;

	if (!sf)
		return 0;

	if (sf->type == SDXI_FILE_CONTEXT && sf->cxt) {
		sdxi_cxt_release_user_handle(sf->cxt);
		sdxi_cxt_put(sf->cxt);
		sf->cxt = NULL;
	}
	sdxi_process_put(sf->process);
	kfree(sf);
	file->private_data = NULL;
	return 0;
}

static const struct file_operations sdxi_fops = {
	.owner = THIS_MODULE,
	.open = sdxi_open,
	.release = sdxi_release,
	.unlocked_ioctl = sdxi_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static const struct file_operations sdxi_cxt_fops = {
	.owner = THIS_MODULE,
	.release = sdxi_release,
	.unlocked_ioctl = sdxi_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.mmap = sdxi_mmap,
	.poll = sdxi_cxt_poll,
};

int sdxi_chardev_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&sdxi_devt, 0, SDXI_MAX_MINORS, "sdxi");
	if (ret)
		return ret;

	sdxi_class = class_create("sdxi");
	if (IS_ERR(sdxi_class)) {
		ret = PTR_ERR(sdxi_class);
		sdxi_class = NULL;
		unregister_chrdev_region(sdxi_devt, SDXI_MAX_MINORS);
		return ret;
	}

	return 0;
}

void sdxi_chardev_exit(void)
{
	class_destroy(sdxi_class);
	sdxi_class = NULL;
	unregister_chrdev_region(sdxi_devt, SDXI_MAX_MINORS);
	ida_destroy(&sdxi_minor_ida);
}

int sdxi_chardev_register(struct sdxi_dev *sdxi)
{
	char name[32];
	dev_t devt;
	int minor;
	int ret;

	minor = ida_alloc_max(&sdxi_minor_ida, SDXI_MAX_MINORS - 1,
			      GFP_KERNEL);
	if (minor < 0)
		return minor;

	sdxi->minor = minor;
	if (sdxi->bus_ops->chardev_name) {
		ret = sdxi->bus_ops->chardev_name(sdxi, name, sizeof(name));
		if (ret < 0)
			goto free_minor;
	} else {
		scnprintf(name, sizeof(name), "sdxi%d", minor);
	}

	devt = MKDEV(MAJOR(sdxi_devt), minor);
	sdxi->chardev.devt = devt;
	sdxi->chardev.class = sdxi_class;
	sdxi->chardev.parent = sdxi->dev;
	sdxi->chardev.groups = sdxi_dev_groups;
	dev_set_drvdata(&sdxi->chardev, sdxi);
	ret = dev_set_name(&sdxi->chardev, "%s", name);
	if (ret)
		goto free_minor;

	cdev_init(&sdxi->cdev, &sdxi_fops);
	sdxi->cdev.owner = THIS_MODULE;

	ret = cdev_device_add(&sdxi->cdev, &sdxi->chardev);
	if (ret)
		goto free_minor;

	return 0;

free_minor:
	sdxi->minor = -1;
	ida_free(&sdxi_minor_ida, minor);
	return ret;
}

void sdxi_chardev_unregister(struct sdxi_dev *sdxi)
{
	if (sdxi->minor < 0)
		return;

	cdev_device_del(&sdxi->cdev, &sdxi->chardev);
	ida_free(&sdxi_minor_ida, sdxi->minor);
	sdxi->minor = -1;
}

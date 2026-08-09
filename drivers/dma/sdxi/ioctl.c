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
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/mm.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/sdxi.h>

#include "ioctl.h"
#include "mmio.h"
#include "process.h"
#include "sdxi.h"

#define SDXI_MAX_MINORS	256

static dev_t sdxi_devt;
static struct class *sdxi_class;
static DEFINE_IDA(sdxi_minor_ida);

static int sdxi_file_check_owner(const struct sdxi_process *process)
{
	if (process->lead_thread != current->group_leader ||
	    process->mm != current->mm)
		return -EBADF;

	return 0;
}

static int sdxi_ioctl_unsupported(struct file *file, struct sdxi_file *sf,
				  void *data)
{
	return -EOPNOTSUPP;
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
			SDXI_UAPI_CAP_DEV_ATTR_MGMT,
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
	SDXI_IOCTL_DEF(0x05, SDXI_GET_RKEY_LIST, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x06, SDXI_GET_RKEYS, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x07, SDXI_SET_RKEYS, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_ADMIN_DEVICE),
	SDXI_IOCTL_DEF(0x08, SDXI_CREATE_CXT, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x09, SDXI_CXT_EVENTFD, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0a, SDXI_GET_AKEY_LIST, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0b, SDXI_GET_AKEYS, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0c, SDXI_SET_AKEYS, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
	SDXI_IOCTL_DEF(0x0d, SDXI_ADMIN_DISC, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_PUBLIC_DEVICE),
	SDXI_IOCTL_DEF(0x0e, SDXI_ADMIN_VENDOR, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_DEVICE, SDXI_IOCTL_A_VENDOR_HANDLER),
	SDXI_IOCTL_DEF(0x0f, SDXI_QUIESCE_CXT, sdxi_ioctl_unsupported,
		       SDXI_IOCTL_F_CONTEXT, SDXI_IOCTL_A_CONTEXT_OWNER),
};

static int sdxi_ioctl_permit(const struct sdxi_ioctl_desc *desc)
{
	switch (desc->access) {
	case SDXI_IOCTL_A_PUBLIC_DEVICE:
	case SDXI_IOCTL_A_CONTEXT_OWNER:
		return 0;
	case SDXI_IOCTL_A_ADMIN_DEVICE:
		return capable(CAP_SYS_ADMIN) ? 0 : -EPERM;
	case SDXI_IOCTL_A_VENDOR_HANDLER:
		return -EOPNOTSUPP;
	}

	return -EINVAL;
}

static bool sdxi_ioctl_has_trailing_payload(unsigned int cmd)
{
	return cmd == SDXI_GET_RKEY_LIST || cmd == SDXI_GET_RKEYS ||
	       cmd == SDXI_SET_RKEYS || cmd == SDXI_GET_AKEY_LIST ||
	       cmd == SDXI_GET_AKEYS || cmd == SDXI_SET_AKEYS;
}

static long sdxi_ioctl_live(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	const struct sdxi_ioctl_desc *desc;
	struct sdxi_file *sf = file->private_data;
	unsigned int canonical_size;
	unsigned int user_size;
	unsigned int size;
	unsigned int nr;
	char stack_data[128];
	void *data = stack_data;
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

	ret = sdxi_ioctl_permit(desc);
	if (ret)
		return ret;

	canonical_size = _IOC_SIZE(desc->cmd);
	user_size = _IOC_SIZE(cmd);
	size = max(canonical_size, user_size);
	if (size > PAGE_SIZE)
		return -E2BIG;

	if (size > sizeof(stack_data)) {
		data = kzalloc(size, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
	} else {
		memset(data, 0, size);
	}

	if ((_IOC_DIR(cmd) & _IOC_WRITE) &&
	    copy_from_user(data, (void __user *)arg, user_size)) {
		ret = -EFAULT;
		goto out;
	}

	ret = desc->func(file, sf, data);

	if ((_IOC_DIR(cmd) & _IOC_READ) && user_size > canonical_size &&
	    !sdxi_ioctl_has_trailing_payload(desc->cmd))
		memset((u8 *)data + canonical_size, 0,
		       user_size - canonical_size);
	if ((_IOC_DIR(cmd) & _IOC_READ) &&
	    copy_to_user((void __user *)arg, data, user_size))
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
	dev_t devt;
	int minor;
	int ret;

	minor = ida_alloc_max(&sdxi_minor_ida, SDXI_MAX_MINORS - 1,
			      GFP_KERNEL);
	if (minor < 0)
		return minor;

	sdxi->minor = minor;
	devt = MKDEV(MAJOR(sdxi_devt), minor);
	sdxi->chardev.devt = devt;
	sdxi->chardev.class = sdxi_class;
	sdxi->chardev.parent = sdxi->dev;
	dev_set_drvdata(&sdxi->chardev, sdxi);
	ret = dev_set_name(&sdxi->chardev, "sdxi%d", minor);
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

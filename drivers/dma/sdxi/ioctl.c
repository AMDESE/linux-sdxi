/*
 * SDXI IOCTL Interface
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 */

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/amd-iommu.h>
#include <uapi/linux/sdxi.h>

#include "ioctl.h"
#include "process.h"
#include "sdxi.h"
#include "context.h"

static const char sdxi_dev_name[] = "sdxi";
static int sdxi_char_dev_major = -1;
static struct class *sdxi_class;
struct device *sdxi_device;

/*********************/
/* SUPPORT FUNCTIONS */
/*********************/
static int sdxi_cxt_doorbell_mmap(struct sdxi_process *process,
				  struct vm_area_struct *vma)
{
	struct sdxi_cxt *cxt = process->cxt;
	struct sdxi_dev *sdxi = cxt->sdxi;
	phys_addr_t address;
	int ret;

	if (vma->vm_end - vma->vm_start != sdxi->db_stride)
		return -EINVAL;

	address = cxt->db_base;

	vm_flags_set(vma, VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE |
		     VM_DONTDUMP | VM_PFNMAP);

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	pr_debug("pasid 0x%x mapping mmio page (dev=%s)\n"
		 "     target user address == 0x%08llX\n"
		 "     physical address    == 0x%08llX\n"
		 "     vm_flags            == 0x%04lX\n"
		 "     size                == 0x%04lX\n",
		 process->pasid, dev_name(&sdxi->pdev->dev),
		 (unsigned long long) vma->vm_start, address,
		 vma->vm_flags, PAGE_SIZE);

	ret = io_remap_pfn_range(vma,
				 vma->vm_start,
				 address >> PAGE_SHIFT,
				 sdxi->db_stride,
				 vma->vm_page_prot);

	return ret;
}

static int sdxi_cxt_struct_mmap(struct sdxi_process *process,
				struct vm_area_struct *vma,
				unsigned int size, void *ptr)
{
	unsigned long pfn;
	int ret;

	if (!IS_ALIGNED(__pa(ptr), PAGE_SIZE)) {
		pr_err("Non-aligned physical memory\n");
		return -EINVAL;
	}

	if ((vma->vm_end - vma->vm_start) > size) {
		pr_err("Incorrect mmap size: request=0x%lx, expected=0x%x\n",
		       (vma->vm_end - vma->vm_start), size);
		return -EINVAL;
	}

	vm_flags_set(vma, VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE |
		     VM_DONTDUMP | VM_PFNMAP);

	//vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	//pfn = PFN_DOWN(__pa(ptr));
	pfn = virt_to_phys(ptr)>>PAGE_SHIFT;

	/* mapping pages to user process */
	ret = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);

	return ret;
}


static int sdxi_ioctl_get_version(struct file *filep, struct sdxi_process *p,
				  void *data)
{
	struct sdxi_get_version_args *args = data;

	args->major_version = SDXI_IOCTL_MAJOR_VER;
	args->minor_version = SDXI_IOCTL_MINOR_VER;

	return 0;
}

static int sdxi_ioctl_get_dev_info(struct file *filep, struct sdxi_process *p,
				   void *data)
{
	struct sdxi_get_dev_info_args *args = data;
	struct list_head *curr;
	struct sdxi_dev *sdxi;
	u32 min_value;
	bool first = true;

	memset(args, 0, sizeof(*args));

	if (list_empty(&sdxi_device_list))
		return 0;

	list_for_each(curr, &sdxi_device_list) {
		sdxi = list_entry(curr, struct sdxi_dev, list);

		if (!first) {
			min_value = min_t(u32, sdxi->max_ring_entries,
					  args->cxt_max_ring_entries);
			args->cxt_max_ring_entries = min_value;

			min_value = min_t(u32, sdxi->max_akeys,
					  args->cxt_max_akey_entries);
			args->cxt_max_akey_entries = min_value;

			/* NB: handle dev_supported_op_grps */
		} else {
			args->cxt_max_ring_entries = sdxi->max_ring_entries;
			args->cxt_max_akey_entries = sdxi->max_akeys;
			args->dev_supported_op_grps = SDXI_DMA_OP_GROUP |
				SDXI_ADMIN_OP_GROUP |
				SDXI_ATOMIC_OP_GROUP |
				SDXI_INTR_OP_GROUP;

			first = false;
		}
	}

	return 0;
}

static int sdxi_ioctl_create_cxt(struct file *filep, struct sdxi_process *p,
				 void *data)
{
	struct sdxi_create_cxt_args *args = data;
	struct sdxi_cxt *cxt;
	int err = 0;

	/* We actually skip the configuration from user. Need to be used */
	cxt = sdxi_working_cxt_alloc();
	if (IS_ERR(cxt))
		return -EINVAL;

	mutex_lock(&p->mutex);

	p->cxt = cxt;
	err = sdxi_bind_process_to_device(p);
	if (err) {
		err = -ESRCH;
		goto err_bind_process;
	}

	/* return values to caller */
	args->pasid = p->pasid;
	args->cxt_id = p->cxt->id;
	args->cxt_status_mmap_base = SDXI_MMAP_TYPE_CXT_STATUS;
	args->desc_ring_mmap_base = SDXI_MMAP_TYPE_DESC_RING;
	args->write_index_mmap_base = SDXI_MMAP_TYPE_WRITE_INDEX;
	args->doorbell_mmap_base = SDXI_MMAP_TYPE_DOORBELL;

	/* setup akey */
	cxt->akey[1].vl = 1;
	cxt->akey[1].pv = 1;
	cxt->akey[1].pasid = p->pasid;

	mutex_unlock(&p->mutex);

	pr_debug("Context id %d was created successfully\n", args->cxt_id);
	return 0;

err_bind_process:
	mutex_unlock(&p->mutex);
	return err;
}

static int sdxi_ioctl_close_cxt(struct file *filep, struct sdxi_process *p,
				void *data)
{
	struct sdxi_close_cxt_args *args = data;

	mutex_lock(&p->mutex);

	if (args->cxt_id == p->cxt->id) {
		sdxi_unbind_process_to_device(p);
		sdxi_cxt_exit(p->cxt);
	}

	mutex_unlock(&p->mutex);

	return 0;
}

/******************/
/* FOPS FUNCTIONS */
/******************/
static int sdxi_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct sdxi_process *process;
	unsigned long offset;
	unsigned int size;
	struct sdxi_sq *sq;

	process = sdxi_get_process(current);
	if (IS_ERR(process))
		return PTR_ERR(process);

	if (!process->cxt)
		return -EINVAL;

	sq = process->cxt->sq;
	if (!sq)
		return -EINVAL;

	offset = vma->vm_pgoff << PAGE_SHIFT;

	switch (offset & SDXI_MMAP_TYPE_MASK) {
	case SDXI_MMAP_TYPE_DOORBELL:
		return sdxi_cxt_doorbell_mmap(process, vma);
	case SDXI_MMAP_TYPE_CXT_STATUS:
		size = sq->cxt_status_size;
		return sdxi_cxt_struct_mmap(process, vma, size, sq->cxt_status);
	case SDXI_MMAP_TYPE_WRITE_INDEX:
		size = sq->write_index_size;
		return sdxi_cxt_struct_mmap(process, vma, size, sq->write_index);
	case SDXI_MMAP_TYPE_DESC_RING:
		size = sq->ring_size;
		return sdxi_cxt_struct_mmap(process, vma, size, sq->desc_ring);
	default:
		break;
	}

	return -EINVAL;
}

#define SDXI_IOCTL_DEF(ioctl, _func, _flags)				\
	[_IOC_NR(ioctl)] = {.cmd = ioctl, .func = _func, .flags = _flags, \
			    .cmd_drv = 0, .name = #ioctl}

static struct sdxi_ioctl_desc sdxi_ioctls[] = {
	SDXI_IOCTL_DEF(SDXI_GET_VERSION,
		       sdxi_ioctl_get_version, 0),

	SDXI_IOCTL_DEF(SDXI_GET_DEV_INFO,
		       sdxi_ioctl_get_dev_info, 0),

	SDXI_IOCTL_DEF(SDXI_CREATE_CXT,
		       sdxi_ioctl_create_cxt, 0),

	SDXI_IOCTL_DEF(SDXI_CLOSE_CXT,
		       sdxi_ioctl_close_cxt, 0),
};
#define SDXI_IOCTL_COUNT ARRAY_SIZE(sdxi_ioctls)

static long sdxi_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct sdxi_process *process;
	sdxi_ioctl_t *func;
	const struct sdxi_ioctl_desc *ioctl = NULL;
	unsigned int nr = _IOC_NR(cmd);
	char stack_kdata[128];
	char *kdata = NULL;
	unsigned int usize, asize;
	u32 sdxi_size;
	int retcode = -EINVAL;

	if (nr >= SDXI_IOCTL_COUNT)
		goto err_out;

	ioctl = &sdxi_ioctls[nr];
	sdxi_size = _IOC_SIZE(ioctl->cmd);
	usize = asize = _IOC_SIZE(cmd);
	if (sdxi_size > asize)
		asize = sdxi_size;

	cmd = ioctl->cmd;

	dev_dbg(sdxi_device, "ioctl cmd 0x%x (#0x%x), arg 0x%lx\n", cmd, nr,
		arg);

	process = filep->private_data;
	if (process->lead_thread != current->group_leader) {
		dev_dbg(sdxi_device, "using SDXI IOCTL in wrong process\n");
		retcode = -EBADF;
		goto err_out;
	}

	func = ioctl->func;
	if (unlikely(!func)) {
		dev_dbg(sdxi_device, "no IOCTL function found\n");
		retcode = -EINVAL;
		goto err_out;
	}

	if (cmd & (IOC_IN | IOC_OUT)) {
		if (asize <= sizeof(stack_kdata)) {
			kdata = stack_kdata;
		} else {
			kdata = kmalloc(asize, GFP_KERNEL);
			if (!kdata) {
				retcode = -ENOMEM;
				goto err_out;
			}
		}
		if (asize > usize)
			memset(kdata + usize, 0, asize - usize);
	}

	if (cmd & IOC_IN) {
		if (copy_from_user(kdata, (void __user *)arg, usize) != 0) {
			retcode = -EFAULT;
			goto err_out;
		}
	} else if (cmd & IOC_OUT) {
		memset(kdata, 0, usize);
	}

	retcode = func(filep, process, kdata);

	if (cmd & IOC_OUT)
		if (copy_to_user((void __user *)arg, kdata, usize) != 0)
			retcode = -EFAULT;

err_out:
	if (!ioctl)
		dev_dbg(sdxi_device, "invalid ioctl: pid=%d, cmd=0x%02x, nr=0x%02x\n",
			task_pid_nr(current), cmd, nr);

	if (kdata != stack_kdata)
		kfree(kdata);

	if (retcode)
		dev_dbg(sdxi_device, "ioctl cmd (#0x%x), arg 0x%lx, ret = %d\n",
			nr, arg, retcode);

	return retcode;
}

static int sdxi_open(struct inode *inode, struct file *filep)
{
	struct sdxi_process *process;

	if (iminor(inode) != 0)
		return -ENODEV;

	/* just create sdxi_process, but no context assigned yet */
	process = sdxi_create_process(filep);
	if (IS_ERR(process))
		return PTR_ERR(process);

	filep->private_data = process;

	dev_dbg(sdxi_device, "process %d opened\n", process->pasid);

	return 0;
}

static int sdxi_release(struct inode *inode, struct file *filep)
{
	struct sdxi_process *process = filep->private_data;

	if (process) {
		/* NB: check leftover work with sdxi_unref_process(process) */
		sdxi_destroy_process(process);
	}

	return 0;
}

/*********************/
/* CHARDEV INIT CODE */
/*********************/
static const struct file_operations sdxi_fops = {
	.owner = THIS_MODULE,
	.mmap = sdxi_mmap,
	.unlocked_ioctl = sdxi_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.open = sdxi_open,
	.release = sdxi_release,
};

int sdxi_chardev_init(void)
{
	int err = 0;

	sdxi_char_dev_major = register_chrdev(0, sdxi_dev_name, &sdxi_fops);
	err = sdxi_char_dev_major;
	if (err < 0)
		goto err_register_chrdev;

	sdxi_class = class_create(sdxi_dev_name);
	err = PTR_ERR(sdxi_class);
	if (IS_ERR(sdxi_class))
		goto err_class_create;

	sdxi_device = device_create(sdxi_class, NULL,
				    MKDEV(sdxi_char_dev_major, 0),
				    NULL, sdxi_dev_name);
	err = PTR_ERR(sdxi_device);
	if (IS_ERR(sdxi_device))
		goto err_device_create;

	return 0;

err_device_create:
	class_destroy(sdxi_class);
err_class_create:
	unregister_chrdev(sdxi_char_dev_major, sdxi_dev_name);
err_register_chrdev:
	return err;
}

void sdxi_chardev_exit(void)
{
	device_destroy(sdxi_class, MKDEV(sdxi_char_dev_major, 0));
	class_destroy(sdxi_class);
	unregister_chrdev(sdxi_char_dev_major, sdxi_dev_name);
	sdxi_device = NULL;
}

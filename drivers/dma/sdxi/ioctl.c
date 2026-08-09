// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI character device support.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "ioctl.h"
#include "process.h"
#include "sdxi.h"

#define SDXI_MAX_MINORS	256

static dev_t sdxi_devt;
static struct class *sdxi_class;
static DEFINE_IDA(sdxi_minor_ida);

static long sdxi_ioctl_unsupported(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	return -ENOTTY;
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
	.unlocked_ioctl = sdxi_ioctl_unsupported,
	.compat_ioctl = sdxi_ioctl_unsupported,
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

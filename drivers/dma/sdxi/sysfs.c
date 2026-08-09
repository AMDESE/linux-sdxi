// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI character device attributes.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/device.h>
#include <linux/sysfs.h>

#include "sdxi.h"

static ssize_t version_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct sdxi_dev *sdxi = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u.%u\n", sdxi->sdxi_version.major,
			  sdxi->sdxi_version.minor);
}
static DEVICE_ATTR_RO(version);

static ssize_t cxt_count_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct sdxi_dev *sdxi = dev_get_drvdata(dev);
	unsigned int count;

	mutex_lock(&sdxi->cxt_lock);
	count = sdxi->cxt_count;
	mutex_unlock(&sdxi->cxt_lock);

	return sysfs_emit(buf, "%u\n", count);
}
static DEVICE_ATTR_RO(cxt_count);

static ssize_t sfunc_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct sdxi_dev *sdxi = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%u\n", sdxi->sfunc);
}
static DEVICE_ATTR_RO(sfunc);

static ssize_t numa_node_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct sdxi_dev *sdxi = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%d\n", dev_to_node(sdxi->dev));
}
static DEVICE_ATTR_RO(numa_node);

static struct attribute *sdxi_dev_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_cxt_count.attr,
	&dev_attr_sfunc.attr,
	&dev_attr_numa_node.attr,
	NULL,
};

static const struct attribute_group sdxi_dev_group = {
	.attrs = sdxi_dev_attrs,
};

const struct attribute_group *sdxi_dev_groups[] = {
	&sdxi_dev_group,
	NULL,
};

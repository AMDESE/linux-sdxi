// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI PCI device code
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/iomap.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci-ats.h>
#include <linux/pci.h>

#include "error.h"
#include "sdxi.h"

enum sdxi_mmio_bars {
	SDXI_PCI_BAR_CTL_REGS = 0,
	SDXI_PCI_BAR_DOORBELL = 2,
};

static bool enabled;
module_param(enabled, bool, 0644);
MODULE_PARM_DESC(enabled, "Enable SDXI feature support (default: false)");

static struct pci_dev *sdxi_to_pci_dev(const struct sdxi_dev *sdxi)
{
	return to_pci_dev(sdxi_to_dev(sdxi));
}

static int sdxi_pci_irq_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	int vecs;

	vecs = pci_alloc_irq_vectors(pdev, SDXI_MIN_VECTORS,
				     SDXI_MIN_VECTORS + sdxi->max_cxts,
				     PCI_IRQ_MSI | PCI_IRQ_MSIX);
	if (vecs < 0) {
		return dev_err_probe(sdxi_to_dev(sdxi), vecs,
				     "failed to allocate vectors (max_cxts=%u)\n",
				     sdxi->max_cxts);
	}

	sdxi_dbg(sdxi, "allocated %d irq vectors, max_cxts=%u\n",
		 vecs, sdxi->max_cxts);

	sdxi->error_irq = pci_irq_vector(pdev, SDXI_ERROR_VECTOR);

	return 0;
}

static int sdxi_pci_map(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	void *__iomem regs;

	regs = pcim_iomap_region(pdev, SDXI_PCI_BAR_CTL_REGS, KBUILD_MODNAME);
	if (IS_ERR(regs))
		return PTR_ERR(regs);
	sdxi->ctrl_regs = regs;

	regs = pcim_iomap_region(pdev, SDXI_PCI_BAR_DOORBELL, KBUILD_MODNAME);
	if (IS_ERR(regs))
		return PTR_ERR(regs);
	sdxi->dbs = regs;

	return 0;
}

static void sdxi_pci_unmap(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);

	pcim_iounmap(pdev, sdxi->ctrl_regs);
	pcim_iounmap(pdev, sdxi->dbs);
}

static int sdxi_pci_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	struct device *dev = &pdev->dev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret) {
		sdxi_err(sdxi, "pcim_enable_device failed\n");
		return ret;
	}

	pci_set_master(pdev);
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		sdxi_err(sdxi, "failed to set DMA mask & coherent bits\n");
		return ret;
	}

	ret = sdxi_pci_map(sdxi);
	if (ret) {
		sdxi_err(sdxi, "failed to map device IO resources\n");
		return ret;
	}

	return 0;
}

static bool sdxi_pci_supports_privileged_addrspace(struct sdxi_dev *sdxi)
{
#ifdef CONFIG_PCI_PASID
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);

	return pdev->pasid_enabled &&
		(pdev->pasid_features & PCI_PASID_CAP_PRIV);
#else
	return false;
#endif
}


static void sdxi_pci_exit(struct sdxi_dev *sdxi)
{
	sdxi_pci_unmap(sdxi);
}

static struct sdxi_dev *sdxi_device_alloc(struct device *dev)
{
	struct sdxi_dev *sdxi;

	sdxi = kzalloc(sizeof(*sdxi), GFP_KERNEL);
	if (!sdxi)
		return NULL;

	sdxi->dev = dev;

	mutex_init(&sdxi->cxt_lock);

	return sdxi;
}

static void sdxi_device_free(struct sdxi_dev *sdxi)
{
	kfree(sdxi);
}

static const struct sdxi_dev_ops sdxi_pci_dev_ops = {
	.irq_init = sdxi_pci_irq_init,
	.supports_privileged_addrspace = sdxi_pci_supports_privileged_addrspace,
};

static int sdxi_pci_probe(struct pci_dev *pdev,
			  const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct sdxi_dev *sdxi;
	int err;

	sdxi = sdxi_device_alloc(dev);
	if (!sdxi)
		return -ENOMEM;

	pci_set_drvdata(pdev, sdxi);

	err = sdxi_pci_init(sdxi);
	if (err)
		goto free_sdxi;

	err = sdxi_device_init(sdxi, &sdxi_pci_dev_ops);
	if (err)
		goto pci_exit;

	return 0;

pci_exit:
	sdxi_pci_exit(sdxi);
free_sdxi:
	sdxi_device_free(sdxi);

	return err;
}

static void sdxi_pci_remove(struct pci_dev *pdev)
{
	struct sdxi_dev *sdxi = pci_get_drvdata(pdev);

	sdxi_device_exit(sdxi);
	sdxi_pci_exit(sdxi);
	sdxi_device_free(sdxi);
}

static const struct pci_device_id sdxi_id_table[] = {
	{ PCI_DEVICE_CLASS(PCI_CLASS_ACCELERATOR_SDXI, 0xffffff) },
	{ }
};
MODULE_DEVICE_TABLE(pci, sdxi_id_table);

static struct pci_driver sdxi_driver = {
	.name = "sdxi",
	.id_table = sdxi_id_table,
	.probe = sdxi_pci_probe,
	.remove = sdxi_pci_remove,
	.sriov_configure = pci_sriov_configure_simple,
};

static int __init sdxi_module_init(void)
{
	int rc = 0;

	if (!enabled) {
		pr_info("SDXI support disabled by default - please use "
			"\"modprobe sdxi enabled=1\" to turn on\n");
		return rc;
	}

	return pci_register_driver(&sdxi_driver);
}

static void __exit sdxi_module_exit(void)
{
	if (!enabled)
		return;

	pci_unregister_driver(&sdxi_driver);
}

MODULE_AUTHOR("Wei Huang <wei.huang2@amd.com>");
MODULE_DESCRIPTION(SDXI_DRV_DESC);
MODULE_LICENSE("GPL v2");
module_init(sdxi_module_init);
module_exit(sdxi_module_exit);

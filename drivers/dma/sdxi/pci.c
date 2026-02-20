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

static int sdxi_pci_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi_to_pci_dev(sdxi);
	struct device *dev = &pdev->dev;
	int ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return dev_err_probe(dev, ret, "failed to enable device\n");

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret)
		return dev_err_probe(dev, ret, "failed to set DMA masks\n");

	sdxi->ctrl_regs = pcim_iomap_region(pdev, SDXI_PCI_BAR_CTL_REGS,
					    KBUILD_MODNAME);
	if (IS_ERR(sdxi->ctrl_regs)) {
		return dev_err_probe(dev, PTR_ERR(sdxi->ctrl_regs),
				     "failed to map control registers\n");
	}

	sdxi->dbs = pcim_iomap_region(pdev, SDXI_PCI_BAR_DOORBELL,
				      KBUILD_MODNAME);
	if (IS_ERR(sdxi->dbs)) {
		return dev_err_probe(dev, PTR_ERR(sdxi->dbs),
				     "failed to map doorbell region\n");
	}

	pci_set_master(pdev);
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

static const struct sdxi_bus_ops sdxi_pci_ops = {
	.irq_init = sdxi_pci_irq_init,
	.supports_privileged_addrspace = sdxi_pci_supports_privileged_addrspace,
};

static int sdxi_pci_probe(struct pci_dev *pdev,
			  const struct pci_device_id *id)
{
	struct sdxi_dev *sdxi;
	int err;

	if (!enabled) {
		return dev_err_probe(&pdev->dev, -EPERM,
				     "sdxi disabled by default. "
				     "Use module parameter enabled=1 to turn on.\n");
	}

	sdxi = sdxi_device_alloc(&pdev->dev);
	if (!sdxi)
		return -ENOMEM;

	err = sdxi_pci_init(sdxi);
	if (err)
		return err;

	return sdxi_device_init(sdxi, &sdxi_pci_ops);
}

static void sdxi_pci_remove(struct pci_dev *pdev)
{
	struct sdxi_dev *sdxi = pci_get_drvdata(pdev);

	sdxi_device_exit(sdxi);
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

MODULE_AUTHOR("Wei Huang <wei.huang2@amd.com>");
MODULE_DESCRIPTION(SDXI_DRV_DESC);
MODULE_LICENSE("GPL v2");
module_pci_driver(sdxi_driver);

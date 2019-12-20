// SPDX-License-Identifier: GPL-2.0+
/*
 *
 * i21555.c: nCipher PCI HSM intel 21555 command driver
 * Copyright 2019 nCipher Security Ltd
 *
 */

#include "solo.h"
#include "i21555.h"

/*
 * pci fixed length accessors.
 * The below functions are used predominantly to access CSR registers in pci
 * memory space.
 */
static u32 nfp_inl(struct nfp_dev *ndev, int bar, int offset)
{
	dev_dbg(&ndev->pcidev->dev,
		"%s: addr %p", __func__, ndev->bar[bar] + offset);
	return le32_to_cpu(ioread32(ndev->bar[bar] + offset));
}

static u16 nfp_inw(struct nfp_dev *ndev, int bar, int offset)
{
	dev_dbg(&ndev->pcidev->dev,
		"%s: addr %p", __func__, ndev->bar[bar] + offset);
	return le16_to_cpu(ioread16(ndev->bar[bar] + offset));
}

static void nfp_outl(struct nfp_dev *ndev, int bar, int offset, u32 data)
{
	dev_dbg(&ndev->pcidev->dev, "%s: addr %p, data %x",
		__func__, ndev->bar[bar] + offset, data);
	iowrite32(cpu_to_le32(data), ndev->bar[bar] + offset);
}

static void nfp_outw(struct nfp_dev *ndev, int bar, int offset, u16 data)
{
	dev_dbg(&ndev->pcidev->dev, "%s: addr %p, data %x",
		__func__, ndev->bar[bar] + offset, data);
	iowrite16(cpu_to_le16(data), ndev->bar[bar] + offset);
}

static int nfp_config_inl(struct nfp_dev *ndev, int offset, u32 *res)
{
	if (!ndev || !ndev->pcidev)
		return -ENODEV;
	pci_read_config_dword(ndev->pcidev, offset, res);
	return 0;
}

/**
 * i21555_started - Check that device is ready to talk
 * @ndev:	common device
 *
 * Checks that device is ready to talk by checking that the i21555 has master
 * enabled on its secondary interface
 *
 * RETURNS: 0 if ready or other value if error.
 */
static int i21555_started(struct nfp_dev *ndev)
{
	u32 tmp32;
	int ne;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	ne = nfp_config_inl(ndev, I21555_CFG_SEC_CMD_STATUS, &tmp32);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: nfp_config_inl failed", __func__);
		return ne;
	}

	tmp32 = le32_to_cpu(tmp32) & 0xffff;

	if (tmp32 & CFG_CMD_MASTER) {
		dev_notice(&ndev->pcidev->dev,
			   "%s: Yes %x", __func__, tmp32);
	} else {
		dev_err(&ndev->pcidev->dev, "%s: device not started yet %x",
			__func__, tmp32);
		ne = -EAGAIN;
	}
	return ne;
}

/**
 * i21555_create - Resets the i21555 device.
 * @ndev:	common device
 *
 * RETURNS: 0 if successful or other value if error.
 */
static int i21555_create(struct nfp_dev *ndev)
{
	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	/* set our context to just be a pointer to our struct nfp_dev */
	ndev->cmdctx = ndev;

	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev,
			"%s: null BAR[%d]", __func__, CSR_BAR);
		return -ENOMEM;
	}
	dev_warn(&ndev->pcidev->dev, "%s: enable doorbell", __func__);
	nfp_outl(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_PRI_SET_MASK,
		 I21555_DOORBELL_PRI_ENABLE);
	nfp_outl(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_PRI_CLEAR_MASK,
		 I21555_DOORBELL_PRI_ENABLE);
	return 0;
}

/**
 * i21555_destroy - Destroys an i21555 device.
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int i21555_destroy(struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	if (!ndev) {
		dev_err(&ndev->pcidev->dev, "%s: NULL ndev", __func__);
		return -ENODEV;
	}
	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev,
			"%s: null BAR[%d]", __func__, CSR_BAR);
		return -ENOMEM;
	}
	nfp_outl(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_PRI_SET_MASK,
		 I21555_DOORBELL_PRI_DISABLE);
	nfp_outl(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_PRI_CLEAR_MASK,
		 I21555_DOORBELL_PRI_DISABLE);

	return 0;
}

/**
 * i21555_open - Opens an i21555 device
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int i21555_open(struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	return 0;
}

/**
 * i21555_close - Closes an i21555 device
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int i21555_close(struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	return 0;
}

/**
 * i21555_isr - Handles an interrupt from the i21555 device.
 * @ctx:	device context (always the device itself)
 * @handled:	set non-zero by this routine if interrupt considered handled
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int i21555_isr(struct nfp_dev *ctx, int *handled)
{
	struct nfp_dev *ndev = ctx;
	u16 doorbell;
	u16 tmp16;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	*handled = 0;

	ndev->stats.isr++;

	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev,
			"%s: null BAR[%d]", __func__, CSR_BAR);
		return -ENOMEM;
	}

	/*
	 * This interrupt may not be from our module, so check that it
	 * actually is us before handling it.
	 */
	doorbell = nfp_inw(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_PRI_SET);
	while (doorbell && doorbell != 0xffff) {
		*handled = 1;
		/* service interrupts */
		if (doorbell & (NFAST_INT_DEVICE_WRITE_OK |
				NFAST_INT_DEVICE_WRITE_FAILED)) {
			ndev->stats.isr_write++;
			tmp16 = (NFAST_INT_DEVICE_WRITE_OK |
				 NFAST_INT_DEVICE_WRITE_FAILED);
			nfp_outw(ndev, CSR_BAR,
				 I21555_OFFSET_DOORBELL_PRI_CLEAR, tmp16);

			dev_warn(&ndev->pcidev->dev,
				 "%s: write done interrupt, ok = %d.", __func__,
				 doorbell & NFAST_INT_DEVICE_WRITE_OK ? 1 : 0);

			nfp_write_complete(ndev, doorbell &
					   NFAST_INT_DEVICE_WRITE_OK ? 1 : 0);
		}

		if (doorbell &
		    (NFAST_INT_DEVICE_READ_OK |
		     NFAST_INT_DEVICE_READ_FAILED)) {
			ndev->stats.isr_read++;
			tmp16 = (NFAST_INT_DEVICE_READ_OK |
				 NFAST_INT_DEVICE_READ_FAILED);
			nfp_outw(ndev, CSR_BAR,
				 I21555_OFFSET_DOORBELL_PRI_CLEAR, tmp16);

			dev_warn(&ndev->pcidev->dev,
				 "%s: read ack interrupt, ok = %d.", __func__,
				 doorbell & NFAST_INT_DEVICE_READ_OK ? 1 : 0);
			nfp_read_complete(ndev, doorbell &
					  NFAST_INT_DEVICE_READ_OK ? 1 : 0);
		}

		if (doorbell &
		    ~(NFAST_INT_DEVICE_READ_OK | NFAST_INT_DEVICE_READ_FAILED |
		      NFAST_INT_DEVICE_WRITE_OK |
		      NFAST_INT_DEVICE_WRITE_FAILED)) {
			nfp_outw(ndev, CSR_BAR,
				 I21555_OFFSET_DOORBELL_PRI_CLEAR, doorbell);
			dev_err(&ndev->pcidev->dev, "%s: unexpected interrupt %x",
				__func__, doorbell);
		}
		doorbell = nfp_inw(ndev, CSR_BAR,
				   I21555_OFFSET_DOORBELL_PRI_SET);
	}
	dev_notice(&ndev->pcidev->dev, "%s: exiting", __func__);
	return 0;
}

/**
 * i21555_write - Initiates a device write request.
 * @addr:	32-bit bus address used by DMA to pull request to device
 * @block:	data buffer to copy from
 * @len:	length of data to copy
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if write successful or other value if error.
 */
static int i21555_write(u32 addr, const char *block, int len,
			struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	__le32 hdr[2];
	int ne;
	u16 tmp16;
	__le32 tmp32;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	ndev->stats.write_fail++;

	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev,
			"%s: null BAR[%d]", __func__, CSR_BAR);
		return -ENOMEM;
	}

	ne = i21555_started(ndev);
	if (ne != 0) {
		if (ne != -EAGAIN) {
			dev_err(&ndev->pcidev->dev,
				"%s: i21555_started failed", __func__);
		}
		return ne;
	}

	dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ MEMBAR2 ]= %p",
		   __func__, ndev->bar[MEMBAR2]);
	dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ CSR_BAR ]= %p",
		   __func__, ndev->bar[CSR_BAR]);
	dev_notice(&ndev->pcidev->dev, "%s: block len %d", __func__, len);

	/* send write request */

	ne = copy_from_user(ndev->bar[MEMBAR2] + NFPCI_JOBS_WR_DATA,
			    block, len) ? -EFAULT : 0;
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: copy_from_user failed", __func__);
		return ne;
	}
	hdr[0] = cpu_to_le32(NFPCI_JOB_CONTROL);
	hdr[1] = cpu_to_le32(len);
	memcpy(ndev->bar[MEMBAR2] + NFPCI_JOBS_WR_CONTROL,
	       (const char *)hdr, 2 * sizeof(hdr[0]));

	/* confirm write request */

	memcpy((char *)hdr, ndev->bar[MEMBAR2] + NFPCI_JOBS_WR_LENGTH,
	       sizeof(hdr[0]));
	tmp32 = cpu_to_le32(len);
	if (hdr[0] != tmp32) {
		dev_err(&ndev->pcidev->dev,
			"%s: length not written", __func__);
		return -EIO;
	}

	tmp16 = NFAST_INT_HOST_WRITE_REQUEST >> 16;
	nfp_outw(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_SEC_SET, tmp16);

	ndev->stats.write_fail--;
	ndev->stats.write_block++;
	ndev->stats.write_byte += len;

	dev_warn(&ndev->pcidev->dev, "%s: done", __func__);
	return 0;
}

/**
 * i21555_read - Reads a device read reply.
 * @block:	data buffer to copy into
 * @len:	maximum length of data to copy
 * @ctx:	device context (always the device itself)
 * @rcnt:	returned actual # of bytes copied
 *
 * RETURNS: 0 if read initiated or other value if error.
 */
static int i21555_read(char *block, int len, struct nfp_dev *ctx, int *rcount)
{
	struct nfp_dev *ndev = ctx;
	int ne;
	int count;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);
	*rcount = 0;

	ndev->stats.read_fail++;

	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev, "%s: null BAR[%d]",
			__func__, CSR_BAR);
		return -ENOMEM;
	}

	ne = i21555_started(ndev);
	if (ne != 0) {
		if (ne != -EAGAIN)
			dev_err(&ndev->pcidev->dev,
				"%s: i21555_started failed", __func__);

		return ne;
	}

	memcpy((char *)&count, ndev->bar[MEMBAR2] + NFPCI_JOBS_RD_LENGTH,
	       sizeof(count));
	count = le32_to_cpu(count);
	if (count < 0 || count > len) {
		dev_err(&ndev->pcidev->dev, "%s: bad byte count (%d) from device",
			__func__, count);
		return -EIO;
	}
	ne = copy_to_user(block, ndev->bar[MEMBAR2] +  NFPCI_JOBS_RD_DATA,
			  count) ? -EFAULT : 0;
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: copy_to_user failed", __func__);
		return ne;
	}
	dev_warn(&ndev->pcidev->dev, "%s: done", __func__);
	*rcount = count;
	ndev->stats.read_fail--;
	ndev->stats.read_block++;
	ndev->stats.read_byte += len;
	return 0;
}

/**
 * i21555_ensure_reading - Initiates a device read request.
 * @addr:	32-bit bus address used by DMA to push reply from device
 * @len:	maximum length data to return
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if read initiated or other value if error.
 */
static int i21555_ensure_reading(dma_addr_t addr, int len, struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	__le32 hdr[3];
	u16 tmp16;
	__le32 tmp32;
	int ne;
	int hdr_len;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);

	ndev->stats.ensure_fail++;

	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev, "%s: null BAR[%d]",
			__func__, CSR_BAR);
		return -ENOMEM;
	}

	ne = i21555_started(ndev);
	if (ne != 0) {
		if (ne != -EAGAIN) {
			dev_err(&ndev->pcidev->dev,
				"%s: i21555_started failed", __func__);
		}
		return ne;
	}

	dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ MEMBAR2 ]= %p", __func__,
		   ndev->bar[MEMBAR2]);
	dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ CSR_BAR ]= %p", __func__,
		   ndev->bar[CSR_BAR]);

	/* send read request */

	if (addr) {
		dev_notice(&ndev->pcidev->dev, "%s: new format, addr %p",
			   __func__, (void *)addr);
		hdr[0] = cpu_to_le32(NFPCI_JOB_CONTROL_PCI_PUSH);
		hdr[1] = cpu_to_le32(len);
		hdr[2] = cpu_to_le32(addr);
		hdr_len = 3 * sizeof(hdr[0]);
	} else {
		hdr[0] = cpu_to_le32(NFPCI_JOB_CONTROL);
		hdr[1] = cpu_to_le32(len);
		hdr_len = 2 * sizeof(hdr[0]);
	}

	memcpy(ndev->bar[MEMBAR2] + NFPCI_JOBS_RD_CONTROL,
	       (const char *)hdr, hdr_len);

	/* confirm read request */

	memcpy((char *)hdr, ndev->bar[MEMBAR2] + NFPCI_JOBS_RD_LENGTH,
	       sizeof(hdr[0]));
	tmp32 = cpu_to_le32(len);
	if (hdr[0] != tmp32) {
		dev_err(&ndev->pcidev->dev, "%s: len not written", __func__);
		return -EIO;
	}

	tmp16 = NFAST_INT_HOST_READ_REQUEST >> 16;
	nfp_outw(ndev, CSR_BAR, I21555_OFFSET_DOORBELL_SEC_SET, tmp16);

	ndev->stats.ensure_fail--;
	ndev->stats.ensure++;

	return 0;
}

/**
 * i21555_set_control - Sets control data.
 * @control:	control string to copy from
 * @ctx:	device context (always the device itself)
 *
 * The device control register is writen directly. No doorbell style handshake
 * is used.
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int i21555_set_control(const struct nfdev_control_str *control,
			      struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);
	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev, "%s: null BAR[%d]",
			__func__, CSR_BAR);
		return -ENOMEM;
	}
	nfp_outl(ndev, CSR_BAR, I21555_SCRATCHPAD_REGISTER_CONTROL,
		 control->control);
	return 0;
}

/**
 * i21555_get_status - Returns status data.
 * @status:	string to copy into
 * @ctx:	device context (always the device itself)
 *
 * The device status registers are read immediately. No doorbell style
 * handshake is used. Without explicit synchronization, it is possible
 * that an inconsistent state may be returned if the status is being
 * updated by the firmware while simultaneously being read by the host.
 * For example, the call could return an updated status word with a not
 * as yet updated error string. This is likely a degenerate case.
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int i21555_get_status(struct nfdev_status_str *status,
			     struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	u32 *error = (u32 *)status->error;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_info(&ndev->pcidev->dev, "%s: entered", __func__);
	if (!ndev->bar[CSR_BAR]) {
		dev_err(&ndev->pcidev->dev,
			"%s: null BAR[%d]", __func__, CSR_BAR);
		return -ENOMEM;
	}

	/*
	 * get status (read immediately with no explicit synchronization
	 * with the firmware)
	 */
	status->status = nfp_inl(ndev,
				 CSR_BAR, I21555_SCRATCHPAD_REGISTER_STATUS);
	error[0] = nfp_inl(ndev, CSR_BAR, I21555_SCRATCHPAD_REGISTER_ERROR_LO);
	error[1] = nfp_inl(ndev, CSR_BAR, I21555_SCRATCHPAD_REGISTER_ERROR_HI);
	return 0;
}

/* command device structure */

const struct nfpcmd_dev i21555_cmddev = {
	.name = "nCipher nShield Solo",
	.vendorid = PCI_VENDOR_ID_INTEL,
	.deviceid = PCI_DEVICE_ID_INTEL_21555,
	.sub_vendorid = PCI_VENDOR_ID_NCIPHER,
	.sub_deviceid = PCI_SUBSYSTEM_ID_NFAST_REV1,
	.bar_sizes = BAR_SIZES,
	.flags = 0,
	.max_ifvers = NFDEV_IF_PCI_PUSH,
	.create = i21555_create,
	.destroy = i21555_destroy,
	.open = i21555_open,
	.close = i21555_close,
	.isr = i21555_isr,
	.write_block = i21555_write,
	.read_block = i21555_read,
	.ensure_reading = i21555_ensure_reading,
	.setcontrol = i21555_set_control,
	.getstatus = i21555_get_status,
};

/* end of file */

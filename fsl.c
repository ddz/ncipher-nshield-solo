// SPDX-License-Identifier: GPL-2.0+
/*
 *
 * fsl.c: nCipher PCI HSM FSL command driver
 * Copyright 2019 nCipher Security Ltd
 *
 */

#include "solo.h"
#include "fsl.h"

/**
 * fsl_create - Resets FSL device.
 * @ndev:	common device
 *
 * Extra device info is initialized the first time created.
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int fsl_create(struct nfp_dev *ndev)
{
	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	if (ndev->created) {
		dev_notice(&ndev->pcidev->dev,
			   "%s: device already created", __func__);
		return 0;
	}

	ndev->active_bar = -1;
	ndev->detection_type = NFP_HSM_POLLING;
	ndev->conn_status = NFP_HSM_STARTING;

	/*
	 * try to reset check doorbell registers
	 * (don't read back in case they hang)
	 */
	ndev->active_bar = FSL_MEMBAR;
	fsl_outl(ndev, FSL_OFFSET_DOORBELL_CS_STATUS, NFAST_INT_DEVICE_CLR);

	if (!ndev->bar[ndev->active_bar]) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: null FSL memory BAR[%d]",
			__func__, ndev->active_bar);
		return -ENOMEM;
	}

	/* set our context to just be a pointer to ourself */
	ndev->cmdctx = ndev;

	/*
	 * try to reset read/write doorbell registers
	 * (don't read back in case they hang)
	 */
	dev_notice(&ndev->pcidev->dev,
		   "%s: clearing read/write doorbell registers", __func__);
	fsl_outl(ndev, FSL_OFFSET_DOORBELL_WR_CMD, NFAST_INT_HOST_CLR);
	fsl_outl(ndev, FSL_OFFSET_DOORBELL_RD_CMD, NFAST_INT_HOST_CLR);

	dev_notice(&ndev->pcidev->dev, "%s: exiting %s active_bar: %d.",
		   __func__, __func__, ndev->active_bar);

	ndev->created = 1;

	return 0;
}

/**
 * fsl_destroy - Destroys an FSL device.
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int fsl_destroy(struct nfp_dev *ctx)
{
	struct nfp_dev *ndev;

	/* check for device */
	ndev = ctx;
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* clear doorbell registers */
	if (ndev->bar[ndev->active_bar]) {
		dev_notice(&ndev->pcidev->dev,
			   "%s: clearing doorbell registers", __func__);
		fsl_outl(ndev,
			 FSL_OFFSET_DOORBELL_WR_STATUS, NFAST_INT_DEVICE_CLR);
		fsl_outl(ndev,
			 FSL_OFFSET_DOORBELL_RD_STATUS, NFAST_INT_DEVICE_CLR);
		fsl_outl(ndev,
			 FSL_OFFSET_DOORBELL_CS_STATUS, NFAST_INT_DEVICE_CLR);
	} else {
		dev_err(&ndev->pcidev->dev,
			"%s: warning: no FSL BAR[%d] memory",
			__func__, ndev->active_bar);
	}

	return 0;
}

/**
 * fsl_created - Returns fsl_created status.
 * @ndev:	common device
 *
 * RETURNS: 0 if created or other value if error.
 */
static int fsl_created(struct nfp_dev *ndev)
{
	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	if (!ndev->created) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: device not created", __func__);
		return -ENODEV;
	}

	if (!ndev->bar[ndev->active_bar]) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: no FSL BAR[%d] memory", __func__,
			ndev->active_bar);
		return -ENOMEM;
	}

	return 0;
}

/**
 * fsl_started - Returns the current status of the connection.
 * @ndev:	common device
 *
 * RETURNS: 0 if started, NFP_HSM_STARTING if not ready,
 * or other value if error.
 */
static int fsl_started(struct nfp_dev *ndev)
{
	int status = NFP_HSM_STARTING;
	int epd_status = NFP_HSM_STARTING;
	u32 doorbell_cs = 0x0;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	if (!ndev->bar[ndev->active_bar]) {
		dev_err(&ndev->pcidev->dev, "%s: error: no FSL BAR[%d] memory",
			__func__, ndev->active_bar);
		return -ENOMEM;
	}

	/* check the status register to see if epd has started */
	doorbell_cs = fsl_inl(ndev, FSL_OFFSET_DOORBELL_POLLING);
	dev_notice(&ndev->pcidev->dev,
		   "%s: doorbell_polling is: %x", __func__, doorbell_cs);

	if (doorbell_cs == NFAST_INT_DEVICE_POLL) {
		epd_status = NFP_HSM_POLLING;
		dev_notice(&ndev->pcidev->dev,
			   "%s: EPD in polling mode", __func__);
	} else if (doorbell_cs == NFAST_INT_DEVICE_PCI_DOWN) {
		epd_status = NFAST_INT_DEVICE_PCI_DOWN;
	}

	/* check current connection status */

	/*
	 * support backwards compatibility with the interrupt driven approach
	 * to detection.
	 */
	if (epd_status == NFP_HSM_POLLING) {
		ndev->detection_type = NFP_HSM_POLLING;
		ndev->conn_status = 0;
		status = ndev->conn_status;
		dev_notice(&ndev->pcidev->dev, "%s: device started", __func__);
	} else if (epd_status == NFAST_INT_DEVICE_PCI_DOWN) {
		ndev->conn_status = NFP_HSM_STARTING;
		dev_notice(&ndev->pcidev->dev, "%s: device starting", __func__);
		/* Closest existing error code */
		status = -EAGAIN;
	}

	return status;
}

/**
 * fsl_update_connection_status - Updates the connection check status.
 * @ndev:	common device
 * @status:	new status
 *
 * RETURNS: 0 if stopped or other value if error.
 */

static int fsl_update_connection_status(struct nfp_dev *ndev, int status)
{
	int current_status;

	if (!ndev)
		return -ENODEV;

	current_status = ndev->conn_status;
	ndev->conn_status = status;
	return current_status;
}

/**
 * fsl_check_complete - Completes a connection check status interrupt.
 * @ndev:	common device
 * @status:	device status
 */
static void fsl_check_complete(struct nfp_dev *ndev, int status)
{
	int ne;
	int started;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check device status */
	ne = fsl_created(ndev);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: check not completed", __func__);
		return;
	}

	/*
	 * started becomes true after fsl_create and the first cs interrupt is
	 * successful.
	 * It switches to false right after since cs_status is set to
	 * 0 right after this check
	 * A fsl_close or a fsl_create can
	 * reset the cs_status to NFP_HSM_STARTING again.
	 */
	started =
		(fsl_update_connection_status(ndev, status) ==
		 NFP_HSM_STARTING) && (status == 0);

	/* reset read/write doorbell registers if just started */

	if (started) {
		dev_notice(&ndev->pcidev->dev,
			   "fsl_create: clearing read/write doorbell registers");
		fsl_outl(ndev, FSL_OFFSET_DOORBELL_WR_CMD, NFAST_INT_HOST_CLR);
		fsl_inl(ndev, FSL_OFFSET_DOORBELL_WR_CMD);
		fsl_outl(ndev, FSL_OFFSET_DOORBELL_RD_CMD, NFAST_INT_HOST_CLR);
		fsl_inl(ndev, FSL_OFFSET_DOORBELL_RD_CMD);
		fsl_outl(ndev,
			 FSL_OFFSET_DOORBELL_WR_STATUS, NFAST_INT_DEVICE_CLR);
		fsl_inl(ndev, FSL_OFFSET_DOORBELL_WR_STATUS);
		fsl_outl(ndev,
			 FSL_OFFSET_DOORBELL_RD_STATUS, NFAST_INT_DEVICE_CLR);
		fsl_inl(ndev, FSL_OFFSET_DOORBELL_RD_STATUS);
	}

	if (status == 0) {
		dev_notice(&ndev->pcidev->dev, "%s: device started", __func__);
	} else if (status == NFP_HSM_STARTING) {
		dev_notice(&ndev->pcidev->dev,
			   "%s: device not started yet", __func__);
	} else {
		dev_err(&ndev->pcidev->dev,
			"%s: device check failed with code: 0x%x",
			__func__, status);
	}
}

/**
 * fsl_isr - Handles an interrupt from the FSL device.
 * @ctx:	device context (always the device itself)
 * @handled:	set non-zero by this routine if interrupt considered handled
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int fsl_isr(struct nfp_dev *ctx, int *handled)
{
	struct nfp_dev *ndev = ctx;
	int ne;
	u32 doorbell_rd, doorbell_wr, doorbell_cs;
	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* mark not yet handled */
	*handled = 0;

	ne = fsl_created(ndev);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: interrupt not handled", __func__);
		return ne;
	}

	++ndev->stats.isr;

	doorbell_wr = fsl_inl(ndev, FSL_OFFSET_DOORBELL_WR_STATUS);
	doorbell_rd = fsl_inl(ndev, FSL_OFFSET_DOORBELL_RD_STATUS);
	doorbell_cs = fsl_inl(ndev, FSL_OFFSET_DOORBELL_CS_STATUS);
	dev_notice(&ndev->pcidev->dev, "%s: cs:= %x,rd:=%x,wr:=%x",
		   __func__, doorbell_cs, doorbell_rd, doorbell_wr);

	while (doorbell_rd || doorbell_wr || doorbell_cs) {
		/*
		 * prevent any illegal combination of set bits from triggering
		 * processing. Note that if anyone of these registers have an
		 * incorrect bit set, it would prevent the other operations from
		 * being processed since we return from the ISR, even if they
		 * have legal values. This is an unlikely scenario since these
		 * registers are written either to 0 or one of the legal values
		 * by the software on the card.
		 */
		if ((doorbell_cs) &&
		    ((doorbell_cs & ~NFAST_INT_DEVICE_CHECK_OK) &&
		     (doorbell_cs & ~NFAST_INT_DEVICE_CHECK_FAILED))) {
			dev_err(&ndev->pcidev->dev,
				"%s: illegal bits in doorbell_cs %x",
				__func__, doorbell_cs);
			*handled = 1;
			/* clear the register*/
			fsl_outl(ndev, FSL_OFFSET_DOORBELL_CS_STATUS,
				 NFAST_INT_DEVICE_CLR);
			return 0;
		}
		if ((doorbell_rd) &&
		    ((doorbell_rd & ~NFAST_INT_DEVICE_READ_OK) &&
		     (doorbell_rd & ~NFAST_INT_DEVICE_READ_FAILED))) {
			dev_err(&ndev->pcidev->dev,
				"%s: illegal bits in doorbell_rd %x",
				__func__, doorbell_rd);
			*handled = 1;
			/* clear the register*/
			fsl_outl(ndev, FSL_OFFSET_DOORBELL_RD_STATUS,
				 NFAST_INT_DEVICE_CLR);
			return 0;
		}
		if ((doorbell_wr) &&
		    ((doorbell_wr & ~NFAST_INT_DEVICE_WRITE_OK) &&
		     (doorbell_wr & ~NFAST_INT_DEVICE_WRITE_FAILED))) {
			dev_err(&ndev->pcidev->dev,
				"%s: illegal bits in doorbell_wr %x",
				__func__, doorbell_wr);
			/* clear the register*/
			fsl_outl(ndev, FSL_OFFSET_DOORBELL_WR_STATUS,
				 NFAST_INT_DEVICE_CLR);
			*handled = 1;
			return 0;
		}

		/*
		 * service interrupts.
		 * if we made it here, the doorbell registers are all valid,
		 * so no need to check for their validity anymore.
		 */

		if (doorbell_wr) {
			fsl_outl(ndev, FSL_OFFSET_DOORBELL_WR_STATUS,
				 NFAST_INT_DEVICE_CLR);
			ndev->stats.isr_write++;
			nfp_write_complete(ndev,
					   doorbell_wr &
					     NFAST_INT_DEVICE_WRITE_OK ?
						1 : 0);
			dev_notice(&ndev->pcidev->dev,
				   "%s: acknowledging write interrupt: ok = %d",
				__func__,
				doorbell_wr & NFAST_INT_DEVICE_WRITE_OK
				? 1 : 0);
		}

		if (doorbell_rd) {
			fsl_outl(ndev, FSL_OFFSET_DOORBELL_RD_STATUS,
				 NFAST_INT_DEVICE_CLR);
			ndev->stats.isr_read++;
			nfp_read_complete(ndev,
					  doorbell_rd &
					    NFAST_INT_DEVICE_READ_OK ? 1 : 0);
			dev_notice(&ndev->pcidev->dev,
				   "%s: acknowledging read interrupt: ok = %d",
				__func__,
				doorbell_rd & NFAST_INT_DEVICE_READ_OK ? 1 : 0);
		}
		/*
		 * the doorbell_cs is being phased out in favor of polling since
		 * there were issues caused by this interrupt being issued from
		 * the card on its own when the driver was not even present.
		 * To maintain backwards compatibility, this code is being kept,
		 * but might be removed in the future.
		 */
		dev_notice(&ndev->pcidev->dev, "%s: doorbell_cs is: %x",
			   __func__, doorbell_cs);
		if (doorbell_cs) {
			fsl_outl(ndev, FSL_OFFSET_DOORBELL_CS_STATUS,
				 NFAST_INT_DEVICE_CLR);
			fsl_check_complete(ndev,
					   doorbell_cs &
						NFAST_INT_DEVICE_CHECK_OK ?
						0 :
						NFP_HSM_STARTING);
			dev_notice(&ndev->pcidev->dev,
				   "%s: acknowledging check interrupt: status:0x%x",
				   __func__,
				   doorbell_cs & NFAST_INT_DEVICE_CHECK_OK ?
					0 :
					NFP_HSM_STARTING);
		}

		doorbell_wr = fsl_inl(ndev, FSL_OFFSET_DOORBELL_WR_STATUS);
		doorbell_rd = fsl_inl(ndev, FSL_OFFSET_DOORBELL_RD_STATUS);
		doorbell_cs = fsl_inl(ndev, FSL_OFFSET_DOORBELL_CS_STATUS);

		dev_notice(&ndev->pcidev->dev, "%s: cs status in isr is: %x",
			   __func__, doorbell_cs);
	}

	/* always report the interrupt as handled */
	*handled = 1;

	dev_notice(&ndev->pcidev->dev, "%s: exiting", __func__);

	return 0;
}

/**
 * fsl_open - Performs additional FSL-specific actions when opening a device.
 * @ctx:	device context (always the device itself)
 *
 * This routine returns an error if the device has not properly started.
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int fsl_open(struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	int ne;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check device status */
	ne = fsl_started(ndev);
	if (ne != 0) {
		ndev->stats.ensure_fail++;
		dev_err(&ndev->pcidev->dev,
			"%s: error: device not started", __func__);
		return ne;
	}

	return 0;
}

/**
 * fsl_close - Performs additional FSL-specific actions when closing a device.
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int fsl_close(struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	return 0;
}

/**
 * fsl_set_control - Sets control data.
 * @control:	control string to copy from
 * @ctx:	device context (always the device itself)
 *
 * The device control register is writen directly. No doorbell style handshake
 * is used.
 *
 * RETURNS: 0 if successful, other value if error.
 */
static int fsl_set_control(const struct nfdev_control_str *control,
			   struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	int ne;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check device status */
	ne = fsl_started(ndev);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: unable to set control", __func__);
		return ne;
	}

	/*
	 * set control (written immediately with no explicit
	 * synchronization with the firmware)
	 */

	fsl_outl(ndev, FSL_OFFSET_REGISTER_CONTROL, control->control);

	return 0;
}

/**
 * fsl_get_status - Returns status data.
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
static int fsl_get_status(struct nfdev_status_str *status, struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	int ne;
	u32 *error = (uint32_t *)status->error;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check device status */
	ne = fsl_started(ndev);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: unable to get status", __func__);
		return ne;
	}

	/*
	 * get status (read immediately with no explicit synchronization
	 * with the firmware)
	 */
	status->status = fsl_inl(ndev, FSL_OFFSET_REGISTER_STATUS);
	error[0] = fsl_inl(ndev, FSL_OFFSET_REGISTER_ERROR_LO);
	error[1] = fsl_inl(ndev, FSL_OFFSET_REGISTER_ERROR_HI);

	return 0;
}

/**
 * fsl_ensure_reading - Initiates a device read request.
 * @addr:	32-bit bus address used by DMA to push reply from device
 * @len:	maximum length data to return
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if read initiated, NFP_HSM_STARTING if device not ready,
 * or other value if error.
 */
static int fsl_ensure_reading(dma_addr_t addr, int len, struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	__le32 hdr[3];
	__le32 tmp32;
	int ne;
	int hdr_len;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check device status */
	ne = fsl_started(ndev);
	if (ne != 0) {
		ndev->stats.ensure_fail++;
		dev_err(&ndev->pcidev->dev,
			"%s: error: unable to initiate read", __func__);
		return ne;
	}

	dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ndev->active_bar]= %p",
		   __func__, (void *)ndev->bar[ndev->active_bar]);

	/* send read request */

	if (addr) {
		dev_notice(&ndev->pcidev->dev,
			   "%s: requesting DMA reply to bus address %p",
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
	memcpy(ndev->bar[ndev->active_bar] + NFPCI_JOBS_RD_CONTROL,
	       (char const *)hdr, hdr_len);

	/* confirm read request */

	memcpy((char *)hdr,
	       ndev->bar[ndev->active_bar] + NFPCI_JOBS_RD_LENGTH,
	       sizeof(hdr[0]));
	tmp32 = cpu_to_le32(len);
	if (hdr[0] != tmp32) {
		dev_err(&ndev->pcidev->dev,
			"%s: error: expected length not written (%08x != %08x)",
			__func__, hdr[0], tmp32);
		ndev->stats.ensure_fail++;
		return -EIO;
	}

	/* trigger read request */

	fsl_outl(ndev, FSL_OFFSET_DOORBELL_RD_CMD, NFAST_INT_HOST_READ_REQUEST);

	ndev->stats.ensure++;

	dev_notice(&ndev->pcidev->dev,
		   "%s: requesting max %d bytes", __func__, len);

	return 0;
}

/**
 * fsl_read - Reads a device read reply.
 * @block:	data buffer to copy into
 * @len:	maximum length of data to copy
 * @ctx:	device context (always the device itself)
 * @rcnt:	returned actual # of bytes copied
 *
 * RETURNS: 0 if read initiated, NFP_HSM_STARTING if device not ready,
 * or other value if error.
 */
static int fsl_read(char *block, int len, struct nfp_dev *ctx, int *rcnt)
{
	struct nfp_dev *ndev = ctx;
	int ne;
	int cnt;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	*rcnt = 0;

	/* check device status */
	ne = fsl_started(ndev);
	if (ne != 0) {
		ndev->stats.read_fail++;
		dev_err(&ndev->pcidev->dev,
			"%s: error: unable to complete read", __func__);
		return ne;
	}

	/* receive reply length */

	memcpy((char *)&cnt,
	       ndev->bar[ndev->active_bar] + NFPCI_JOBS_RD_LENGTH,
	       sizeof(cnt));
	cnt = le32_to_cpu(cnt);
	dev_notice(&ndev->pcidev->dev, "%s: cnt=%u.", __func__, cnt);
	if (cnt < 0 || cnt > len) {
		ndev->stats.read_fail++;
		dev_err(&ndev->pcidev->dev, "%s: error: bad byte count (%d) from device",
			__func__, cnt);
		return -EIO;
	}

	/* receive data */

	ne = copy_to_user(block, ndev->bar[ndev->active_bar] +
			  NFPCI_JOBS_RD_DATA, cnt) ? -EFAULT : 0;
	if (ne != 0) {
		ndev->stats.read_fail++;
		dev_err(&ndev->pcidev->dev, "%s: error: copy_to_user failed",
			__func__);
		return ne;
	}

	*rcnt = cnt;
	ndev->stats.read_block++;
	ndev->stats.read_byte += cnt;
	dev_warn(&ndev->pcidev->dev, "%s: read %d bytes (std)", __func__, cnt);

	return 0;
}

/**
 * fsl_write - Initiates a device write request.
 * @addr:	32-bit bus address used by DMA to pull request to device
 * @block:	data buffer to copy from
 * @len:	length of data to copy
 * @ctx:	device context (always the device itself)
 *
 * RETURNS: 0 if write successful, NFP_HSM_STARTING if device not
 * ready, or other value if error.
 */
static int fsl_write(u32 addr, char const *block, int len, struct nfp_dev *ctx)
{
	struct nfp_dev *ndev = ctx;
	__le32 hdr[3];
	int ne;
	__le32 tmp32;
	int hdr_len;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check device status */
	ne = fsl_started(ndev);
	if (ne != 0) {
		ndev->stats.write_fail++;
		dev_err(&ndev->pcidev->dev,
			"%s: error: unable to initiate write", __func__);
		return ne;
	}

	if (addr == 0) {
		/* std write */

		dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ndev->active_bar]= %p",
			   __func__, (void *)ndev->bar[ndev->active_bar]);
		dev_notice(&ndev->pcidev->dev,
			   "%s: block len %d", __func__, len);

		/* send write request */

		ne = copy_from_user(ndev->bar[ndev->active_bar] +
				    NFPCI_JOBS_WR_DATA, block, len)
				    ? -EFAULT : 0;
		if (ne != 0) {
			ndev->stats.write_fail++;
			dev_err(&ndev->pcidev->dev,
				"%s: error: copy_from_user failed", __func__);
			return ne;
		}

		hdr[0] = cpu_to_le32(NFPCI_JOB_CONTROL);
		hdr[1] = cpu_to_le32(len);
		hdr_len = 2 * sizeof(hdr[0]);
		memcpy(ndev->bar[ndev->active_bar] + NFPCI_JOBS_WR_CONTROL,
		       (char const *)hdr, hdr_len);

		/* confirm write request */

		memcpy((char *)hdr,
		       ndev->bar[ndev->active_bar] + NFPCI_JOBS_WR_LENGTH,
		       sizeof(hdr[0]));
		tmp32 = cpu_to_le32(len);
		if (hdr[0] != tmp32) {
			ndev->stats.write_fail++;
			dev_err(&ndev->pcidev->dev, "%s: length not written (%08x != %08x)",
				__func__, hdr[0], tmp32);
			return -EIO;
		}
	} else {
		/* dma write */

		dev_notice(&ndev->pcidev->dev, "%s: ndev->bar[ndev->active_bar]= %p",
			   __func__, (void *)ndev->bar[ndev->active_bar]);
		dev_notice(&ndev->pcidev->dev,
			   "%s: block len %d", __func__, len);
		dev_notice(&ndev->pcidev->dev, "%s: pull from 0x%016x using DMA",
			   __func__, addr);

		/* submit write request */

		hdr[0] = cpu_to_le32(NFPCI_JOB_CONTROL_PCI_PULL);
		hdr[1] = cpu_to_le32(len);
		hdr[2] = cpu_to_le32(addr);
		hdr_len = 3 * sizeof(hdr[0]);
		memcpy(ndev->bar[ndev->active_bar] + NFPCI_JOBS_WR_CONTROL,
		       (char const *)hdr, hdr_len);

		/* confirm write request */

		memcpy((char *)hdr,
		       ndev->bar[ndev->active_bar] + NFPCI_JOBS_WR_LENGTH,
		       sizeof(hdr[0]));
		tmp32 = cpu_to_le32(len);
		if (hdr[0] != tmp32) {
			ndev->stats.write_fail++;
			dev_err(&ndev->pcidev->dev,
				"%s: length not written (%08x != %08x)",
				__func__, tmp32, hdr[0]);
			return -EIO;
		}
	}

	/* trigger write */

	fsl_outl(ndev,
		 FSL_OFFSET_DOORBELL_WR_CMD, NFAST_INT_HOST_WRITE_REQUEST);

	ndev->stats.write_block++;
	ndev->stats.write_byte += len;

	dev_notice(&ndev->pcidev->dev, "%s: done", __func__);
	return 0;
}

/* FSL Sawshark T1022 device configuration. */
const struct nfpcmd_dev fsl_t1022_cmddev = { "nCipher nShield Solo XC",
				      PCI_VENDOR_ID_FREESCALE,
				      PCI_DEVICE_ID_FREESCALE_T1022,
				      PCI_VENDOR_ID_NCIPHER,
				      PCI_SUBSYSTEM_ID_NFAST_REV1,
				      { 0, FSL_MEMSIZE, 0, 0, 0, 0 },
				      NFP_CMD_FLG_NEED_MSI,
				      NFDEV_IF_PCI_PULL,
				      fsl_create,
				      fsl_destroy,
				      fsl_open,
				      fsl_close,
				      fsl_isr,
				      fsl_write,
				      fsl_read,
				      fsl_ensure_reading,
				      fsl_set_control,
				      fsl_get_status };
/* end of file */

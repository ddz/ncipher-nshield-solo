// SPDX-License-Identifier: GPL-2.0+
/*
 *
 * hostif.c: nCipher PCI HSM linux host interface
 * Copyright 2019 nCipher Security Ltd
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/bitops.h>

#include "solo.h"
#include "i21555.h"
#include "fsl.h"

/* limits & sizes */
#define NFP_READ_MAX (8 * 1024)
#define NFP_WRITE_MAX (8 * 1024)
#define NFP_READBUF_SIZE (NFP_READ_MAX + 8)
#define NFP_WRITEBUF_SIZE (NFP_WRITE_MAX + 8)
#define NFP_MAXDEV 16

/* other operating constants */
#define NFP_TIMEOUT_SEC 20
#define NFP_DMA_NBYTES_OFFSET (4)
#define NFP_DMA_ADDRESS_OFFSET (8)
#define NFP_DRVNAME "nCipher nFast PCI driver"
#define NFP_TIMEOUT ((NFP_TIMEOUT_SEC) * HZ)

/* Interpretation of the bits of struct nfp_dev.rd_outstanding */
#define WAIT_BIT  0 /* waiting for data */
#define CMPLT_BIT 1 /* completing a read (got data or timing out) */

/*
 * Used to determine which installed module we're looking at
 * from its minor device number
 */
#define INODE_FROM_FILE(file) ((file)->f_path.dentry->d_inode)

/*
 * Major device type
 * "nCipher nFast PCI crypto accelerator" in
 * https://www.kernel.org/doc/html/v4.11/admin-guide/devices.html
 */
#define NFP_MAJOR 176

/* device list */

static struct nfp_dev *nfp_dev_list[NFP_MAXDEV];
static int nfp_num_devices;
static struct class *nfp_class;

/**
 * Module structures.
 */

/**
 * NSHIELD_SOLO module interface version parameter.
 *
 * This value can be overridden when the module is loaded, for example:
 *
 *   insmod nshield_solo.ko nfp_ifvers=<n>
 *
 * where n = 0 allows any supported interface,
 *       n > 0 allows only interface versions <= n.
 * See nfdev-common.h for a list of supported interface versions.
 * Specific card models may not support all interface versions.
 */
static int nfp_ifvers;

MODULE_AUTHOR("nCipher");
MODULE_DESCRIPTION("nCipher PCI HSM driver");
module_param(nfp_ifvers, int, 0444);
MODULE_PARM_DESC(nfp_ifvers, "maximum interface version (1-2), or any (0)");
MODULE_LICENSE("GPL");

/**
 * NSHIELD_SOLO character device file operations.
 */

/**
 * nfp_poll - Polls an NSHIELD SOLO device.
 * @filep:	device file pointer
 * @wait:	poll table pointer
 *
 * The kernel calls this function when a user tries to poll an NSHIELD SOLO
 * device. The function returns a bit mask which indicates if the device is
 * immediately readable or writable.  A readable device will set
 * (POLLIN | POLLRDNORM). A writable device will set (POLLOUT | POLLWRNORM).
 *
 * RETURNS: mask indicating if readable and/or writable.
 */
static u32 nfp_poll(struct file *file, poll_table *wait)
{
	struct nfp_dev *ndev;
	u32 mask = 0;
	int minor = MINOR(INODE_FROM_FILE(file)->i_rdev);

	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return -ENODEV;
	}

	ndev = nfp_dev_list[minor];
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* find ndev from minor */

	poll_wait(file, &ndev->wr_queue, wait);
	poll_wait(file, &ndev->rd_queue, wait);

	if (test_bit(0, &ndev->wr_ready))
		mask |= POLLOUT | POLLWRNORM; /* writeable */
	if (test_bit(0, &ndev->rd_ready))
		mask |= POLLIN | POLLRDNORM; /* readable */

	dev_notice(&ndev->pcidev->dev, "%s: device is %swritable, %sreadable",
		   __func__,
		mask & POLLOUT ? "" : "not ", mask & POLLIN ? "" : "not ");

	return mask;
}

void nfp_write_complete(struct nfp_dev *ndev, int ok)
{
	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/*
	 * could be executed simultaneously by more than one thread -
	 * e.g. from the write isr and from the nfp_write/timeout
	 * we don't want that to happen.
	 */
	if (test_and_set_bit(CMPLT_BIT, &ndev->wr_outstanding))
		return;

	if (!test_bit(WAIT_BIT, &ndev->wr_outstanding)) {
		/*
		 * we can only get here if the write has already
		 * been completed
		 */
		dev_err(&ndev->pcidev->dev,
			"%s: no write outstanding to complete; ignoring completion",
			__func__);
		clear_bit(CMPLT_BIT, &ndev->wr_outstanding);
		return;
	}

	/* complete write by waking waiting processes */
	ndev->wr_ok = ok;

	dev_notice(&ndev->pcidev->dev, "%s: write completed %sokay",
		   __func__, ok ? "" : "not ");

	/* make sure that write is complete before we clear wr_outstanding */
	smp_mb__before_atomic();
	clear_bit(CMPLT_BIT, &ndev->wr_outstanding);
	clear_bit(WAIT_BIT, &ndev->wr_outstanding);

	/* wake up anyone waiting */

	wake_up_all(&ndev->wr_queue);
}

#define CREATE_TRACE_POINTS

/**
 * nfp_write - Writes to an NSHIELD SOLO device.
 * @file:	device file pointer
 * @buf:	pointer to a user space buffer
 * @count:	size of user space buffer
 * @off:	offset position (ignored)
 *
 * Data in the user space buffer is written to the NSHIELD SOLO device. Any
 * previous data is overwritten. An error is returned if not all
 * bytes are written from the user space buffer.
 *
 * RETURNS: actual number of bytes written or a negative value if an error
 * occurred.
 */
static ssize_t nfp_write(struct file *file, char const __user *buf,
			 size_t count, loff_t *off)
{
	struct nfp_dev *ndev;
	u32 addr;
	int nbytes;
	int minor;
	int ne;

	/* find ndev from minor */
	minor = MINOR(INODE_FROM_FILE(file)->i_rdev);
	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return -ENODEV;
	}

	ndev = nfp_dev_list[minor];
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check max length requested */
	if (count <= 0 || NFP_WRITE_MAX < count) {
		dev_err(&ndev->pcidev->dev,
			"%s: invalid requested write length %lu",
			__func__, count);
		return -EINVAL;
	}

	/* check if called before ready */
	if (!test_and_clear_bit(0, &ndev->wr_ready)) {
		dev_err(&ndev->pcidev->dev, "%s: write called when not ready.",
			__func__);
		return -ENXIO;
	}
	set_bit(WAIT_BIT, &ndev->wr_outstanding);

	dev_notice(&ndev->pcidev->dev, "%s: writing %ld bytes",
		   __func__, count);

	addr = 0;
	if (ndev->ifvers >= NFDEV_IF_PCI_PULL) {
		dev_notice(&ndev->pcidev->dev,
			   "%s: copying %lu bytes to dma buffer",
			   __func__, count);
		addr = ndev->write_dma;
		nbytes = cpu_to_le32(count);
		*(u32 *)(ndev->write_buf + NFP_DMA_NBYTES_OFFSET) = nbytes;
		if (0 !=
		    copy_from_user(ndev->write_buf + NFP_DMA_ADDRESS_OFFSET,
				   buf, count)) {
			clear_bit(WAIT_BIT, &ndev->wr_outstanding);
			set_bit(0, &ndev->wr_ready);
			dev_err(&ndev->pcidev->dev,
				"%s: copy from user space failed", __func__);
			return -EIO;
		}
	}

	ne = ndev->cmddev->write_block(addr, buf, count, ndev->cmdctx);
	if (ne != 0) {
		nfp_write_complete(ndev, 0);
		if (ne != -EAGAIN)
			dev_err(&ndev->pcidev->dev,
				"%s: write_block failed", __func__);
	}

	while (test_bit(WAIT_BIT, &ndev->wr_outstanding)) {
		if (!wait_event_timeout(ndev->wr_queue,
					test_bit(WAIT_BIT,
						 &ndev->wr_outstanding) == 0,
					NFP_TIMEOUT)) {
			nfp_write_complete(ndev, 0);
			set_bit(0, &ndev->wr_ready);
			dev_err(&ndev->pcidev->dev,
				"%s: module timed out", __func__);
			return -ENXIO;
		}
		if (test_bit(WAIT_BIT, &ndev->wr_outstanding)) {
			dev_err(&ndev->pcidev->dev,
				"%s: handling spurious wake-up", __func__);
		}
	}
	set_bit(0, &ndev->wr_ready);

	dev_warn(&ndev->pcidev->dev, "%s: returning %ld.", __func__,
		 ndev->wr_ok ? count : -EIO);

	if (!ndev->wr_ok) {
		dev_err(&ndev->pcidev->dev,
			"%s: device write failed", __func__);
		return -EIO;
	}

	dev_warn(&ndev->pcidev->dev,
		 "%s: wrote %ld bytes (%s)", __func__, count,
		 ndev->ifvers >= NFDEV_IF_PCI_PULL ? "dma" : "std");
	return count;
}

void nfp_read_complete(struct nfp_dev *ndev, int ok)
{
	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/*
	 * could be executed simultaneously by more than one thread -
	 * e.g. from the read isr and from the timeout
	 * we don't want that to happen.
	 */
	if (test_and_set_bit(CMPLT_BIT, &ndev->rd_outstanding))
		return;

	if (!test_bit(WAIT_BIT, &ndev->rd_outstanding)) {
		/*
		 * we can only get here if the read has already been completed
		 * and no new ENSUREREADING request has been received since
		 */
		dev_err(&ndev->pcidev->dev,
			"%s: no read outstanding to complete; ignoring completion",
			__func__);
		clear_bit(CMPLT_BIT, &ndev->rd_outstanding);
		return;
	}

	/* in case the timer has not expired */
	del_timer(&ndev->rd_timer);

	ndev->rd_ok = ok;
	set_bit(0, &ndev->rd_ready);

	dev_notice(&ndev->pcidev->dev, "%s: read completed %sokay",
		   __func__, ok ? "" : "not ");

	/* make sure that rd_ready is set before we clear rd_outstanding */
	smp_mb__before_atomic();
	clear_bit(CMPLT_BIT, &ndev->rd_outstanding);
	clear_bit(WAIT_BIT, &ndev->rd_outstanding);

	/* wake up anyone waiting */

	wake_up_all(&ndev->rd_queue);
}

static void nfp_read_timeout(struct timer_list *t)
{
	struct nfp_dev *ndev = from_timer(ndev, t, rd_timer);

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	nfp_read_complete(ndev, 0);
}

/**
 * nfp_read - Reads from an NSHIELD SOLO device.
 * @file:	device file pointer
 * @buf:	pointer to a user space buffer
 * @count:	maximum size of user space buffer
 * @off:	offset position (ignored)
 *
 * Data is read from the NSHIELD SOLO device into the user space buffer.
 * The read removes the data from the device. An error is returned is not
 * all the bytes are read from the user space buffer.
 *
 * RETURNS: actual number of bytes read or a negative value if an error
 * occurred.
 */
static ssize_t nfp_read(struct file *file, char __user *buf, size_t count,
			loff_t *off)
{
	struct nfp_dev *ndev;
	int nbytes;
	int minor;
	int ne;

	minor = MINOR(INODE_FROM_FILE(file)->i_rdev);
	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return -ENODEV;
	}

	ndev = nfp_dev_list[minor];
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	/* check user space buffer */
	if (!access_ok(buf, count)) {
		dev_err(&ndev->pcidev->dev,
			"%s: user space verify failed.", __func__);
		return -EFAULT;
	}

	/* check max length requested */

	if (count <= 0 || NFP_READ_MAX < count) {
		dev_err(&ndev->pcidev->dev,
			"%s: invalid requested max read length %lu",
			__func__, count);
		return -EINVAL;
	}

	if (!test_and_clear_bit(0, &ndev->rd_ready)) {
		dev_err(&ndev->pcidev->dev,
			"%s: read called when not ready.", __func__);
		return -EIO;
	}
	nbytes = 0;

	/* check if read was ok */

	if (!ndev->rd_ok) {
		dev_err(&ndev->pcidev->dev, "%s: read failed", __func__);
		return -EIO;
	}

	/* finish read */

	if (ndev->ifvers >= NFDEV_IF_PCI_PUSH) {
		nbytes = *(u32 *)(ndev->read_buf + NFP_DMA_NBYTES_OFFSET);
		nbytes = le32_to_cpu(nbytes);
		dev_notice(&ndev->pcidev->dev,
			   "%s: nbytes %d", __func__, nbytes);
		if (nbytes < 0 || nbytes > count) {
			dev_err(&ndev->pcidev->dev,
				"%s: bad byte count (%d) from device",
				__func__, nbytes);
			return -EIO;
		}
		if (copy_to_user(buf, ndev->read_buf + NFP_DMA_ADDRESS_OFFSET,
				 nbytes) != 0) {
			dev_err(&ndev->pcidev->dev,
				"%s: copy to user space failed", __func__);
			return -EIO;
		}
	} else {
		nbytes = 0;
		ne = ndev->cmddev->read_block(buf, count, ndev->cmdctx,
					      (void *)&nbytes);
		if (ne != 0) {
			dev_err(&ndev->pcidev->dev,
				"%s: device read failed", __func__);
			return ne;
		}
	}

	if (nbytes > NFP_READ_MAX) {
		dev_err(&ndev->pcidev->dev,
			"%s: read reply overflow: %d > %d max",
			__func__, nbytes, NFP_READ_MAX);
		return -EIO;
	}

	dev_warn(&ndev->pcidev->dev, "%s: read %d bytes (%s)", __func__, nbytes,
		 ndev->ifvers >= NFDEV_IF_PCI_PUSH ? "dma" : "std");
	return nbytes;
}

static int nfp_alloc_pci_push(struct nfp_dev *ndev)
{
	/*
	 * allocate resources needed for PCI Push,
	 * if not already allocated.
	 * return True if successful
	 */
	if (!ndev->read_buf) {
		ndev->read_buf =
			kzalloc(NFP_READBUF_SIZE, GFP_KERNEL | GFP_DMA);
		if (!ndev->read_buf)
			return -ENOMEM;

		ndev->read_dma =
			dma_map_single(&ndev->pcidev->dev, ndev->read_buf,
				       NFP_READBUF_SIZE, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(&ndev->pcidev->dev, ndev->read_dma)) {
			dev_err(&ndev->pcidev->dev,
				"dma_mapping_error found after attempting dma_map_single");
			kfree(ndev->read_buf);
			ndev->read_buf = NULL;
			ndev->read_dma = 0;
		}
	}
	return ndev->read_buf ? 1 : 0;
}

static int nfp_alloc_pci_pull(struct nfp_dev *ndev)
{
	/*
	 * allocate resources needed for PCI Pull,
	 * if not already allocated.
	 * return True if successful
	 */
	if (!ndev->write_buf) {
		ndev->write_buf =
			kzalloc(NFP_WRITEBUF_SIZE, GFP_KERNEL | GFP_DMA);
		if (!ndev->write_buf)
			return -ENOMEM;

		ndev->write_dma = dma_map_single(&ndev->pcidev->dev,
						 ndev->write_buf,
						 NFP_WRITEBUF_SIZE,
						 DMA_BIDIRECTIONAL);
		if (dma_mapping_error(&ndev->pcidev->dev, ndev->write_dma)) {
			dev_err(&ndev->pcidev->dev,
				"dma_mapping_error found after attempting dma_map_single");
			kfree(ndev->write_buf);
			ndev->write_buf = NULL;
			ndev->write_dma = 0;
		}
	}
	return ndev->write_buf ? 1 : 0;
}

static void nfp_free_pci_push(struct nfp_dev *ndev)
{
	/* free resources allocated to PCI Push */
	if (ndev->read_buf) {
		dma_unmap_single(&ndev->pcidev->dev, ndev->read_dma,
				 NFP_READBUF_SIZE, DMA_BIDIRECTIONAL);
		kfree(ndev->read_buf);
		ndev->read_buf = NULL;
		ndev->read_dma = 0;
	}
}

static void nfp_free_pci_pull(struct nfp_dev *ndev)
{
	/* free resources allocated to PCI Pull */
	if (ndev->write_buf) {
		dma_unmap_single(&ndev->pcidev->dev, ndev->write_dma,
				 NFP_WRITEBUF_SIZE, DMA_BIDIRECTIONAL);
		kfree(ndev->write_buf);
		ndev->write_buf = NULL;
		ndev->write_dma = 0;
	}
}

/**
 * nfp_set_ifvers - Sets device interface version.
 * @ndev:	an NSHIELD SOLO device
 * @ifvers:	interface version
 *
 * RETURNS: interface version actually set.
 */
static int nfp_set_ifvers(struct nfp_dev *ndev, int ifvers)
{
	int max_ifvers;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return 0; /* no interface version */
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	max_ifvers = ndev->cmddev->max_ifvers;
	if (nfp_ifvers != 0 && max_ifvers > nfp_ifvers)
		max_ifvers = nfp_ifvers;

	/* on any error, ifvers remains unchanged */
	if (ifvers < 0 || ifvers > max_ifvers) {
		/* invalid nfp_ifvers: set to max as fallback */
		dev_err(&ndev->pcidev->dev, "%s: %d out of allowable range [0:%d]",
			__func__, ifvers, max_ifvers);
		return ndev->ifvers;
	}

	if (ifvers == 0 &&
	    ndev->cmddev->deviceid == PCI_DEVICE_ID_FREESCALE_T1022) {
		/*
		 * default ifvers: set to max for ngsolo not for legacy!
		 * The legacy card needs it set to 0 when in Maintenance
		 * mode and then the hardserver steps it up to ifvers 2
		 * when switching back to Operational mode. Solo XC starts
		 * at the max (3) whenever possible.
		 */
		ifvers = max_ifvers;
	}

	if (ifvers >= NFDEV_IF_PCI_PUSH) {
		if (!nfp_alloc_pci_push(ndev)) {
			dev_err(&ndev->pcidev->dev,
				"%s: can't set ifvers %d as resources not available",
				__func__, ifvers);
			return ndev->ifvers;
		}
	} else {
		nfp_free_pci_push(ndev);
	}

	if (ifvers >= NFDEV_IF_PCI_PULL) {
		if (!nfp_alloc_pci_pull(ndev)) {
			dev_err(&ndev->pcidev->dev,
				"%s: can't set ifvers %d as resources not available",
				__func__, ifvers);
			return ndev->ifvers;
		}
	} else {
		nfp_free_pci_pull(ndev);
	}

	ndev->ifvers = ifvers;
	dev_warn(&ndev->pcidev->dev,
		 "%s: setting ifvers = %d", __func__, ifvers);

	return ifvers;
}

/**
 * nfp_ioctl - Performs an NSHIELD SOLO device IOCTL call.
 * @inode:	device inode pointer
 * @file:	device file pointer
 * @cmd:	command id
 * @arg:	command argument
 *
 * RETURNS: 0 if successful or other value if error.
 */
static int nfp_ioctl(struct inode *inode,
		     struct file *file,
		     u32 cmd,
		     u64 arg)
{
	struct nfp_dev *ndev;
	int minor;

	/* find ndev from minor */
	minor = MINOR(INODE_FROM_FILE(file)->i_rdev);

	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return -ENODEV;
	}

	ndev = nfp_dev_list[minor];

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	switch (cmd) {
	case NFDEV_IOCTL_ENQUIRY: {
		struct nfdev_enquiry_str enq_data;
		int err = -EIO;

		dev_dbg(&ndev->pcidev->dev, "%s: enquiry", __func__);
		enq_data.busno = ndev->busno;
		enq_data.slotno = ndev->slotno;
		if ((void *)arg) {
			err = copy_to_user((void __user *)arg, &enq_data,
					   sizeof(enq_data)) ? -EFAULT : 0;
			if (err) {
				dev_err(&ndev->pcidev->dev,
					"%s: copy to user space failed.",
					__func__);
				return err;
			}
		} else {
			dev_err(&ndev->pcidev->dev,
				"%s enquiry: arg pointer is NULL!", __func__);
			return err;
		}
	} break;
	case NFDEV_IOCTL_ENSUREREADING: {
		dma_addr_t addr;
		u32 len;
		int err = -EIO;
		int ne;

		dev_dbg(&ndev->pcidev->dev, "%s: ensure reading", __func__);

		/* get and check max length */
		if ((void *)arg) {
			err = copy_from_user((void *)&len, (void __user *)arg,
					     sizeof(u32)) ? -EFAULT : 0;
			if (err) {
				dev_err(&ndev->pcidev->dev,
					"%s: ensure reading: copy from user space failed.",
					__func__);
				return err;
			}
			/* signal a read to the module */
			dev_warn(&ndev->pcidev->dev,
				 "%s: signalling read request to module, len = %x.",
				 __func__, len);
			if (len > NFP_READ_MAX) {
				dev_err(&ndev->pcidev->dev, "%s: len > %x = %x.",
					__func__, NFP_READ_MAX, len);
				return -EINVAL;
			}
		} else {
			dev_err(&ndev->pcidev->dev,
				"%s ensure reading: arg pointer is NULL!",
				__func__);
			return err;
		}

		if (len <= 0 || NFP_READ_MAX < len) {
			dev_err(&ndev->pcidev->dev,
				"%s: ensure reading: invalid max length %d/%d",
				__func__, len, NFP_READ_MAX);
			err = -EINVAL;
			return err;
		}

		/* check if okay to start read */

		if (test_and_set_bit(WAIT_BIT, &ndev->rd_outstanding)) {
			dev_err(&ndev->pcidev->dev,
				"%s: ensure reading: another read is outstanding",
				__func__);
			return -EBUSY;
		}

		dev_warn(&ndev->pcidev->dev,
			 "%s: ndev->rd_outstanding=1", __func__);

		/* start read ready timeout */

		mod_timer(&ndev->rd_timer, jiffies + (NFP_TIMEOUT_SEC * HZ));

		dev_warn(&ndev->pcidev->dev, "%s: read request", __func__);
		/* start read */

		addr = (ndev->ifvers < NFDEV_IF_PCI_PUSH) ? 0 : ndev->read_dma;
		dev_notice(&ndev->pcidev->dev,
			   "%s: ensure reading: read request with ifvers=%d addr=%p",
			   __func__, ndev->ifvers, (void *)addr);

		ne = ndev->cmddev->ensure_reading(addr, len, ndev->cmdctx);

		if (ne != 0) {
			dev_err(&ndev->pcidev->dev,
				"%s: ensure reading: read request failed",
				__func__);
			del_timer_sync(&ndev->rd_timer);
			/*
			 * make sure that del_timer_sync is done before
			 * we clear rd_outstanding
			 */
			smp_mb__before_atomic();
			clear_bit(WAIT_BIT, &ndev->rd_outstanding);
			return -EIO;
		}
	} break;

	case NFDEV_IOCTL_PCI_IFVERS: {
		int vers, err = -EIO;

		dev_dbg(&ndev->pcidev->dev, "%s: set ifvers", __func__);
		if ((void *)arg) {
			err = copy_from_user(&vers, (void __user *)arg,
					     sizeof(vers)) ? -EFAULT : 0;
			if (err) {
				dev_err(&ndev->pcidev->dev,
					"%s: set ifvers: copy from user space failed.",
					__func__);
				return err;
			}
		} else {
			dev_err(&ndev->pcidev->dev,
				"%s ifvers: arg pointer is NULL!",
				__func__);
			return err;
		}

		if (test_bit(WAIT_BIT, &ndev->rd_outstanding)) {
			dev_err(&ndev->pcidev->dev,
				"%s: set ifvers: unable to set interface version while read outstanding",
				__func__);
			return -EIO;
		}

		nfp_set_ifvers(ndev, vers);
	} break;

	case NFDEV_IOCTL_STATS: {
		int err = -EIO;

		dev_dbg(&ndev->pcidev->dev, "%s: stats", __func__);
		if ((void *)arg) {
			err = copy_to_user((void __user *)arg, &ndev->stats,
					   sizeof(struct nfdev_stats_str))
					   ? -EFAULT : 0;
			if (err) {
				dev_err(&ndev->pcidev->dev,
					"%s: stats: copy to user space failed.",
					__func__);
				return err;
			}
		} else {
			dev_err(&ndev->pcidev->dev,
				"%s stats: arg pointer is NULL!", __func__);
			return err;
		}
	} break;

	case NFDEV_IOCTL_CONTROL: {
		int err = -EIO;
		struct nfdev_control_str control;

		dev_dbg(&ndev->pcidev->dev, "%s: control", __func__);
		if ((void *)arg) {
			err = copy_from_user(&control, (void __user *)arg,
					     sizeof(control)) ? -EFAULT : 0;
			if (err) {
				dev_err(&ndev->pcidev->dev,
					"%s: control: copy from user space failed.",
					__func__);
				return err;
			}
		} else {
			dev_err(&ndev->pcidev->dev,
				"%s control: arg pointer is NULL!", __func__);
			return err;
		}
		if (!ndev->cmddev->setcontrol) {
			dev_warn(&ndev->pcidev->dev,
				 "%s: control: set control not supported for this device: ignored",
				 __func__);
			return -EINVAL;
		}
		dev_notice(&ndev->pcidev->dev,
			   "%s: control: updating HSM control register to 0x%x.",
			   __func__,
			   control.control);

		return ndev->cmddev->setcontrol(&control, ndev->cmdctx);
	} break;

	case NFDEV_IOCTL_STATUS: {
		int err = -EIO;
		struct nfdev_status_str status;

		dev_dbg(&ndev->pcidev->dev, "%s: status", __func__);

		if (!ndev->cmddev->getstatus) {
			dev_warn(&ndev->pcidev->dev,
				 "%s: status not supported for this device: ignored",
				 __func__);
			return -EINVAL;
		}
		err = ndev->cmddev->getstatus(&status,
					      ndev->cmdctx);

		if (err)
			return err;

		if ((void *)arg) {
			err = copy_to_user((void __user *)arg, &status,
					   sizeof(status)) ? -EFAULT : 0;
			if (err) {
				dev_err(&ndev->pcidev->dev,
					"%s: status: copy from user space failed.",
					__func__);
				return err;
			}
		} else {
			dev_err(&ndev->pcidev->dev,
				"%s status: arg pointer is NULL!",
				__func__);
			return err;
		}
		dev_notice(&ndev->pcidev->dev,
			   "%s: read status: 0x%x, error: 0x%02x%02x%02x%02x%02x%02x%02x%02x",
			   __func__,
			status.status, status.error[0], status.error[1],
			status.error[2], status.error[3], status.error[4],
			status.error[5], status.error[6], status.error[7]);
	} break;

	default: {
		dev_err(&ndev->pcidev->dev, "%s: unknown ioctl.", __func__);
		return -EINVAL;
	} break;
	}

	return 0;
}

/**
 * nfp_unlocked_ioctl - Performs an NSHIELD SOLO device unlocked IOCTL call.
 * @file:	device file pointer
 * @cmd:	command id
 * @arg:	command argument
 *
 * RETURNS: 0 if successful or other value if error.
 */
static long nfp_unlocked_ioctl(struct file *file,
			       u32 cmd,
			       unsigned long arg)
{
	long ret;
	int minor;
	struct nfp_dev *ndev;

	minor = MINOR(INODE_FROM_FILE(file)->i_rdev);
	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return -ENODEV;
	}

	ndev = nfp_dev_list[minor];
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	mutex_lock(&ndev->ioctl_mutex);
	ret = nfp_ioctl(NULL, file, cmd, arg);
	mutex_unlock(&ndev->ioctl_mutex);

	dev_dbg(&ndev->pcidev->dev, "%s: left", __func__);
	return ret;
}

static irqreturn_t nfp_isr(int irq, void *context)
{
	struct nfp_dev *ndev = (struct nfp_dev *)context;
	int handled;
	int ne;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return IRQ_NONE;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	ne = ndev->cmddev->isr(ndev->cmdctx, &handled);

	if (ne != 0)
		dev_err(&ndev->pcidev->dev, "%s: cmddev isr failed (%d)",
			__func__, ne);

	return IRQ_RETVAL(handled);
}

/**
 * nfp_open - Opens an NSHIELD SOLO device.
 * @inode:	device inode pointer
 * @file:	device file pointer
 *
 * The kernel calls this function when a user tries to open an
 * NSHIELD SOLO device.  It is an error to attempt to open an
 * already opened device.
 *
 * RETURNS: 0 if successful or other value if error.
 */
static int nfp_open(struct inode *inode, struct file *file)
{
	struct nfp_dev *ndev;
	int ne;
	int minor = MINOR(INODE_FROM_FILE(file)->i_rdev);

	/* find ndev */

	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return -ENODEV;
	}

	ndev = nfp_dev_list[minor];
	if (!ndev) {
		pr_err("%s: cannot find dev %d.", __func__, minor);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	dev_notice(&ndev->pcidev->dev,
		   "%s: opening file at %p.", __func__, file);

	/* check if already open */

	if (atomic_read(&ndev->busy)) {
		dev_err(&ndev->pcidev->dev, "%s: device %s busy", __func__,
			pci_name(ndev->pcidev));
		return -EBUSY;
	}
	atomic_set(&ndev->busy, 1);

	/* drop any old data */

	clear_bit(0, &ndev->rd_ready);

	/* set interface to module default */

	if (ndev->cmddev->deviceid == PCI_DEVICE_ID_FREESCALE_T1022)
		nfp_set_ifvers(ndev, NFDEV_IF_PCI_PULL);
	else
		nfp_set_ifvers(ndev, NFDEV_IF_STANDARD);

	dev_notice(&ndev->pcidev->dev,
		   "%s: ifvers set to %d", __func__, ndev->ifvers);

	/* open device */

	ne = ndev->cmddev->open(ndev->cmdctx);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev, "%s: device open failed: error %d",
			__func__, ne);
		atomic_set(&ndev->busy, 0);
		return ne;
	}

	dev_warn(&ndev->pcidev->dev, "%s: device %s open",
		 __func__, pci_name(ndev->pcidev));

	return 0;
}

/**
 * nfp_release - Releases an NSHIELD SOLO device.
 * @node:	device inode pointer
 * @file:	device file pointer
 *
 * The kernel calls this function when a user tries to close an
 * NSHIELD SOLO device.  It is an error to attempt to close an
 * already closed device.
 *
 * RETURNS: 0 if successful or other value if error.
 */
static int nfp_release(struct inode *node, struct file *file)
{
	struct nfp_dev *ndev;
	long timeout;
	int ne;
	int minor = MINOR(INODE_FROM_FILE(file)->i_rdev);

	/* find ndev from minor */
	if (minor >= NFP_MAXDEV) {
		pr_err("%s: minor out of range.", __func__);
		return(-ENODEV);
	}

	ndev = nfp_dev_list[minor];
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return -ENODEV;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);

	dev_warn(&ndev->pcidev->dev, "%s: closing file at %p.", __func__, file);

	{
		wait_queue_entry_t wait;

		timeout = 1;
		init_waitqueue_entry(&wait, current);
		current->state = TASK_UNINTERRUPTIBLE;
		add_wait_queue(&ndev->rd_queue, &wait);
		if (test_bit(WAIT_BIT, &ndev->rd_outstanding)) {
			dev_dbg(&ndev->pcidev->dev,
				"%s: read outstanding", __func__);
			timeout = schedule_timeout(NFP_TIMEOUT);
			dev_dbg(&ndev->pcidev->dev,
				"%s: finished waiting", __func__);
		}
		current->state = TASK_RUNNING;
		remove_wait_queue(&ndev->rd_queue, &wait);
		if (!timeout) {
			dev_err(&ndev->pcidev->dev,
				"%s: outstanding read timed out", __func__);
		}
	}

	atomic_set(&ndev->busy, 1);
	if (test_bit(WAIT_BIT, &ndev->rd_outstanding)) {
		del_timer_sync(&ndev->rd_timer);
		/* make sure that del_timer_sync is done before
		 * we clear rd_outstanding
		 */
		smp_mb__before_atomic();
		clear_bit(WAIT_BIT, &ndev->rd_outstanding);
	}
	atomic_set(&ndev->busy, 0);

	/* close device */

	ne = ndev->cmddev->close(ndev->cmdctx);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: device close failed", __func__);
		return ne;
	}

	return(0);
}

/**
 * NSHIELD SOLO character device file operations table.
 */
static const struct file_operations nfp_fops = { .owner = THIS_MODULE,
	.poll = nfp_poll,
	.write = nfp_write,
	.read = nfp_read,
	.unlocked_ioctl = nfp_unlocked_ioctl,
	.open = nfp_open,
	.release = nfp_release,
};

/**
 * NSHIELD SOLO device management.
 */

/* device setup */

static void nfp_dev_destroy(struct nfp_dev *ndev, struct pci_dev *pci_dev)
{
	int i;

	/* check for device */
	if (!ndev) {
		pr_err("%s: error: no device", __func__);
		return;
	}

	dev_dbg(&ndev->pcidev->dev, "%s: entered", __func__);
	if (ndev) {
		nfp_free_pci_push(ndev);
		nfp_free_pci_pull(ndev);

		if (ndev->irq) {
			dev_notice(&ndev->pcidev->dev, "%s: freeing irq, %x",
				   __func__, ndev->irq);
			free_irq(ndev->irq, ndev);
		}
		for (i = 0; i < 6; i++)
			if (ndev->bar[i]) {
				dev_notice(&ndev->pcidev->dev,
					   "%s: freeing MEM BAR, %d",
					   __func__, i);
				release_mem_region(pci_resource_start(pci_dev,
								      i),
						   pci_resource_len(pci_dev,
								    i));
				iounmap(ndev->bar[i]);
			}
		dev_notice(&ndev->pcidev->dev, "%s: freeing ndev", __func__);
		kfree(ndev);
	}
}

static int nfp_setup(const struct nfpcmd_dev *cmddev, u8 bus, u8 slot,
		     u32 bar[6], u32 irq_line, struct pci_dev *pcidev)
{
	struct nfp_dev *ndev = 0;
	int ne;
	int i;

	dev_warn(&pcidev->dev,
		 "%s: Found '%s' at bus %x, slot %x, irq %d.",
		 __func__, cmddev->name, bus, slot, irq_line);

	if (nfp_num_devices >= NFP_MAXDEV) {
		dev_err(&pcidev->dev,
			"%s: minor out of range.", __func__);
		goto fail_continue;
	}

	ndev = kzalloc(sizeof(*ndev), GFP_KERNEL);
	if (!ndev) {
		/* logged by the allocator */
		goto fail_continue;
	}
	dev_warn(&pcidev->dev,
		 "%s: allocated device structure.", __func__);

	ndev->busno = bus;
	ndev->pcidev = pcidev;
	ndev->slotno = slot;
	ndev->cmddev = cmddev;

	for (i = 0; i < NFP_BARSIZES_COUNT; i++) {
		int map_bar_size = cmddev->bar_sizes[i] & NFP_BARSIZES_MASK;
		int bar_flags = cmddev->bar_sizes[i] & ~NFP_BARSIZES_MASK;

		if (map_bar_size) {
			if (!request_mem_region(pci_resource_start(pcidev, i),
						pci_resource_len(pcidev, i),
						cmddev->name)) {
				dev_err(&ndev->pcidev->dev,
					"%s: request_mem_region failed, %llx %llx %d (%s)",
					__func__,
					pci_resource_start(pcidev, i),
					pci_resource_len(pcidev, i), i,
					cmddev->name);
				goto fail_continue;
			}

			if (bar_flags & PCI_BASE_ADDRESS_SPACE_PREFETCHABLE) {
				ndev->bar[i] =
					ioremap(bar[i], map_bar_size);
			} else {
				ndev->bar[i] =
					ioremap_nocache(bar[i], map_bar_size);
			}

			if (!ndev->bar[i]) {
				dev_err(&ndev->pcidev->dev,
					"%s: unable to map memory BAR %d, (0x%x).",
					__func__, i, bar[i]);
				goto fail_continue;
			}
		}
	}

	mutex_init(&ndev->ioctl_mutex);

	init_waitqueue_head(&ndev->wr_queue);
	init_waitqueue_head(&ndev->rd_queue);

	set_bit(0, &ndev->wr_ready);

	ne = ndev->cmddev->create(ndev);
	if (ne != 0) {
		dev_err(&ndev->pcidev->dev,
			"%s: failed to create command device (%d)",
			__func__, ne);
		goto fail_continue;
	}

	if (request_irq(irq_line, nfp_isr, IRQF_SHARED, cmddev->name, ndev)) {
		dev_err(&ndev->pcidev->dev,
			"%s: unable to claim interrupt.", __func__);
		goto fail_continue;
	}
	ndev->irq = irq_line;

	memset(&ndev->stats, 0, sizeof(ndev->stats));

	pci_set_drvdata(pcidev, ndev);

	/* setup timeout timer */
	timer_setup(&ndev->rd_timer, nfp_read_timeout, 0);
	mod_timer(&ndev->rd_timer, jiffies + (NFP_TIMEOUT_SEC * HZ));

	nfp_dev_list[nfp_num_devices] = ndev;
	device_create(nfp_class, NULL, /* parent */
		      MKDEV(NFP_MAJOR, nfp_num_devices), NULL, /* drvdata */
		      "nshield_solo%d", nfp_num_devices);
	dev_warn(&ndev->pcidev->dev, "%s: nfp_num_devices= %d, ndev = %p.",
		 __func__, nfp_num_devices, ndev);
	nfp_num_devices++;
	return 1;

fail_continue:
	nfp_dev_destroy(ndev, pcidev);

	return 0;
}

/* device probing */

/**
 * nfp_pci_probe - Adds a PCI device to the module.
 * @pcidev:	PCI device
 * @id:	PCI device ids
 *
 * The PCI subsystem calls this function when a PCI device is found.
 *
 * RETURNS: 0 if successful or other value if error.
 */
static int nfp_pci_probe(struct pci_dev *pcidev,
			 struct pci_device_id const *id)
{
	int i;
	u32 bar[6];
	const struct nfpcmd_dev *nfp_drvlist[] = { &i21555_cmddev,
						   &fsl_t1022_cmddev, NULL };
	const struct nfpcmd_dev *cmddev = nfp_drvlist[id->driver_data];
	u64 iosize;
	u32 irq_line;
	int pos = 0u;
	int err = 0;

	if (!pcidev || !id) {
		pr_err("%s: pcidev or id was NULL!", __func__);
		return -ENODEV;
	}

	dev_notice(&pcidev->dev, "%s: probing PCI device %s",
		   __func__, pci_name(pcidev));

	/* enable the device */
	err = pci_enable_device(pcidev);
	if (err) {
		dev_err(&pcidev->dev, "%s: pci_enable_device failed", __func__);
		err = -ENODEV;
		goto probe_err;
	}

	pci_set_master(pcidev);

	/* save PCI device info */
	irq_line = pcidev->irq;
	for (i = 0; i < NFP_BARSIZES_COUNT; ++i) {
		iosize = cmddev->bar_sizes[i] & NFP_BARSIZES_MASK;
		if (pci_resource_len(pcidev, i) < iosize) {
			dev_err(&pcidev->dev,
				"%s: %s region request overflow: bar %d, requested %llx, maximum %llx",
				__func__, pci_name(pcidev), i, iosize,
				pci_resource_len(pcidev, i));
			err = -ENODEV;
			goto probe_err;
		}
		bar[i] = pci_resource_start(pcidev, i);
	}

	if (cmddev->flags & NFP_CMD_FLG_NEED_MSI) {
		pos = pci_find_capability(pcidev, PCI_CAP_ID_MSI);
		if (!pos) {
			dev_err(&pcidev->dev, "%s: %s MSI not supported",
				__func__, pci_name(pcidev));
			err = -ENODEV;
			goto probe_err;
		}
		dev_err(&pcidev->dev, "%s: %s MSI support at %d",
			__func__, pci_name(pcidev), pos);

		err = pci_enable_msi(pcidev);
		if (err) {
			dev_err(&pcidev->dev,
				"%s: %s unable to enable MSI",
				__func__, pci_name(pcidev));
			goto probe_err;
		}

		/* IRQ vector changes if MSI is enabled. */
		irq_line = pcidev->irq;
		dev_notice(&pcidev->dev, "%s: %s MSI IRQ at %d",
			   __func__, pci_name(pcidev), irq_line);
	}

	dev_warn(&pcidev->dev, "%s: devname %s, slotname %s, busname %s",
		 __func__, "", pci_name(pcidev), pcidev->bus->name);

	err = nfp_setup(cmddev, pcidev->bus->number, PCI_SLOT(pcidev->devfn),
			bar, irq_line, pcidev);
	if (!err) {
		err = -ENODEV;
		goto probe_err;
	}

	return 0;

probe_err:
	pci_disable_msi(pcidev);
	pci_clear_master(pcidev);
	pci_disable_device(pcidev);
	return err;
}

/**
 * nfp_pci_remove - Removes a PCI device from the module.
 * @pcidev:	PCI device
 *
 * The PCI subsystem calls this function when a PCI device is removed.
 *
 * RETURNS: 0 if successful or other value if error.
 */
static void nfp_pci_remove(struct pci_dev *pcidev)
{
	int index;
	struct nfp_dev *ndev;

	dev_err(&pcidev->dev, "%s: removing PCI device %s",
		__func__, pci_name(pcidev));

	/* find existing device */

	ndev = pci_get_drvdata(pcidev);
	if (!ndev) {
		dev_err(&pcidev->dev,
			"%s: no NSHIELD SOLO device associated with this PCI device",
			__func__);
		return;
	}

	/* destroy common device */

	if (ndev->cmddev)
		ndev->cmddev->destroy(ndev->cmdctx);

	nfp_dev_destroy(ndev, pcidev);

	pci_disable_msi(pcidev);
	pci_clear_master(pcidev);
	pci_disable_device(pcidev);

	index = 0;
	while (index < NFP_MAXDEV) {
		if (nfp_dev_list[index] == ndev) {
			nfp_dev_list[index] = NULL;
			device_destroy(nfp_class, MKDEV(NFP_MAJOR, index));
		}
		index++;
	}
}

/**
 * PCI device ID table.  We use the driver_data field to hold an index into
 * nfp_drvlist, so bear than in mind when editing either.
 */
static struct pci_device_id nfp_pci_tbl[] = {
	{
		PCI_DEVICE_SUB(PCI_VENDOR_ID_INTEL,
			       PCI_DEVICE_ID_INTEL_21555,
			       PCI_VENDOR_ID_NCIPHER,
			       PCI_SUBSYSTEM_ID_NFAST_REV1),
		.class = 0, /* Ignore class */
		.class_mask = 0, /* Ignore class mask */
		.driver_data = 0 /* Index into nfp_drvlist */
	},
	{
		PCI_DEVICE_SUB(PCI_VENDOR_ID_FREESCALE,
			       PCI_DEVICE_ID_FREESCALE_T1022,
			       PCI_VENDOR_ID_NCIPHER,
			       PCI_SUBSYSTEM_ID_NFAST_REV1),
		.class = 0, /* Ignore class */
		.class_mask = 0, /* Ignore class mask */
		.driver_data = 1 /* Index into nfp_drvlist */
	},
	{
		0,
	} /* terminate list */
};
MODULE_DEVICE_TABLE(pci, nfp_pci_tbl);

/**
 * PCI driver operations.
 */
static struct pci_driver nfp_pci_driver = { .name = "nshield_solo",
					    .probe = nfp_pci_probe,
					    .remove = nfp_pci_remove,
					    .id_table = nfp_pci_tbl };

/**
 * initialisation
 */

static int nfp_init(void)
{
	int index;

	pr_info("%s: entered", __func__);

	if (register_chrdev(NFP_MAJOR, NFP_DRVNAME, &nfp_fops)) {
		pr_err("unable to get major for nshield_solo device.");
		return -EIO;
	}

	for (index = 0; index < NFP_MAXDEV; index++)
		nfp_dev_list[index] = NULL;

	nfp_class = class_create(THIS_MODULE, "nshield_solo");
	if (IS_ERR(nfp_class)) {
		pr_err("%s: failed to create a class for this device, err = %ld",
		       __func__, PTR_ERR(nfp_class));
		return -EIO;
	}

	index = 0;
	return pci_register_driver(&nfp_pci_driver);
}

/**
 * Initializes this NSHIELD SOLO kernel module.
 */
static int __init nfp_module_init(void)
{
	int err;

	pr_err("%s: inserting nshield_solo module", __func__);

	err = nfp_init();

	return err;
}

/**
 * Exits this NSHIELD SOLO kernel module.
 */
static void __exit nfp_module_exit(void)
{
	pr_notice("%s: removing nshield_solo module", __func__);

	/* unregister pci driver */

	pci_unregister_driver(&nfp_pci_driver);
	/* this triggers device removals */

	class_destroy(nfp_class);

	unregister_chrdev(NFP_MAJOR, NFP_DRVNAME);
	pr_notice("%s: removed nshield_solo module", __func__);
}

module_init(nfp_module_init);
module_exit(nfp_module_exit);

/* end of file */

/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *
 * Interface to the Solo XC's T1022 communication processor
 * Copyright 2019 nCipher Security Ltd
 *
 */

#ifndef NFP_FSL_H
#define NFP_FSL_H

#include <linux/io.h>
#include "solo.h"

/* Always use a lock when 'we' call fsl_started */
#define NFP_WITH_LOCK 1

/* PCI FSL definitions */

#ifndef PCI_VENDOR_ID_FREESCALE
#define PCI_VENDOR_ID_FREESCALE 0x1957
#endif

#ifndef PCI_DEVICE_ID_FREESCALE_T1022
#define PCI_DEVICE_ID_FREESCALE_T1022 0x082c
#endif

#ifndef PCI_VENDOR_ID_NCIPHER
#define PCI_VENDOR_ID_NCIPHER 0x0100
#endif

#ifndef PCI_SUBSYSTEM_ID_NFAST_REV1
#define PCI_SUBSYSTEM_ID_NFAST_REV1 0x0100
#endif

#define FSL_CFG_SEC_CMD_STATUS 0x4C
#define FSL_CFG_CMD_MASTER 0x10

#define FSL_MEMBAR 1

/* NFAST extended PCI register definitions */

#define NFPCI_OFFSET_JOBS_DS 0x00020000

/* Interrupts from device to host */

#define NFAST_INT_DEVICE_CLR 0x00000000
#define NFAST_INT_DEVICE_CHECK_OK 0x00000100
#define NFAST_INT_DEVICE_CHECK_FAILED 0x00000200
#define NFAST_INT_DEVICE_POLL 0x00000300
#define NFAST_INT_DEVICE_PCI_DOWN 0x00000400

/* Interrupts from host to device */

#define NFAST_INT_HOST_CLR 0x00000000

/* PCI FSL register definitions */

#define FSL_LENGTH NFPCI_RAM_MINSIZE_JOBS
#define FSL_MEMSIZE NFPCI_RAM_MINSIZE_KERN

#define FSL_DOORBELL_LOCATION (FSL_MEMSIZE - 0x100)

#define FSL_OFFSET_DOORBELL_RD_CMD 0x00u
#define FSL_OFFSET_DOORBELL_WR_CMD 0x04u
#define FSL_OFFSET_DOORBELL_RD_STATUS 0x08u
#define FSL_OFFSET_DOORBELL_WR_STATUS 0x0Cu
#define FSL_OFFSET_DOORBELL_CS_STATUS 0x10u

#define FSL_OFFSET_REGISTER_CONTROL 0x20u
#define FSL_OFFSET_REGISTER_STATUS 0x24u
#define FSL_OFFSET_REGISTER_ERROR_LO 0x28u
#define FSL_OFFSET_REGISTER_ERROR_HI 0x2Cu
#define FSL_OFFSET_DOORBELL_POLLING 0x30u

#define FSL_MAGIC 0x12345678u

/* Monitor firmware supports MOI control and error reporting */
#define NFDEV_STATUS_MONITOR_MOI 0x0001

/* Application firmware supports MOI control and error reporting */
#define NFDEV_STATUS_APPLICATION_MOI 0x0002

/* Application firmware running and supports error reporting */
#define NFDEV_STATUS_APPLICATION_RUNNING 0x0004

/**
 * fsl_outl - Writes a 32 bit word across PCI to the FSL card.
 * @ndev:	command device
 * @bar:	base address region id
 * @offset:	offset in bytes from base address
 * @value:	32 bit value being written
 */
static inline void fsl_outl(struct nfp_dev *ndev, int offset, u32 value)
{
	iowrite32(cpu_to_le32(value), ndev->bar[ndev->active_bar] +
		  FSL_DOORBELL_LOCATION + offset);
}

/**
 * fsl_inl - Reads a 32 bit word across PCI from the FSL card.
 * @ndev:	command device
 * @bar:	base address region id
 * @offset:	offset in bytes from base address
 *
 * RETURNS: 32 bit value.
 */
static inline uint32_t fsl_inl(struct nfp_dev *ndev, int offset)
{
	return le32_to_cpu(ioread32(ndev->bar[ndev->active_bar]
			   + FSL_DOORBELL_LOCATION + offset));
}

#endif /* NFP_FSL_H */

/* end of file */

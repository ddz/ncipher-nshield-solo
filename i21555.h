/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *
 * Interfaces to the Solo's Intel 21555 bridge
 * Copyright 2019 nCipher Security Ltd
 *
 */

#ifndef NFP_I21555_H
#define NFP_I21555_H

#include "solo.h"

#ifndef PCI_DEVICE_ID_INTEL_21555
#define PCI_DEVICE_ID_INTEL_21555		0xb555
#endif

#ifndef PCI_VENDOR_ID_NCIPHER
#define PCI_VENDOR_ID_NCIPHER			0x0100
#endif

#ifndef PCI_SUBSYSTEM_ID_NFAST_REV1
#define PCI_SUBSYSTEM_ID_NFAST_REV1		0x0100
#endif

#define I21555_OFFSET_DOORBELL_PRI_SET		0x9C
#define I21555_OFFSET_DOORBELL_SEC_SET		0x9E
#define I21555_OFFSET_DOORBELL_PRI_CLEAR	0x98

#define I21555_OFFSET_DOORBELL_PRI_SET_MASK	0xA4
#define I21555_OFFSET_DOORBELL_PRI_CLEAR_MASK	0xA0

#define I21555_DOORBELL_PRI_ENABLE 0x0000
#define I21555_DOORBELL_PRI_DISABLE 0xFFFF

/* 8 32-bit scratchpad registers start here; bridge manual section 11.4 */
#define I21555_SCRATCHPAD_REGISTER(n)		(0xA8 + 4 * (n))

/* Scratchpad register assignments */
#define I21555_SCRATCHPAD_REGISTER_CONTROL	I21555_SCRATCHPAD_REGISTER(0)
#define I21555_SCRATCHPAD_REGISTER_STATUS	I21555_SCRATCHPAD_REGISTER(1)
#define I21555_SCRATCHPAD_REGISTER_ERROR_LO	I21555_SCRATCHPAD_REGISTER(2)
#define I21555_SCRATCHPAD_REGISTER_ERROR_HI	I21555_SCRATCHPAD_REGISTER(3)

#define I21555_CFG_SEC_CMD_STATUS		0x44

#define CFG_CMD_MASTER				0x0004

#define MEMBAR1					0
#define MEMBAR2					2

/* lower 4k of BAR0 map the 21555 CSRs (doorbell IRQs etc) */
#define MEMBAR1_SIZE 4096

#define CSR_BAR MEMBAR1
#define BAR_SIZES {MEMBAR1_SIZE,                                               \
		   0,                                                          \
		   NFPCI_RAM_MINSIZE_JOBS |                                    \
		   PCI_BASE_ADDRESS_SPACE_PREFETCHABLE,                        \
		   0,                                                          \
		   0,                                                          \
		   0}

#endif /* NFP_I21555_H */

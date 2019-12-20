/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *
 * nshield_solo.h: UAPI header for driving the nCipher PCI HSMs using the
 * nshield_solo module
 */
#ifndef _UAPI_NSHIELD_SOLO_H_
#define _UAPI_NSHIELD_SOLO_H_

#include <linux/types.h>
#include <linux/ioctl.h>

/* Device ioctl struct definitions */

/* Result of the ENQUIRY ioctl. */
struct nfdev_enquiry_str {
	__u32 busno;			/* Which bus is the PCI device on. */
	__u8 slotno;			/* Which slot is the PCI device in. */
	__u8 reserved[3];		/* for consistent struct alignment */
};

/* Result of the STATS ioctl. */
struct nfdev_stats_str {
	__u32 isr;			/* Count interrupts. */
	__u32 isr_read;			/* Count read interrupts. */
	__u32 isr_write;		/* Count write interrupts. */
	__u32 write_fail;		/* Count write failures. */
	__u32 write_block;		/* Count blocks written. */
	__u32 write_byte;		/* Count bytes written. */
	__u32 read_fail;		/* Count read failures. */
	__u32 read_block;		/* Count blocks read. */
	__u32 read_byte;		/* Count bytes read. */
	__u32 ensure_fail;		/* Count read request failures. */
	__u32 ensure;			/* Count read requests. */
};

/* Result of the STATUS ioctl. */
struct nfdev_status_str {
	__u32 status;			/* Status flags. */
	char error[8];			/* Error string. */
};

/* Input to the CONTROL ioctl. */
struct nfdev_control_str {
	__u32 control;			/* Control flags. */
};

/**
 * Index of control bits indicating desired mode
 *
 * Desired mode follows the M_ModuleMode enumeration.
 */
#define NFDEV_CONTROL_MODE_SHIFT	1

/* Monitor firmware supports MOI control and error reporting */
#define NFDEV_STATUS_MONITOR_MOI	0x0001

/* Application firmware supports MOI control and error reporting */
#define NFDEV_STATUS_APPLICATION_MOI	0x0002

/* Application firmware running and supports error reporting */
#define NFDEV_STATUS_APPLICATION_RUNNING 0x0004

/**
 * HSM failed
 *
 * Consult error[] for additional information.
 */
#define NFDEV_STATUS_FAILED		0x0008

/* Standard PCI interface. */
#define NFDEV_IF_STANDARD		0x01

/* PCI interface with read replies pushed from device via DMA. */
#define NFDEV_IF_PCI_PUSH		0x02

/**
 * PCI interface with read replies pushed from device and write requests
 * pulled from host via DMA.
 */
#define NFDEV_IF_PCI_PULL		0x03

/* Maximum PCI interface. */
#define NFDEV_IF_MAX_VERS		NFDEV_IF_PCI_PUSH_PULL

/* platform independent base ioctl numbers */

enum {
	/**
	 * Enquiry ioctl.
	 * return nfdev_enquiry_str describing the attached device.
	 */
	NFDEV_IOCTL_NUM_ENQUIRY = 1,

	/**
	 * Ensure Reading ioctl.
	 * Signal a read request to the device.
	 * param (unsigned int) Length of data to be read.
	 */
	NFDEV_IOCTL_NUM_ENSUREREADING = 3,

	/**
	 * Device Count ioctl.
	 * Not implemented for on all platforms.
	 * return (int) the number of attached devices.
	 */
	NFDEV_IOCTL_NUM_DEVCOUNT = 4,

	/**
	 * PCI Interface Version ioctl.
	 * param (int) Maximum PCI interface version
	 * supported by the user of the device.
	 */
	NFDEV_IOCTL_NUM_PCI_IFVERS = 6,

	/**
	 * Statistics ioctl.
	 * return nfdev_enquiry_str describing the attached device.
	 */
	NFDEV_IOCTL_NUM_STATS = 7,

	/**
	 * Module control ioctl
	 * param (nfdev_control_str) Value to write to HSM
	 * control register
	 */
	NFDEV_IOCTL_NUM_CONTROL = 8,

	/**
	 * Module state ioctl
	 * return (nfdev_status_str) Values read from HSM
	 * status/error registers
	 */
	NFDEV_IOCTL_NUM_STATUS = 9,
};

#define NFDEV_IOCTL_TYPE 0x10

#define NFDEV_IOCTL_ENQUIRY                                                    \
	_IOR(NFDEV_IOCTL_TYPE, NFDEV_IOCTL_NUM_ENQUIRY,                        \
	     struct nfdev_enquiry_str)

#define NFDEV_IOCTL_ENSUREREADING                                              \
	_IOW(NFDEV_IOCTL_TYPE, NFDEV_IOCTL_NUM_ENSUREREADING, int)

#define NFDEV_IOCTL_PCI_IFVERS                                                 \
	_IOW(NFDEV_IOCTL_TYPE, NFDEV_IOCTL_NUM_PCI_IFVERS, int)

#define NFDEV_IOCTL_STATS                                                      \
	_IOR(NFDEV_IOCTL_TYPE, NFDEV_IOCTL_NUM_STATS, struct nfdev_stats_str)

#define NFDEV_IOCTL_CONTROL                                                    \
	_IOW(NFDEV_IOCTL_TYPE, NFDEV_IOCTL_NUM_CONTROL,                        \
	     const struct nfdev_control_str)

#define NFDEV_IOCTL_STATUS                                                     \
	_IOR(NFDEV_IOCTL_TYPE, NFDEV_IOCTL_NUM_STATUS, struct nfdev_status_str)

#endif /* _UAPI_NSHIELD_SOLO_H_ */

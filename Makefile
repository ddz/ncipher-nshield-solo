# SPDX-License-Identifier: GPL-2.0
#
# Makefile for nCipher nShield HSM drivers
#

ifneq ($(KERNELRELEASE),)
include Kbuild

else

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

endif

# SPDX-License-Identifier: GPL-2.0
#
# Kbuild for nCipher nShield HSM drivers
#

obj-m := nshield_solo.o
nshield_solo-y := hostif.o fsl.o i21555.o

ccflags-y := -I$(src)/include/uapi

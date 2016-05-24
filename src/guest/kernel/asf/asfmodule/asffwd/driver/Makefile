#/**************************************************************************
# * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */
include $(KERNEL_PATH)/.config
include $(TOPDIR)/asfconfig.mk

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS

EXTRA_CFLAGS += -Wall -I../../asfffp/driver/
#-DASF_DEBUG
#EXTRA_CFLAGS += -DASF_DEBUG_L2
#EXTRA_CFLAGS += -DASF_FFP_XTRA_STATS=1

obj-m += asffwdcache.o

asffwdcache-y := asffwd.o \
		fwdproc.o #asffwd6.o

ifeq ($(CONFIG_ASF_IPV6), y)
#asf-y += asffwd6.o
endif

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean

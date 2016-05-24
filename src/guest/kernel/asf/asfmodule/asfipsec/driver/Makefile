#/**************************************************************************
# * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */


include $(KERNEL_PATH)/.config
include $(TOPDIR)/asfconfig.mk


KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS

ASF_FP_LINUX_CRYPTO=y
#EXTRA_CFLAGS += -DASF_DEBUG
#EXTRA_CFLAGS += -DASF_IPSEC_DEBUG
#EXTRA_CFLAGS += -DASFIPSEC_DEBUG_FRAME
EXTRA_CFLAGS += -DASF_FP_LINUX_CRYPTO -DASF_SECFP_PROTO_OFFLOAD -I$(KERNEL_PATH)/drivers/virtio
obj-m += asfipsec.o

asfipsec-y := \
	ipsecfp.o \
	ipsfpapi.o \
	ipsecproc.o \
	ipsecfp_innerapi.o

asfipsec-$(CONFIG_ASF_SEC3x) += ipsecfp_sec3x.o
asfipsec-$(CONFIG_ASF_SEC4x) += ipsecfp_sec4x.o
asfipsec-$(CONFIG_ASF_SEC4x) += ipsecfp_ah.o
asfipsec-$(CONFIG_DPA) += ipsecfp_qman.o
#asfipsec-$(CONFIG_VIRTIO) += ipsecvio.o
asfipsec-$(ASF_FP_LINUX_CRYPTO) += ipsec_linux_crypto.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean

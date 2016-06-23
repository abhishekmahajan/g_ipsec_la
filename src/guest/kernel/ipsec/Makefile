include $(KERNEL_PATH)/.config
#include /home/qemu/g_ipsec_la/src/guest/kernel/asf/asfmodule/asfconfig.mk
MODULE_NAME = virtio_ipsec

#change the file(virtio_ipsec.c) name. 
SRC := virtio_ipsec.c ../../common/ipsec/virtio_ipsec_msg.c
$(MODULE_NAME)-objs = $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o

EXTRA_CFLAGS	:= -I$(KERNEL_PATH) -I$(G_IPSEC_LA) -I$(G_IPSEC_LA)/../../common/ipsec -v

all:
	make -C $(KERNEL_PATH) M=$(G_IPSEC_LA) modules

clean:
	make -C $(KERNEL_PATH) M=$(G_IPSEC_LA) clean

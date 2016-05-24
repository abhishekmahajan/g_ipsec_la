#!/bin/bash

ASF_DIR=`pwd`/src/guest/kernel/asf/asfmodule
VIO_IPSEC_DIR=`pwd`/src/guest/kernel/ipsec

all:
	mkdir -p bin/min
	make -C $(VIO_IPSEC_DIR) G_IPSEC_LA=$(VIO_IPSEC_DIR)
	make -C $(ASF_DIR) min
	mv $(ASF_DIR)/bin/min/* bin/min/
	#make -C $(VIO_IPSEC_DIR) G_IPSEC_LA=$(VIO_IPSEC_DIR)
	mv $(VIO_IPSEC_DIR)/virtio_ipsec.ko bin/

clean:
	make -C $(ASF_DIR) clean
	-rm -rf bin/min
	make -C $(VIO_IPSEC_DIR) G_IPSEC_LA=$(VIO_IPSEC_DIR) clean
	-rm bin/virtio_ipsec.ko

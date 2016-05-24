#!/bin/bash

# define build platform/environment
#export ARCH=arm64
#export CROSS_COMPILE=aarch64-linux-gnu-
#export PATH="$PATH":/opt/gcc-linaro-aarch64-linux-gnu-4.8-2013.12_linux/bin
#export KERNEL_PATH=~/ls2-linux-vm
export KERNEL_PATH=/home/qemu/vivid
make $1

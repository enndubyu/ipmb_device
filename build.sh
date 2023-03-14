#!/bin/bash
echo "Building ipmb-device.ko..."
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -j4 all
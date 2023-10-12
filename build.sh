#!/bin/bash
echo "Building ipmb-device.ko..."
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -j4 all
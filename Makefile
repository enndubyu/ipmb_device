#obj-$(CONFIG_IPMB_DEVICE) += ipmb-device.o
obj-m := ipmb_device.o

KERNEL_MODULE_NAME := ipmb_device
KERNELDIR ?= ../linux/

all default: modules
install: modules_install

headers_install:
	@cp ipmb_device.h $(INSTALL_HDR_PATH)/include/linux/

modules modules_install help clean:
	$(MAKE) -C $(KERNELDIR) M=$(shell pwd) $@

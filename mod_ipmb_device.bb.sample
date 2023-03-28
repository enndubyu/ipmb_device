DESCRIPTION = "IPMB device kernel module"
LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://${S}/COPYING;md5=b234ee4d69f5fce4486a80fdaf4a4263"
DEPENDS = "bc-native"

inherit module

PR = "r0"

BRANCH = "master"
SRCREV = "d2b9528992e5c1610a9fbf8866ab82232b8125d6"

SRC_URI = " \
    git://git@github.com:enndubyu/ipmb_device.git;branch=${BRANCH};protocol=ssh \
    "

S = "${WORKDIR}/git"

KERNEL_MODULE_AUTOLOAD += "ipmb_device.ko"

export KERNELDIR = "${STAGING_KERNEL_DIR}"


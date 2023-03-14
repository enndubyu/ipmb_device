/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */

/******************************************************************************
 * Copyright © 2021, Spectranetix Inc, All Rights Reserved. 
 * 
 * File name: ipmb_device.h
 * Library: Linux IPMB Driver
 * 
 * Author: Nick Winterer
 * Created: 8/6/21
 * 
 * Description: Header for userspace programs using ipmb_device driver. Defines
 *              ioctl() commands for enabling and disabling driver features.
 *
 * Commands:
 *   IPMB_IOC_EN_IGNORE_NACK: Enables IGNORE_NACK mode (if supported by i2c backend).
 *                            When enabled, driver will send entire buffer even
 *                            if the slave fails to ACK a byte. On failure, errno
 *                            will be set with one of the following:
 *           EOPNOTSUPP - Backend driver doesn't support I2C protocol mangling
 *
 *   IPMB_IOC_DIS_IGNORE_NACK: Disables IGNORE_NACK mode. Driver will stop transaction
 *                             and write STOP condition to the i2c bus if the slave
 *                             fails to ACK a byte. Default.
 *
 *   IPMB_IOC_ENABLE_CHECKSUM: Enables checksum verification. Driver will attempt
 *                             to NACK IPMB messages with an invalid connection
 *                             header checksum. The user is still responsible for
 *                             verifying the second IPMI checksum.
 *
 *   IPMB_IOC_DISABLE_CHECKSUM: Disables checksum verification. All i2c messages
 *                              will be received even when they are not valid IPMB
 *                              messages. This allows IPMB devices to detect and
 *                              handle checksum errors manually. Default.
 *
 * Usage:
 *     #include <linux/ipmb_device.h>
 *
 *     if (ioctl(fd, IPMB_IOC_EN_IGNORE_NACK, NULL) == -1)
 *         perror("IGNORE_NACK mode not supported");
 *
 ******************************************************************************/
/**
* @file ipmb_device.h
* @brief IOCTL commands for ipmb_device driver
*/

#ifndef IPMB_DEVICE_H
#define IPMB_DEVICE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IPMB_IOC_MAGIC 217

#define IPMB_IOC_EN_IGNORE_NACK		_IO(IPMB_IOC_MAGIC, 1)
#define IPMB_IOC_DIS_IGNORE_NACK	_IO(IPMB_IOC_MAGIC, 2)

#define IPMB_IOC_ENABLE_CHECKSUM	_IO(IPMB_IOC_MAGIC, 3)
#define IPMB_IOC_DISABLE_CHECKSUM	_IO(IPMB_IOC_MAGIC, 4)

#endif

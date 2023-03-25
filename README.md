<center>Intelligent Platform Management Bus (IPMB) Device Driver</center>
----------

This is a linux driver for sending IPMI messages (requests and responses) over the IPMB bus.

#### Example Applications:
  * Satellite MC that needs to be able to send IPMI requests
  * BMC
  * VITA 46.11 Chassis Manager
  * VITA 46.11 Tier-2 IPMC

### Table of Contents
- [Intelligent Platform Management Bus (IPMB) Device Driver](#intelligent-platform-management-bus--ipmb--device-driver)
    * [Motivation](#motivation)
    * [Requirements](#requirements)
    * [Usage](#usage)
    * [Credits](#credits)

### Motivation 
Currently, the mainline linux kernel doesn't have any drivers that can support
sending both requests and responses over IPMB . The `i2c-dev` driver exposes the
i2c bus to userspace, but only supports master i2c transactions. The `ipmb-dev-int`
driver (intended for use in a satellite IPMC) is limited to receiving requests/sending
responses. This driver is a modified version of the `ipmb-dev-int` driver that supports
both sides of the IPMI transaction (requester and responder).

### Requirements

  * Linux kernel version 4.13 or higher.
  * Kconfig
    * enable `CONFIG_I2C_SLAVE`
    * disable `CONFIG_IPMB_DEVICE_INTERFACE`

### Usage

 1. Add nodes to the device tree for each IPMB bus and specify
    the IPMI address (slave address) to use. *(See the 
    `device_tree.dts.sample` file for an example)*
 2. The `/dev/ipmb-<i2c-bus-num>` device can be used to read and write IPMB messages on an i2c bus.
    * `read()` will receive one message per call.
    * `write()` will write one message per call to the address in the message header.
 3. `ioctl()` can be used to enable/disable optional functionality (see [ipmb_device.h](ipmb_device.h)).
 4. Consider using [the select system call](https://man7.org/linux/man-pages/man2/select.2.html),
    [boost.asio](https://www.boost.org/doc/libs/1_76_0/doc/html/boost_asio.html), or
    [libevent](https://libevent.org/) to receive messages asynchronously.

*(See the `usage.c.sample` for a simple example of using this driver to send 
an IPMB msg)*

This is a relatively bare-bones implementation that doesn't make many assumptions
about the structure of the underlying IPMI messages. Apart from extracting the destination
address from the message header and optionally validating the header checksum (see
[ioctl interface](ipmb_device.h)), this driver simply exposes the raw i2c bus to
userspace. The user is responsible for (de)serialization, validation, timeouts and
retry logic, etc.

### Credits

This is based on Mellanox's ipmb_dev_int driver in the mainline linux kernel.

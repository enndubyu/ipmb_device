## <center>Intelligent Platform Management Bus (IPMB) Device Driver</center>

---

This is a linux driver for sending messages over the IPMB bus. This is a relatively
bare-bones implementation that doesn't make any assumptions about the structure of 
the underlying IPMI messages. IPMI requests and responses are both represented as
IPMB messages consisting of a three-byte header (with the destination address, net
function/LUN, and header checksum) plus a payload of between 0 and 255 bytes. Apart
from extracting the destination address from the message header and optionally
validating the header checksum (see ioctl interface), this driver simply exposes
the raw i2c bus to userspace. The user is responsible for (de)serialization,
validation, timeouts and retry logic, etc.

- [IPMB Driver](#intelligent-platform-management-bus-device-driver)
    * [Motivation](#motivation)
    * [Requirements](#requirements)
    * [Usage](#usage)
    * [License](#license)
    * [Credits](#credits)

### Motivation 
Currently, the mainline linux kernel doesn't have any drivers
that can support sending both IPMI requests and responses over IPMB.
The `i2c-dev` driver exposes the i2c bus to userspace, but can only do master
transactions. The `ipmb-dev-int` driver (intended for use in a satellite
IPMC) is limited to receiving requests/sending responses. This driver is a 
modified version of the `ipmb-dev-int` driver that supports both sides of the 
IPMI transaction (requester and responder).

### Requirements

Kernel needs to have been built with `CONFIG_I2C_SLAVE` and the i2c bus driver
for your system needs to support linux's i2c slave interface. Config *should not*
include `CONFIG_IPMB_DEVICE_INTERFACE`.

### Usage

 1. Add nodes to the device tree for each IPMB bus and specify
    the IPMI address (slave address) to use. *(See the 
    `device_tree.dts.sample` file for an example)*
 2. The `/dev/ipmb-<i2c-bus-num>` device can be used to read and
    write IPMB messages on an i2c bus.
 3. `read()` will receive one message per call.
    for reads through an `ioctl()` call.
 4. `write()` will write one message per call. Write will fail and set `errno` to
    `EINVAL` if header checksum is invalid.
 5. An `ioctl()` call can set the driver to immediately NACK messages with invalid
    header checksums. See [ipmb_device.h](ipmb_device.h).
 6. Another `ioctl()` can enable a debug mode where NACKs
    will be ignored while writing a message to the i2c bus (making 
    sure the whole buffer is transmitted over the bus even if the slave
    doesn't respond).
 7. Consider using [the select system call](https://man7.org/linux/man-pages/man2/select.2.html), [boost.asio](https://www.boost.org/doc/libs/1_76_0/doc/html/boost_asio.html),
    or [libevent](https://libevent.org/) to receive messages asynchronously.

*(See the `usage.c.sample` for a simple example of using this driver to send 
an IPMB msg)*

### License 

GPL v2

### Credits

This is based on Mellanox's ipmb_dev_int driver in the mainline linux kernel.

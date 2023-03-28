// SPDX-License-Identifier: GPL-2.0

/******************************************************************************
 * Copyright © 2021, Spectranetix Inc, All Rights Reserved.
 *
 * File name: ipmb_device.c
 * Library: Linux IPMB Driver
 *
 * Author: Nick Winterer
 * Created: 7/12/2021
 *
 * Description: IPMB driver that acts as a low-level interface to the i2c bus,
 *              allowing clients to send both requests and responses. This is
 *              based on the ipmb_dev_int driver, with modifications to support
 *              both sides of the IPMB transaction.
 ******************************************************************************/

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/i2c.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/wait.h>
#include "ipmb_device.h"

#define REQUEST_QUEUE_MAX_LEN 256

#define HEADER_SA_OFFSET 0
#define HEADER_NETFN_OFFSET 1
#define HEADER_CHECKSUM_OFFSET 2

#define IPMB_HEADER_LENGTH 3

#define GET_7BIT_ADDR(addr_8bit) ((addr_8bit) >> 1)
#define GET_8BIT_ADDR(addr_7bit) (((addr_7bit) << 1) & 0xff)

#define GET_IPMB_MESSAGE_BODY(msg) (((const char *)(msg)) + 1)

/*
 * i2c_driver.remove signature changed in version 6.1.0:
 *   old: int (*remove)(struct i2c_client)
 *   new: void (*remove)(struct i2c_client)
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	#define REMOVE_RET_TYPE void
	#define REMOVE_RET_VAL
#else
	#define REMOVE_RET_TYPE int
	#define REMOVE_RET_VAL 0
#endif

/*
 * i2c_driver.probe signature changed in 6.3.0rc3
 *   old: int (*probe)(struct i2c_client, const struct i2c_device_id*)
 *   new: int (*probe)(struct i2c_client)
 *
 * TODO: Maintain separate branches for different branches for different kernel
 *       API versions instead of abusing the preprocessor. We can't even detect
 *       which release candidate with a kernel macro so the fact that this hack
 *       will break builds for v6.3.0rc1 and v6.3.0rc2 is all the more reason to
 *       get rid of it.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0))
	#define PROBE_PARAM_PACK struct i2c_client *client
#else
	#define PROBE_PARAM_PACK struct i2c_client *client, const struct i2c_device_id *id
#endif


struct ipmb_msg {
	u8 payload_len;
	u8 sa;
	u8 netfn_lun;
	u8 checksum;
	u8 payload[U8_MAX];
} __packed;

struct ipmb_request_elem {
	struct list_head list;
	struct ipmb_msg msg;
};

struct ipmb_device {
	struct i2c_client *client;
	struct miscdevice miscdev;
	struct ipmb_msg msg;
	struct list_head msg_queue;
	atomic_t msg_queue_len;
	size_t msg_idx;
	spinlock_t lock;
	wait_queue_head_t wait_queue;
	struct mutex file_mutex;
	bool ignore_nack;
	bool verify_checksum;
};

static inline struct ipmb_device *to_ipmb_dev(struct file *file)
{
	return container_of(file->private_data, struct ipmb_device, miscdev);
}

static ssize_t ipmb_read(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	struct ipmb_device *ipmb_dev = to_ipmb_dev(file);
	struct ipmb_request_elem *queue_elem;
	struct ipmb_msg msg;
	ssize_t ret = 0;

	memset(&msg, 0, sizeof(msg));

	spin_lock_irq(&ipmb_dev->lock);

	while (list_empty(&ipmb_dev->msg_queue)) {
		spin_unlock_irq(&ipmb_dev->lock);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(
			ipmb_dev->wait_queue,
			!list_empty(&ipmb_dev->msg_queue));
		if (ret)
			return ret;

		spin_lock_irq(&ipmb_dev->lock);
	}

	queue_elem = list_first_entry(&ipmb_dev->msg_queue,
				      struct ipmb_request_elem, list);
	memcpy(&msg, &queue_elem->msg, sizeof(msg));
	list_del(&queue_elem->list);
	kfree(queue_elem);
	atomic_dec(&ipmb_dev->msg_queue_len);

	spin_unlock_irq(&ipmb_dev->lock);

	count = min_t(size_t, count, msg.payload_len + IPMB_HEADER_LENGTH);
	if (copy_to_user(buf, GET_IPMB_MESSAGE_BODY(&msg), count))
		ret = -EFAULT;

	return ret < 0 ? ret : count;
}

static int ipmb_i2c_write(struct ipmb_device *ipmb_dev, u8 *msg, u8 len,
			  u8 addr)
{
	struct i2c_msg i2c_msg;

	/* Assign msg to buffer except first bytes (address) */
	i2c_msg.buf = msg + 1;
	i2c_msg.len = len - 1;
	i2c_msg.addr = addr;
	i2c_msg.flags = ipmb_dev->client->flags;

	if (ipmb_dev->ignore_nack)
		i2c_msg.flags |= I2C_M_IGNORE_NAK;

	return i2c_transfer(ipmb_dev->client->adapter, &i2c_msg, 1);
}

static bool ipmb_checksum_verify(u8 sa, u8 netfn_lun, u8 checksum)
{
	/* LSB sums to 0 when header checksum is valid */
	return (u8)(sa + netfn_lun + checksum) == 0;
}

static ssize_t ipmb_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct ipmb_device *ipmb_dev = to_ipmb_dev(file);
	u8 sa;
	u8 msg[sizeof(struct ipmb_msg)];
	ssize_t ret;

	if (count > sizeof(msg) || count < IPMB_HEADER_LENGTH)
		return -EINVAL;
 
	if (copy_from_user(&msg, buf, count))
		return -EFAULT;

	if (!ipmb_checksum_verify(msg[HEADER_SA_OFFSET],
				  msg[HEADER_NETFN_OFFSET],
				  msg[HEADER_CHECKSUM_OFFSET]))
		return -EINVAL;

	sa = GET_7BIT_ADDR(msg[HEADER_SA_OFFSET]);

	ret = ipmb_i2c_write(ipmb_dev, msg, count, sa);
	return (ret == 1) ? count : ret;
}

static __poll_t ipmb_poll(struct file *file, poll_table *wait)
{
	struct ipmb_device *ipmb_dev = to_ipmb_dev(file);
	__poll_t mask = EPOLLOUT;

	mutex_lock(&ipmb_dev->file_mutex);
	poll_wait(file, &ipmb_dev->wait_queue, wait);

	if (atomic_read(&ipmb_dev->msg_queue_len))
		mask |= EPOLLIN;
	mutex_unlock(&ipmb_dev->file_mutex);

	return mask;
}

static long ipmb_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int retval = 0;
	struct ipmb_device *ipmb_dev = to_ipmb_dev(file);

	switch (cmd) {
	case IPMB_IOC_EN_IGNORE_NACK:
		/* Make sure protocol mangling is supported */
		if (i2c_check_functionality(ipmb_dev->client->adapter,
					    I2C_FUNC_PROTOCOL_MANGLING))
			ipmb_dev->ignore_nack = true;
		else
			retval = EOPNOTSUPP;

		break;
	case IPMB_IOC_DIS_IGNORE_NACK:
		ipmb_dev->ignore_nack = false;

		break;

	case IPMB_IOC_ENABLE_CHECKSUM:
		ipmb_dev->verify_checksum = true;

		break;

	case IPMB_IOC_DISABLE_CHECKSUM:
		ipmb_dev->verify_checksum = false;

		break;
	}

	return retval;
}

static const struct file_operations ipmb_fops = {
	.owner = THIS_MODULE,
	.read = ipmb_read,
	.write = ipmb_write,
	.poll = ipmb_poll,
	.unlocked_ioctl = ipmb_ioctl,
};

/* Called with ipmb_device->lock held. */
static void ipmb_handle_request(struct ipmb_device *ipmb_dev)
{
	struct ipmb_request_elem *queue_elem;

	if (atomic_read(&ipmb_dev->msg_queue_len) >= REQUEST_QUEUE_MAX_LEN)
		return;

	queue_elem = kmalloc(sizeof(*queue_elem), GFP_ATOMIC);
	if (!queue_elem)
		return;

	memcpy(&queue_elem->msg, &ipmb_dev->msg, sizeof(struct ipmb_msg));
	list_add(&queue_elem->list, &ipmb_dev->msg_queue);
	atomic_inc(&ipmb_dev->msg_queue_len);
	wake_up_all(&ipmb_dev->wait_queue);
}

/*
 * The IPMB protocol only supports I2C Writes so there is no need
 * to support I2C_SLAVE_READ* events.
 * This i2c callback function only monitors IPMB msg messages
 * and adds them in a queue, so that they can be handled by
 * receive_ipmb_request.
 */
static int ipmb_device_slave_cb(struct i2c_client *client,
				enum i2c_slave_event event, u8 *val)
{
	struct ipmb_device *ipmb_dev = i2c_get_clientdata(client);
	u8 *buf = (u8 *)&ipmb_dev->msg;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&ipmb_dev->lock, flags);
	switch (event) {
	case I2C_SLAVE_WRITE_REQUESTED:
		memset(&ipmb_dev->msg, 0, sizeof(ipmb_dev->msg));
		ipmb_dev->msg_idx = 0;

		/*
		 * At index 0, ipmb_msg stores the length of msg,
		 * skip it for now.
		 * The payload_len will be populated once the whole
		 * buf is populated.
		 *
		 * The I2C bus driver's responsibility is to pass the
		 * data bytes to the backend driver; it does not
		 * forward the i2c slave address.
		 * Since the first byte in the IPMB msg is the
		 * address of the responder, it is the responsibility
		 * of the IPMB driver to format the msg properly.
		 * So this driver prepends the address of the responder
		 * to the received i2c data before the msg msg
		 * is handled in userland.
		 */
		buf[++ipmb_dev->msg_idx] = GET_8BIT_ADDR(client->addr);
		break;

	case I2C_SLAVE_WRITE_RECEIVED:
		if (ipmb_dev->msg_idx >= sizeof(struct ipmb_msg) - 1)
			break;

		buf[++ipmb_dev->msg_idx] = *val;

		/*
		 * Validate checksum immediately after receipt if validation is
		 * enabled. Bus driver will attempt to NACK the transaction in
		 * order to free up the bus immediately.
		 */
		if (ipmb_dev->msg_idx == IPMB_HEADER_LENGTH &&
		    ipmb_dev->verify_checksum &&
		    !ipmb_checksum_verify(ipmb_dev->msg.sa,
					  ipmb_dev->msg.netfn_lun,
					  ipmb_dev->msg.checksum)) {
			ret = -EINVAL;

			/*
			 * SIZE_MAX is used to flag invalid messages so we
			 * know not to add them to the read queue when we
			 * receive the stop signal.
			 */
			ipmb_dev->msg_idx = SIZE_MAX;
		}

		break;

	case I2C_SLAVE_STOP:
		if (ipmb_dev->msg_idx <= sizeof(struct ipmb_msg) - 1) {
			ipmb_dev->msg.payload_len = ipmb_dev->msg_idx - IPMB_HEADER_LENGTH;
			ipmb_handle_request(ipmb_dev);
		}

		break;

	default:
		break;
	}
	spin_unlock_irqrestore(&ipmb_dev->lock, flags);

	return ret;
}

static int ipmb_device_probe(PROBE_PARAM_PACK)
{
	struct ipmb_device *ipmb_dev;
	int ret;

	ipmb_dev = devm_kzalloc(&client->dev, sizeof(*ipmb_dev), GFP_KERNEL);
	if (!ipmb_dev)
		return -ENOMEM;

	spin_lock_init(&ipmb_dev->lock);
	init_waitqueue_head(&ipmb_dev->wait_queue);
	atomic_set(&ipmb_dev->msg_queue_len, 0);
	INIT_LIST_HEAD(&ipmb_dev->msg_queue);

	mutex_init(&ipmb_dev->file_mutex);

	ipmb_dev->ignore_nack = false;

	ipmb_dev->miscdev.minor = MISC_DYNAMIC_MINOR;

	ipmb_dev->miscdev.name =
		devm_kasprintf(&client->dev, GFP_KERNEL, "ipmb-%d",
			       client->adapter->nr);
	ipmb_dev->miscdev.fops = &ipmb_fops;
	ipmb_dev->miscdev.parent = &client->dev;
	ret = misc_register(&ipmb_dev->miscdev);
	if (ret)
		return ret;

	ipmb_dev->client = client;
	i2c_set_clientdata(client, ipmb_dev);
	ret = i2c_slave_register(client, ipmb_device_slave_cb);
	if (ret) {
		misc_deregister(&ipmb_dev->miscdev);
		return ret;
	}

	dev_dbg(ipmb_dev->miscdev.this_device,
		 "registering at address 0x%02x\n", client->addr);

	return 0;
}

static REMOVE_RET_TYPE ipmb_device_remove(struct i2c_client *client)
{
	struct ipmb_device *ipmb_dev = i2c_get_clientdata(client);

	i2c_slave_unregister(client);
	misc_deregister(&ipmb_dev->miscdev);

	return REMOVE_RET_VAL;
}

static const struct i2c_device_id ipmb_device_id[] = { { .name = "ipmb-device" },
						       {} };
MODULE_DEVICE_TABLE(i2c, ipmb_device_id);

static const struct of_device_id ipmb_device_match[] = {
	{ .compatible = "ipmb-device" },
	{}
};
MODULE_DEVICE_TABLE(of, ipmb_device_match);

static struct i2c_driver ipmb_device_driver = {
	.driver = { .name = "ipmb-device",
		    .owner = THIS_MODULE,
		    .of_match_table = ipmb_device_match },
	.id_table = ipmb_device_id,
	.probe = ipmb_device_probe,
	.remove = ipmb_device_remove,
};
module_i2c_driver(ipmb_device_driver);

MODULE_AUTHOR("Nick Winterer <nicholas.winterer@spectranetix.com>");
MODULE_LICENSE("GPL v2");

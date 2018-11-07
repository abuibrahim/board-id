// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for Renesas Board ID 1.0 (based on R5H30211 Secure MCU).
 *
 * Copyright (C) 2016 Ruslan Babayev.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/reset.h>

#define BAA_GN_SP		0x00
#define BAA_GN_FWVERSION	0x01
#define BAA_GN_STATUS		0x03
#define BAA_GN_CONTROL		0x04
#define BAA_GN_UC_NAUTHCOUNT	0x05
#define BAA_GN_UC_RAUTHCOUNT	0x06
#define BAA_GN_UC_LOCATION	0x08
#define BAA_GN_UC_IPP		0x09
#define BAA_CC_SELKEY		0x41
#define BAA_CC_DIGSIGMODE	0x42
#define BAA_CC_NONCE		0x43
#define BAA_CC_SIGNATURE	0x44
#define BAA_CC_CCBID		0x45
#define BAA_CC_DEVKEYCERT0	0x60
#define BAA_GN_EESTORAGE0	0xe0

struct baa_data {
	struct reset_control *rst;
	u32 ver;
	bool prod;
	u8 cert[1536];
	u8 storage[512];
	u8 nonce[32];
	u8 salt[32];
	u8 signature[256];
};

static int baa_i2c_read(struct i2c_client *client, u8 cmd, void *data, u16 len)
{
	struct i2c_msg msgs[2];
	int ret;

	msgs[0].addr = client->addr;
	msgs[0].flags = client->flags;
	msgs[0].len = 1;
	msgs[0].buf = &cmd;

	msgs[1].addr = client->addr;
	msgs[1].flags = client->flags | I2C_M_RD;
	msgs[1].len = len;
	msgs[1].buf = data;

	ret = i2c_transfer(client->adapter, msgs, 2);
	if (ret < 0)
		dev_err(&client->dev, "i2c read failed");

	return (ret == 2) ? 0 : ret;
}

static int baa_i2c_write(struct i2c_client *client, u8 cmd, void *data, u16 len)
{
	struct i2c_msg msgs[1];
	u8 *buffer;
	int ret;

	buffer = kzalloc(len + 1, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	buffer[0] = cmd;
	memcpy(buffer + 1, data, len);

	msgs[0].addr = client->addr;
	msgs[0].flags = client->flags;
	msgs[0].len = len + 1;
	msgs[0].buf = buffer;

	ret = i2c_transfer(client->adapter, msgs, ARRAY_SIZE(msgs));
	if (ret < 0)
		dev_err(&client->adapter->dev, "i2c write failed");

	kfree(buffer);
	return ret;
}

static ssize_t control_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	u8 val;
	int ret;

	ret = baa_i2c_read(client, BAA_GN_CONTROL, &val, 1);
	if (ret < 0)
		return ret;

	return sprintf(buf, "0x%x\n", val);
}

static ssize_t control_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct baa_data *data = dev_get_drvdata(dev);
	u8 cmd, val;
	int ret;

	ret = kstrtou8(buf, 0, &cmd);
	if (ret || cmd != 1)
		return -EINVAL;

	val = 0;
	ret = baa_i2c_write(client, BAA_CC_SELKEY, &val, 1);
	if (ret < 0)
		return ret;

	val = 1;
	ret = baa_i2c_write(client, BAA_CC_DIGSIGMODE, &val, 1);
	if (ret < 0)
		return ret;
	mdelay(500);

	val = 1;
	ret = baa_i2c_write(client, BAA_CC_NONCE, data->nonce,
			    sizeof (data->nonce));
	if (ret < 0)
		return ret;

	ret = baa_i2c_write(client, BAA_GN_CONTROL, &cmd, 1);
	if (ret < 0)
		return ret;

	mdelay(3000);
	ret = baa_i2c_read(client, BAA_GN_STATUS, &val, 1);
	if (ret < 0)
		return ret;

	if (val) {
		dev_err(dev, "status:0x%x", val);
		return -EBUSY;
	}

	ret = baa_i2c_read(client, BAA_CC_SIGNATURE, data->signature,
			   sizeof (data->signature));
	if (ret < 0)
		return ret;

	ret = baa_i2c_read(client, BAA_CC_CCBID, data->salt,
			   sizeof (data->salt));
	if (ret < 0)
		return ret;

	return count;
}

static DEVICE_ATTR_RW(control);

static struct attribute *baa_attrs[] = {
	&dev_attr_control.attr,
	NULL
};

static ssize_t cert_read(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *attr,
			 char *buf, loff_t off, size_t count)
{
	struct baa_data *data = dev_get_drvdata(kobj_to_dev(kobj));

	memcpy(buf, data->cert + 4 + off, count);
	return count;
}

static ssize_t storage_read(struct file *filp, struct kobject *kobj,
			    struct bin_attribute *attr,
			    char *buf, loff_t off, size_t count)
{
	struct baa_data *data = dev_get_drvdata(kobj_to_dev(kobj));

	memcpy(buf, data->storage + off, count);
	return count;
}

static ssize_t nonce_read(struct file *filp, struct kobject *kobj,
			  struct bin_attribute *attr,
			  char *buf, loff_t off, size_t count)
{
	struct baa_data *data = dev_get_drvdata(kobj_to_dev(kobj));

	memcpy(buf, data->nonce + off, count);
	return count;
}

static ssize_t nonce_write(struct file *filp, struct kobject *kobj,
			   struct bin_attribute *attr,
			   char *buf, loff_t off, size_t count)
{
	struct baa_data *data = dev_get_drvdata(kobj_to_dev(kobj));

	if (off + count > attr->size)
		count = attr->size - off;
	memcpy(data->nonce + off, buf, count);
	return count;
}

static ssize_t salt_read(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *attr,
			 char *buf, loff_t off, size_t count)
{
	struct baa_data *data = dev_get_drvdata(kobj_to_dev(kobj));

	memcpy(buf, data->salt + off, count);
	return count;
}

static ssize_t signature_read(struct file *filp, struct kobject *kobj,
			      struct bin_attribute *attr,
			      char *buf, loff_t off, size_t count)
{
	struct baa_data *data = dev_get_drvdata(kobj_to_dev(kobj));

	memcpy(buf, data->signature + off, count);
	return count;
}

static BIN_ATTR_RO(cert, 1536);
static BIN_ATTR_RO(storage, 512);
static BIN_ATTR_RW(nonce, 32);
static BIN_ATTR_RO(salt, 32);
static BIN_ATTR_RO(signature, 256);

static struct bin_attribute *baa_bin_attrs[] = {
	&bin_attr_cert,
	&bin_attr_storage,
	&bin_attr_nonce,
	&bin_attr_salt,
	&bin_attr_signature,
	NULL
};

static const struct attribute_group baa_attr_group = {
	.attrs = baa_attrs,
	.bin_attrs = baa_bin_attrs,
};

static int baa_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct device *dev = &client->dev;
	struct baa_data *data;
	int i, err;
	u32 val;
	u8 sp, *p;

	data = devm_kzalloc(dev, sizeof (*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	i2c_set_clientdata(client, data);

	data->rst = devm_reset_control_get_optional_exclusive(dev, NULL);
	if (PTR_ERR(data->rst) == -EPROBE_DEFER)
		return PTR_ERR(data->rst);

	reset_control_assert(data->rst);
	mdelay(5);
	reset_control_deassert(data->rst);
	mdelay(40);

	err = baa_i2c_read(client, BAA_GN_SP, &sp, 1);
	if (err)
		return err;
	data->prod = sp;

	err = baa_i2c_read(client, BAA_GN_FWVERSION, &val, 4);
	if (err)
		return err;
	data->ver = be32_to_cpu(val);

	p = data->cert;
	for (i = 0; i < 6; i++, p += 256) {
		err = baa_i2c_read(client, BAA_CC_DEVKEYCERT0 + i, p, 256);
		if (err)
			return err;
	}
	if (memcmp(data->cert, "DERt", 4)) {
		dev_err(&client->dev, "invalid certificate");
		return -ENODEV;
	}

	p = data->storage;
	for (i = 0; i < 8; i++, p += 64) {
		err = baa_i2c_read(client, BAA_GN_EESTORAGE0 + i, p, 64);
		if (err)
			return err;
	}

	err = sysfs_create_group(&client->dev.kobj, &baa_attr_group);
	if (err)
		return err;

	dev_info(dev, "%s version 0x%x probed",
		 data->prod ? "production" : "sample", data->ver);

	return 0;
}

static int baa_remove(struct i2c_client *client)
{
	sysfs_remove_group(&client->dev.kobj, &baa_attr_group);

	return 0;
}

static struct i2c_device_id baa_ids[] = {
	{ "board-id", 0 },
	{}
};
MODULE_DEVICE_TABLE(i2c, baa_ids);

static struct i2c_driver baa_driver = {
	.driver = {
		.name	= "board-id",
		.owner	= THIS_MODULE,
	},
	.probe		= baa_probe,
	.remove		= baa_remove,
	.id_table	= baa_ids,
};

module_i2c_driver(baa_driver);

MODULE_AUTHOR("Ruslan Babayev <ruslan@babayev.com>");
MODULE_DESCRIPTION("Renesas Board ID");
MODULE_LICENSE("GPL");

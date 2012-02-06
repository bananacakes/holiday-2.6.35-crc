/* Copyright (c) 2009, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */
/*
 * Qualcomm Marimba Core Driver
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/err.h>

#include <linux/i2c.h>
#include <linux/mfd/marimba.h>

#define MARIMBA_MODE				0x00

#define ADIE_ARRY_SIZE  (CHIP_ID_MAX * MARIMBA_NUM_CHILD)

static int marimba_shadow[ADIE_ARRY_SIZE][0xff];

struct marimba marimba_modules[ADIE_ARRY_SIZE];

#define MARIMBA_VERSION_REG		0x11
#define MARIMBA_MODE_REG		0x00

#if defined(CONFIG_I2C_SSBI) && !defined(CONFIG_MSM8X60_SSBI)
#define NUM_ADD	MARIMBA_NUM_CHILD
#else
#define NUM_ADD	(MARIMBA_NUM_CHILD - 1)
#endif

/**
 * marimba_ssbi_write - Writes a n bit TSADC register in Marimba
 * @param mariba: marimba structure pointer passed by client
 * @param reg: register address
 * @param value: buffer to be written
 * @param len: num of bytes
 * @returns result of the operation.
 */
int marimba_ssbi_write(struct marimba *marimba, u16 reg , u8 *value, int len)
{
	struct i2c_msg *msg;
	int ret;

	marimba = &marimba_modules[marimba->mod_id];

	mutex_lock(&marimba->xfer_lock);

	msg = &marimba->xfer_msg[0];
	msg->addr = reg;
	msg->flags = 0x0;
	msg->buf = value;
	msg->len = len;

	ret = i2c_transfer(marimba->client->adapter, marimba->xfer_msg, 1);

	mutex_unlock(&marimba->xfer_lock);

	return ret;
}
EXPORT_SYMBOL(marimba_ssbi_write);

/**
 * marimba_ssbi_read - Reads a n bit TSADC register in Marimba
 * @param marimba: marimba structure pointer passed by client
 * @param reg: register address
 * @param value: ssbi read of the register to be stored
 * @param len: num of bytes
 *
 * @returns result of the operation.
*/
int marimba_ssbi_read(struct marimba *marimba, u16 reg, u8 *value, int len)
{
	struct i2c_msg *msg;
	int ret;

	marimba = &marimba_modules[marimba->mod_id];

	mutex_lock(&marimba->xfer_lock);

	msg = &marimba->xfer_msg[0];
	msg->addr = reg;
	msg->flags = I2C_M_RD;
	msg->buf = value;
	msg->len = len;

	ret = i2c_transfer(marimba->client->adapter, marimba->xfer_msg, 1);

	mutex_unlock(&marimba->xfer_lock);

	return ret;
}
EXPORT_SYMBOL(marimba_ssbi_read);

/**
 * marimba_write_bit_mask - Sets n bit register using bit mask
 * @param mariba: marimba structure pointer passed by client
 * @param reg: register address
 * @param value: buffer to be written to the registers
 * @param num_bytes: n bytes to write
 * @param mask: bit mask corresponding to the registers
 *
 * @returns result of the operation.
 */
int marimba_write_bit_mask(struct marimba *marimba, u8 reg, u8 *value,
						unsigned num_bytes, u8 mask)
{
	int ret, i;
	struct i2c_msg *msg;
	u8 data[num_bytes + 1];
	u8 mask_value[num_bytes];

	marimba = &marimba_modules[marimba->mod_id];

	mutex_lock(&marimba->xfer_lock);
	memset(mask_value, 0, sizeof(mask_value));

	for (i = 0; i < num_bytes; i++)
		mask_value[i] = (marimba_shadow[marimba->mod_id][reg + i]
					& ~mask) | (value[i] & mask);

	msg = &marimba->xfer_msg[0];
	msg->addr = marimba->client->addr;
	msg->flags = 0;
	msg->len = num_bytes + 1;
	msg->buf = data;
	data[0] = reg;
	memcpy(data+1, mask_value, num_bytes);

	ret = i2c_transfer(marimba->client->adapter, marimba->xfer_msg, 1);

	/* Try again if the write fails */
	if (ret != 1)
		ret = i2c_transfer(marimba->client->adapter,
						marimba->xfer_msg, 1);

	if (ret == 1) {
		for (i = 0; i < num_bytes; i++)
			marimba_shadow[marimba->mod_id][reg + i]
							= mask_value[i];
	} else {
		dev_err(&marimba->client->dev, "i2c write failed\n");
		ret = -ENODEV;
	}

	mutex_unlock(&marimba->xfer_lock);

	return ret;
}
EXPORT_SYMBOL(marimba_write_bit_mask);

/**
 * marimba_write - Sets n bit register in Marimba
 * @param marimba: marimba structure pointer passed by client
 * @param reg: register address
 * @param value: buffer values to be written
 * @param num_bytes: n bytes to write
 *
 * @returns result of the operation.
 */
int marimba_write(struct marimba *marimba, u8 reg, u8 *value,
							unsigned num_bytes)
{
	return marimba_write_bit_mask(marimba, reg, value, num_bytes, 0xff);
}
EXPORT_SYMBOL(marimba_write);

/**
 * marimba_read_bit_mask - Reads a n bit register based on bit mask
 * @param marimba: marimba structure pointer passed by client
 * @param reg: register address
 * @param value: i2c read of the register to be stored
 * @param num_bytes: n bytes to be read.
 * @param mask: bit mask concerning its register
 *
 * @returns result of the operation.
*/
int marimba_read_bit_mask(struct marimba *marimba, u8 reg, u8 *value,
						unsigned num_bytes, u8 mask)
{
	int ret, i;

	struct i2c_msg *msg;

	marimba = &marimba_modules[marimba->mod_id];

	mutex_lock(&marimba->xfer_lock);

	msg = &marimba->xfer_msg[0];
	msg->addr = marimba->client->addr;
	msg->len = 1;
	msg->flags = 0;
	msg->buf = &reg;

	msg = &marimba->xfer_msg[1];
	msg->addr = marimba->client->addr;
	msg->len = num_bytes;
	msg->flags = I2C_M_RD;
	msg->buf = value;

	ret = i2c_transfer(marimba->client->adapter, marimba->xfer_msg, 2);

	/* Try again if read fails first time */
	if (ret != 2)
		ret = i2c_transfer(marimba->client->adapter,
						marimba->xfer_msg, 2);

	if (ret == 2) {
		for (i = 0; i < num_bytes; i++) {
			marimba_shadow[marimba->mod_id][reg + i] = value[i];
			value[i] &= mask;
		}
	} else {
		dev_err(&marimba->client->dev, "i2c read failed\n");
		ret = -ENODEV;
	}

	mutex_unlock(&marimba->xfer_lock);

	return ret;
}
EXPORT_SYMBOL(marimba_read_bit_mask);

/**
 * marimba_read - Reads n bit registers in Marimba
 * @param marimba: marimba structure pointer passed by client
 * @param reg: register address
 * @param value: i2c read of the register to be stored
 * @param num_bytes: n bytes to read.
 * @param mask: bit mask concerning its register
 *
 * @returns result of the operation.
*/
int marimba_read(struct marimba *marimba, u8 reg, u8 *value, unsigned num_bytes)
{
	return marimba_read_bit_mask(marimba, reg, value, num_bytes, 0xff);
}
EXPORT_SYMBOL(marimba_read);

int timpani_read(struct marimba *marimba, u8 reg, u8 *value, unsigned num_bytes)
{
	return marimba_read_bit_mask(marimba, reg, value, num_bytes, 0xff);
}
EXPORT_SYMBOL(timpani_read);

int timpani_write(struct marimba *marimba, u8 reg,
					u8 *value, unsigned num_bytes)
{
	return marimba_write_bit_mask(marimba, reg, value, num_bytes, 0xff);
}
EXPORT_SYMBOL(timpani_write);

static int cur_codec_type = -1, cur_adie_type = -1, cur_connv_type = -1;
static int adie_arry_idx;

int adie_get_detected_codec_type(void)
{
	return cur_codec_type;
}
EXPORT_SYMBOL(adie_get_detected_codec_type);

int adie_get_detected_connectivity_type(void)
{
	return cur_connv_type;
}
EXPORT_SYMBOL(adie_get_detected_connectivity_type);

static struct device *
add_numbered_child(unsigned chip, const char *name, int num, u8 driver_data,
					void *pdata, unsigned pdata_len)
{
	struct platform_device *pdev;
	struct marimba  *marimba = &marimba_modules[chip + adie_arry_idx];
	int status = 0;

	pdev = platform_device_alloc(name, num);
	if (!pdev) {
		status = -ENOMEM;
		return ERR_PTR(status);
	}

	pdev->dev.parent = &marimba->client->dev;

	marimba->mod_id = chip + adie_arry_idx;

	platform_set_drvdata(pdev, marimba);

	if (pdata) {
		status = platform_device_add_data(pdev, pdata, pdata_len);
		if (status < 0)
			goto err;
	}

	status = platform_device_add(pdev);
	if (status < 0)
		goto err;

err:
	if (status < 0) {
		platform_set_drvdata(pdev, NULL);
		platform_device_put(pdev);
		dev_err(&marimba->client->dev, "can't add %s dev\n", name);
		return ERR_PTR(status);
	}
	return &pdev->dev;
}

static inline struct device *add_child(unsigned chip, const char *name,
		u8 driver_data, void *pdata, unsigned pdata_len)
{
	return add_numbered_child(chip, name, -1, driver_data, pdata,
								pdata_len);
}

static int marimba_add_child(struct marimba_platform_data *pdata,
					u8 driver_data)
{
	struct device	*child;

	if (cur_adie_type == MARIMBA_ID) {
		child = add_child(MARIMBA_SLAVE_ID_FM, "marimba_fm",
			driver_data, pdata->fm, sizeof(*pdata->fm));
		if (IS_ERR(child))
			return PTR_ERR(child);
	} else if ((cur_adie_type == BAHAMA_ID) &&
			(cur_connv_type == BAHAMA_ID)) {
		child = add_child(BAHAMA_SLAVE_ID_FM_ID, "marimba_fm",
			driver_data, pdata->fm, sizeof(*pdata->fm));
		if (IS_ERR(child))
			return PTR_ERR(child);
	}

	/* Add Codec for Marimba and Timpani */
	if (cur_adie_type == MARIMBA_ID) {
		child = add_child(MARIMBA_SLAVE_ID_CDC, "marimba_codec",
			driver_data, pdata->codec, sizeof(*pdata->codec));
		if (IS_ERR(child))
			return PTR_ERR(child);
	} else if (cur_adie_type == TIMPANI_ID) {
		child = add_child(MARIMBA_SLAVE_ID_CDC, "timpani_codec",
			driver_data, pdata->codec, sizeof(*pdata->codec));
		if (IS_ERR(child))
			return PTR_ERR(child);
	}

#if defined(CONFIG_I2C_SSBI) && !defined(CONFIG_MSM8X60_SSBI)
	if ((pdata->tsadc != NULL) && (cur_adie_type != BAHAMA_ID)) {
		child = add_child(MARIMBA_ID_TSADC, "marimba_tsadc",
			driver_data, pdata->tsadc, sizeof(*pdata->tsadc));
		if (IS_ERR(child))
			return PTR_ERR(child);
	}
#endif
	return 0;
}

static int get_adie_type(void)
{
	u8 rd_val;
	int ret;

	struct marimba *marimba = &marimba_modules[ADIE_ARRY_SIZE - 1];

	marimba->mod_id = ADIE_ARRY_SIZE - 1;
	/* Enable the Mode for Marimba/Timpani */
	ret = marimba_read(marimba, MARIMBA_MODE_REG, &rd_val, 1);

	if (ret >= 0) {
		if (rd_val & 0x80) {
			cur_adie_type = BAHAMA_ID;
			return cur_adie_type;
		} else {
			ret = marimba_read(marimba,
				MARIMBA_VERSION_REG, &rd_val, 1);
			if ((ret >= 0) && (rd_val & 0x20)) {
				cur_adie_type = TIMPANI_ID;
				return cur_adie_type;
			} else if (ret >= 0) {
				cur_adie_type = MARIMBA_ID;
				return cur_adie_type;
			}
		}
	}

	return ret;
}

static void marimba_init_reg(struct i2c_client *client, u8 driver_data)
{
	struct marimba_platform_data *pdata = client->dev.platform_data;
	struct marimba *marimba =
		&marimba_modules[MARIMBA_SLAVE_ID_MARIMBA + adie_arry_idx];

	u8 buf[1];

	buf[0] = 0x10;

	if (cur_adie_type != BAHAMA_ID) {
		marimba->mod_id = MARIMBA_SLAVE_ID_MARIMBA + adie_arry_idx;
		/* Enable the Mode for Marimba/Timpani */
		marimba_write(marimba, MARIMBA_MODE, buf, 1);
	} else if ((cur_adie_type == BAHAMA_ID) &&
				(cur_connv_type == BAHAMA_ID)) {
		marimba->mod_id = MARIMBA_SLAVE_ID_MARIMBA + adie_arry_idx;
		marimba_write(marimba, BAHAMA_SLAVE_ID_FM_ID,
				&pdata->slave_id[SLAVE_ID_BAHAMA_FM], 1);
		/* Configure Bahama core registers (AREG & DREG) */
		/* with optimal values to eliminate power leakage */
		if (pdata->bahama_core_config != NULL)
			pdata->bahama_core_config(cur_adie_type);
	}
}

static int marimba_probe(struct i2c_client *client,
				const struct i2c_device_id *id)
{
	struct marimba_platform_data *pdata = client->dev.platform_data;
	struct i2c_adapter *ssbi_adap;
	struct marimba *marimba;
	int i, status, rc, client_loop, adie_slave_idx_offset;
	int rc_bahama = 0, rc_marimba = 0;
	int j;

	if (!pdata) {
		dev_dbg(&client->dev, "no platform data?\n");
		return -EINVAL;
	}

	if (i2c_check_functionality(client->adapter, I2C_FUNC_I2C) == 0) {
		dev_dbg(&client->dev, "can't talk I2C?\n");
		return -EIO;
	}

	/* First, identify the codec type */
	if (pdata->marimba_setup != NULL) {
		rc_marimba = pdata->marimba_setup();
		if (rc_marimba)
			pdata->marimba_shutdown();
	}

	if (pdata->bahama_setup != NULL &&
		cur_connv_type != BAHAMA_ID) {
		rc_bahama = pdata->bahama_setup();
		if (rc_bahama)
			pdata->bahama_shutdown(cur_connv_type);
	}

	if (rc_marimba & rc_bahama)
		return -EAGAIN;

	marimba = &marimba_modules[ADIE_ARRY_SIZE - 1];
	marimba->client = client;
	mutex_init(&marimba->xfer_lock);

	/* add retry mechanism to avoid i2c transfer fail */
	for (j = 0; j < 10; j++) {
		rc = get_adie_type();
		if (rc >= 0)
			break;
	}

	mutex_destroy(&marimba->xfer_lock);

	if (rc < 0) {
		if (pdata->bahama_setup != NULL)
			pdata->bahama_shutdown(cur_adie_type);
		if (pdata->marimba_shutdown != NULL)
			pdata->marimba_shutdown();
		return -ENODEV;
	}

	if (rc < 2) {
		adie_arry_idx = 0;
		adie_slave_idx_offset = 0;
		client_loop = 0;
		cur_codec_type = rc;
		if (cur_connv_type < 0)
			cur_connv_type = rc;
		if (pdata->bahama_shutdown != NULL)
			pdata->bahama_shutdown(cur_connv_type);
	} else {
		adie_arry_idx = 5;
		adie_slave_idx_offset = 5;
		client_loop = 1;
		cur_connv_type = rc;
	}

	marimba = &marimba_modules[adie_arry_idx];
	marimba->client = client;
	mutex_init(&marimba->xfer_lock);

	for (i = 1; i <= (NUM_ADD - client_loop); i++) {
		/* Skip adding BT/FM for Timpani */
		if (i == 1 && rc >= 1)
			i++;
		marimba = &marimba_modules[i + adie_arry_idx];
		if (i != MARIMBA_ID_TSADC)
			marimba->client = i2c_new_dummy(client->adapter,
				pdata->slave_id[i + adie_slave_idx_offset]);
		else {
			ssbi_adap = i2c_get_adapter(MARIMBA_SSBI_ADAP);
			marimba->client = i2c_new_dummy(ssbi_adap,
						0x55);
		}
		if (!marimba->client) {
			dev_err(&marimba->client->dev,
				"can't attach client %d\n", i);
			status = -ENOMEM;
			goto fail;
		}
		strlcpy(marimba->client->name, id->name,
			sizeof(marimba->client->name));

		mutex_init(&marimba->xfer_lock);
	}

	marimba_init_reg(client, id->driver_data);

	status = marimba_add_child(pdata, id->driver_data);

	return 0;

fail:
	return status;
}

static int __devexit marimba_remove(struct i2c_client *client)
{
	int i;
	struct marimba_platform_data *pdata;

	pdata = client->dev.platform_data;
	for (i = 0; i < ADIE_ARRY_SIZE; i++) {
		struct marimba *marimba = &marimba_modules[i];

		if (marimba->client && marimba->client != client)
			i2c_unregister_device(marimba->client);

		marimba_modules[i].client = NULL;
	}

	if (pdata->marimba_shutdown != NULL)
		pdata->marimba_shutdown();

	return 0;
}

static struct i2c_device_id marimba_id_table[] = {
	{"marimba", MARIMBA_ID},
	{"timpani", TIMPANI_ID},
	{}
};
MODULE_DEVICE_TABLE(i2c, marimba_id_table);

static struct i2c_driver marimba_driver = {
		.driver			= {
			.owner		=	THIS_MODULE,
			.name		=	"marimba-core",
		},
		.id_table		=	marimba_id_table,
		.probe			=	marimba_probe,
		.remove			=	__devexit_p(marimba_remove),
};

static int __init marimba_init(void)
{
	return i2c_add_driver(&marimba_driver);
}
module_init(marimba_init);

static void __exit marimba_exit(void)
{
	i2c_del_driver(&marimba_driver);
}
module_exit(marimba_exit);

MODULE_DESCRIPTION("Marimba Top level Driver");
MODULE_ALIAS("platform:marimba-core");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("0.1");

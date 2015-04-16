/**
 * @file   rle_conf.c
 * @brief  definition of rle configuration module.
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_conf.h"
#include "constants.h"

#define MODULE_NAME "RLE CONF"

#define IS_NOT_A_BOOLEAN(x) ((x) < C_FALSE || (x) > C_TRUE)

struct rle_configuration {
	uint8_t default_ptype;
	int enable_ptype_compressed;
	int enable_ptype_suppressed;
	int enable_crc_check;
};

struct rle_configuration *rle_conf_new(void)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	struct rle_configuration *_this = MALLOC(sizeof(struct rle_configuration));

	if (!_this) {
		PRINT("ERROR %s %s:%s:%d: allocation for RLE configuration failed\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return NULL;
	}

	rle_conf_init(_this);

	return _this;
}

int rle_conf_destroy(struct rle_configuration *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	if (!_this) {
		PRINT("ERROR %s %s:%s:%d: RLE configuration is NULL\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	FREE(_this);
	_this = NULL;

	return C_OK;
}

void rle_conf_init(struct rle_configuration *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	/* set default values */
	_this->default_ptype = RLE_CONF_DEFAULT_PTYPE;
	_this->enable_ptype_compressed = RLE_CONF_COMPRESS_PTYPE;
	_this->enable_ptype_suppressed = RLE_CONF_SUPPRESS_PTYPE;
	_this->enable_crc_check = C_FALSE;
}

int rle_conf_set_default_ptype(struct rle_configuration *_this, uint8_t protocol_type)
{
	_this->default_ptype = protocol_type;

	return C_OK;
}

int rle_conf_get_default_ptype(struct rle_configuration *_this)
{
	return _this->default_ptype;
}

int rle_conf_set_ptype_compression(struct rle_configuration *_this, int enable_ptype_compression)
{
	if (IS_NOT_A_BOOLEAN(enable_ptype_compression)) {
		PRINT("ERROR %s %s:%s:%d: invalid protocol type compression flag\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->enable_ptype_compressed = enable_ptype_compression;

	return C_OK;
}

int rle_conf_get_ptype_compression(struct rle_configuration *_this)
{
	return _this->enable_ptype_compressed;
}

int rle_conf_set_ptype_suppression(struct rle_configuration *_this, int enable_ptype_suppression)
{
	if (IS_NOT_A_BOOLEAN(enable_ptype_suppression)) {
		PRINT("ERROR %s %s:%s:%d: invalid protocol type suppression flag\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->enable_ptype_suppressed = enable_ptype_suppression;

	return C_OK;
}

int rle_conf_get_ptype_suppression(struct rle_configuration *_this)
{
	return _this->enable_ptype_suppressed;
}

int rle_conf_set_crc_check(struct rle_configuration *_this, int enable_crc_check)
{
	if (IS_NOT_A_BOOLEAN(enable_crc_check)) {
		PRINT("ERROR %s %s:%s:%d: invalid use-CRC flag\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->enable_crc_check = enable_crc_check;

	return C_OK;
}

int rle_conf_get_crc_check(struct rle_configuration *_this)
{
	return _this->enable_crc_check;
}

int ptype_is_omissible(const uint16_t ptype, const struct rle_configuration *const rle_conf)
{
	int status = C_FALSE;

	const int is_suppressible =
	        (rle_conf_get_ptype_suppression((struct rle_configuration *)rle_conf));
	const int ptype_is_signal = (ptype == RLE_PROTO_TYPE_SIGNAL_UNCOMP);

	if (is_suppressible) {
		const uint8_t default_ptype =
		        rle_conf_get_default_ptype((struct rle_configuration *)rle_conf);
		int ptype_is_default_ptype = 0;

		if (default_ptype == RLE_PROTO_TYPE_IP_COMP) {
			ptype_is_default_ptype = (ptype == RLE_PROTO_TYPE_IPV4_UNCOMP);
			ptype_is_default_ptype |= (ptype == RLE_PROTO_TYPE_IPV6_UNCOMP);
		} else {
			ptype_is_default_ptype =
			        (ptype == rle_header_ptype_decompression(default_ptype));
		}

		if (ptype_is_default_ptype) {
			status = C_TRUE;
		}
	}
	if (ptype_is_signal) {
		status = C_TRUE;
	}

	return status;
}

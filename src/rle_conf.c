/**
 * @file   rle_conf.c
 * @author aurelien castanie
 *
 * @brief  definition of rle configuration module.
 *
 *
 */

#include "rle_conf.h"
#include "constants.h"

#define IS_NOT_A_BOOLEAN(x) ((x) < C_FALSE || (x) > C_TRUE)

struct rle_configuration {
	uint16_t default_ptype;
	int enable_ptype_compressed;
	int enable_ptype_suppressed;
	int enable_crc_check;
};

struct rle_configuration *rle_conf_new(struct rle_configuration *_this)
{
	_this = MALLOC(sizeof(struct rle_configuration));

	if (!_this) {
		PRINT("ERROR %s:%s:%d: allocation for RLE configuration failed\n",
				__FILE__, __func__, __LINE__);
		return NULL;
	}

	rle_conf_init(_this);

	return _this;
}

int rle_conf_destroy(struct rle_configuration *_this)
{
	if (!_this) {
		PRINT("ERROR %s:%s:%d: RLE configuration is NULL\n",
				__FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	FREE(_this);
	_this = NULL;

	return C_OK;
}

void rle_conf_init(struct rle_configuration *_this)
{
	/* set default values */
	_this->default_ptype		= RLE_CONF_DEFAULT_PTYPE;
	_this->enable_ptype_compressed	= RLE_CONF_COMPRESS_PTYPE;
	_this->enable_ptype_suppressed	= RLE_CONF_SUPPRESS_PTYPE;
	_this->enable_crc_check		= C_FALSE;
}

int rle_conf_set_default_ptype(struct rle_configuration *_this,
				uint16_t protocol_type)
{
	if ((_this->enable_ptype_compressed && protocol_type > 0xff)) {
		PRINT("ERROR %s:%s:%d: invalid protocol type [0x%0x] for uncompressed field\n",
				__FILE__, __func__, __LINE__, protocol_type);
		return C_ERROR;
	}

	_this->default_ptype = protocol_type;

	return C_OK;
}

int rle_conf_get_default_ptype(struct rle_configuration *_this)
{
	return(_this->default_ptype);
}

int rle_conf_set_ptype_compression(struct rle_configuration *_this,
				int enable_ptype_compression)
{
	if (IS_NOT_A_BOOLEAN(enable_ptype_compression)) {
		PRINT("ERROR %s:%s:%d: invalid protocol type compression flag\n",
				__FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->enable_ptype_compressed = enable_ptype_compression;

	return C_OK;
}

int rle_conf_get_ptype_compression(struct rle_configuration *_this)
{
	return(_this->enable_ptype_compressed);
}

int rle_conf_set_ptype_suppression(struct rle_configuration *_this,
				int enable_ptype_suppression)
{
	if (IS_NOT_A_BOOLEAN(enable_ptype_suppression)) {
		PRINT("ERROR %s:%s:%d: invalid protocol type suppression flag\n",
				__FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->enable_ptype_suppressed = enable_ptype_suppression;

	return C_OK;
}

int rle_conf_get_ptype_suppression(struct rle_configuration *_this)
{
	return(_this->enable_ptype_suppressed);
}

int rle_conf_set_crc_check(struct rle_configuration *_this,
				int enable_crc_check)
{
	if (IS_NOT_A_BOOLEAN(enable_crc_check)) {
		PRINT("ERROR %s:%s:%d: invalid use-CRC flag\n",
				__FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->enable_crc_check = enable_crc_check;

	return C_OK;
}

int rle_conf_get_crc_check(struct rle_configuration *_this)
{
	return(_this->enable_crc_check);
}


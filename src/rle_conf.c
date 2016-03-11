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
#include <stdbool.h>


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "RLE CONF"

#define IS_NOT_A_BOOLEAN(x) ((x) < false || (x) > true)


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------- PRIVATE STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

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


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

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
	_this->enable_crc_check = false;
}

int rle_conf_set_default_ptype(struct rle_configuration *_this, uint8_t protocol_type)
{
	_this->default_ptype = protocol_type;

	return C_OK;
}

int rle_conf_get_default_ptype(const struct rle_configuration *const _this)
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

int rle_conf_get_ptype_compression(const struct rle_configuration *const _this)
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

int rle_conf_get_crc_check(const struct rle_configuration *const _this)
{
	return _this->enable_crc_check;
}

int ptype_is_omissible(const uint16_t ptype, const struct rle_configuration *const rle_conf)
{
	int status = false;

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
			status = true;
		}
	}
	if (ptype_is_signal) {
		status = true;
	}

	return status;
}

enum rle_header_size_status rle_get_header_size(const struct rle_context_configuration *const conf,
                                                const enum rle_fpdu_types fpdu_type,
                                                size_t *const rle_header_size)
{
	enum rle_header_size_status status = RLE_HEADER_SIZE_ERR;
	size_t header_size = 0;

	switch (fpdu_type) {
	case RLE_LOGON_FPDU:

		/* FPDU header. */
		/* payload label = 6 */
		header_size = 6;

		status = RLE_HEADER_SIZE_OK;
		break;

	case RLE_CTRL_FPDU:

		/* FPDU header. */
		/* payload label = 3 */
		header_size = 3;

		status = RLE_HEADER_SIZE_OK;
		break;

	case RLE_TRAFFIC_FPDU:

		/* Unable to guess the headers overhead size */

		status = RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC;
		break;

	case RLE_TRAFFIC_CTRL_FPDU:

		/* FPDU header. */
		/* payload label = 3 */
		header_size = 3;

		/* PPDU header. Only complete PPDU. */
		/* se_length_ltt = 2 */
		/* pdu_label     = 0 */
		header_size += 2 + 0;

		if (conf != NULL) {
			/* ALPDU header. */
			/* protocol_type    = 0. May depends on conf with a different implementation. */
			/* alpdu_label      = 0 */
			/* protection_bytes = 0 */
			header_size += 0 + 0 + 0;
		} else {
			/* ALPDU header. */
			/* protocol_type    = 0 */
			/* alpdu_label      = 0 */
			/* protection_bytes = 0 */
			header_size += 0 + 0 + 0;
		}

		status = RLE_HEADER_SIZE_OK;
		break;
	default:
		break;
	}

	*rle_header_size = header_size;

	return status;
}

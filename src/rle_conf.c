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


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------- PRIVATE STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int ptype_is_omissible(const uint16_t ptype, const struct rle_config *const rle_conf)
{
	int status = false;

	const int is_suppressible = rle_conf->use_ptype_omission;
	const int ptype_is_signal = (ptype == RLE_PROTO_TYPE_SIGNAL_UNCOMP);

	if (is_suppressible) {
		const uint8_t default_ptype = rle_conf->implicit_protocol_type;
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

enum rle_header_size_status rle_get_header_size(const struct rle_config *const conf,
                                                const enum rle_fpdu_types fpdu_type,
                                                size_t *const rle_header_size)
{
	enum rle_header_size_status status = RLE_HEADER_SIZE_ERR;
	size_t header_size = 0;

	if (conf == NULL || rle_header_size == NULL) {
		goto error;
	}

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

		/* ALPDU header. */
		/* protocol_type    = 0. May depends on conf with a different implementation. */
		/* alpdu_label      = 0 */
		/* protection_bytes = 0 */
		header_size += 0 + 0 + 0;

		status = RLE_HEADER_SIZE_OK;
		break;
	default:
		break;
	}

	*rle_header_size = header_size;

error:
	return status;
}

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

bool rle_config_check(const struct rle_config *const conf)
{
	const uint8_t implicit_alpdu_label_size_max = 0x0f;
	const uint8_t implicit_ppdu_label_size_max = 0x0f;
	const uint8_t implicit_payload_label_size_max = 0x0f;

	if (conf == NULL) {
		PRINT_RLE_WARNING("NULL given as configuration");
		return false;
	}
	if (conf->allow_ptype_omission != 0 && conf->allow_ptype_omission != 1) {
		PRINT_RLE_WARNING("configuration parameter allow_ptype_omission set to %d "
		                  "while 0 or 1 expected", conf->allow_ptype_omission);
		return false;
	}
	if (conf->use_compressed_ptype != 0 && conf->use_compressed_ptype != 1) {
		PRINT_RLE_WARNING("configuration parameter use_compressed_ptype set to %d "
		                  "while 0 or 1 expected", conf->use_compressed_ptype);
		return false;
	}
	if (conf->allow_alpdu_crc != 0 && conf->allow_alpdu_crc != 1) {
		PRINT_RLE_WARNING("configuration parameter allow_alpdu_crc set to %d "
		                  "while 0 or 1 expected", conf->allow_alpdu_crc);
		return false;
	}
	if (conf->allow_alpdu_sequence_number != 0 &&
	    conf->allow_alpdu_sequence_number != 1) {
		PRINT_RLE_WARNING("configuration parameter allow_alpdu_sequence_number set "
		                  "to %d while 0 or 1 expected", conf->allow_ptype_omission);
		return false;
	}
	if (conf->allow_alpdu_crc == 0 && conf->allow_alpdu_sequence_number == 0) {
		PRINT_RLE_WARNING("configuration parameters allow_alpdu_crc and "
		                  "allow_alpdu_sequence_number are both set to 0, set at "
		                  "least one of them to 1");
		return false;
	}
	if (conf->use_explicit_payload_header_map != 0 &&
	    conf->use_explicit_payload_header_map != 1) {
		PRINT_RLE_WARNING("configuration parameter use_explicit_payload_header_map "
		                  "set to %d while 0 or 1 expected",
		                  conf->use_explicit_payload_header_map);
		return false;
	}
	if (conf->use_explicit_payload_header_map == 1) {
		PRINT_RLE_WARNING("configuration parameter use_explicit_payload_header_map "
		                  "set to 1 is not supported yet");
		return false;
	}
	if (conf->implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
		PRINT_RLE_ERROR("configuration parameter implicit_protocol_type set to "
		                "0x%02x is not supported yet",
		                RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD);
		return false;
	}
	if (conf->implicit_ppdu_label_size > implicit_ppdu_label_size_max) {
		PRINT_RLE_WARNING("configuration parameter implicit_ppdu_label_size set to "
		                  "%u while only values [0 ; %u] allowed",
		                  conf->implicit_ppdu_label_size,
		                  implicit_ppdu_label_size_max);
		return false;
	}
	if (conf->implicit_payload_label_size > implicit_payload_label_size_max) {
		PRINT_RLE_WARNING("configuration parameter implicit_payload_label_size set "
		                  "to %u while only values [0 ; %u] allowed",
		                  conf->implicit_payload_label_size,
		                  implicit_payload_label_size_max);
		return false;
	}
	if (conf->type_0_alpdu_label_size > implicit_alpdu_label_size_max) {
		PRINT_RLE_WARNING("configuration parameter implicit_alpdu_label_size set to "
		                  "%u while only values [0 ; %u] allowed",
		                  conf->type_0_alpdu_label_size,
		                  implicit_alpdu_label_size_max);
		return false;
	}

	return true;
}

int ptype_is_omissible(const uint16_t ptype, const struct rle_config *const rle_conf)
{
	int status = false;

	const bool is_suppressible = !!rle_conf->allow_ptype_omission;
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

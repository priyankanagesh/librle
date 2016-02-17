/**
 * @file   header.c
 * @brief  RLE encapsulation functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_transmitter.h"
#include "constants.h"
#include "fragmentation_buffer.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"
#include "header.h"

#include "rle.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>

#else

#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "HEADER"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PRIVATE FUNCTIONS --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief         create and push uncompressed ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the SDU protocol_type.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_uncompressed_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                                          const uint16_t protocol_type);

/**
 *  @brief         create and push compressed supported ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the compressed SDU protocol_type.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_compressed_supported_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                                                  const uint8_t protocol_type);

/**
 *  @brief         create and push compressed fallback ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the SDU protocol_type.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_compressed_fallback_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                                                 const uint16_t protocol_type);

/**
 *  @brief         create and push COMPLETE PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff                   the fragmentation buffer in use.
 *  @param[in]     alpdu_label_type         the ALPDU label type field.
 *  @param[in]     protocol_type_suppressed the protocol type suppressed field.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_comp_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                 const uint8_t alpdu_label_type,
                                 const uint8_t protocol_type_suppressed);

/**
 *  @brief         create and push START PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff                   the fragmentation buffer in use.
 *  @param[in]     frag_id                  the fragmentation context ID.
 *  @param[in]     alpdu_label_type         the ALPDU label type field.
 *  @param[in]     protocol_type_suppressed the protocol type suppressed field.
 *  @param[in]     use_alpdu_crc            the use ALPDU CRC field.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_start_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                  const uint8_t frag_id, const uint8_t alpdu_label_type,
                                  const uint8_t protocol_type_suppressed,
                                  const uint8_t use_alpdu_crc);

/**
 *  @brief         create and push CONT PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_cont_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                 const uint8_t frag_id);

/**
 *  @brief         create and push END PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
static int push_end_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                const uint8_t frag_id);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PRIVATE FUNCTIONS CODE ------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int push_uncompressed_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                                          const uint16_t protocol_type)
{
	int status = 1;
	rle_alpdu_header_uncompressed_t **p_alpdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_alpdu_header = (rle_alpdu_header_uncompressed_t **)&f_buff->alpdu.start;

	status = f_buff_alpdu_push(f_buff, sizeof(**p_alpdu_header));

	if (status == 0) {
		(*p_alpdu_header)->proto_type = protocol_type;
	}

	return status;
}

static int push_compressed_supported_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                                                  const uint8_t protocol_type)
{
	int status = 1;
	rle_alpdu_header_compressed_supported_t **p_alpdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_alpdu_header = (rle_alpdu_header_compressed_supported_t **)&f_buff->alpdu.start;

	status = f_buff_alpdu_push(f_buff, sizeof(**p_alpdu_header));

	if (status == 0) {
		(*p_alpdu_header)->proto_type = protocol_type;
	}

	return status;
}

static int push_compressed_fallback_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                                                 const uint16_t protocol_type)
{
	int status = 1;
	rle_alpdu_header_compressed_fallback_t **p_alpdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_alpdu_header = (rle_alpdu_header_compressed_fallback_t **)&f_buff->alpdu.start;

	status = f_buff_alpdu_push(f_buff, sizeof(**p_alpdu_header));

	if (status == 0) {
		(*p_alpdu_header)->compressed.proto_type = RLE_PROTO_TYPE_FALLBACK;
		(*p_alpdu_header)->uncompressed.proto_type = protocol_type;
	}

	return status;
}

static int push_comp_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                 const uint8_t alpdu_label_type,
                                 const uint8_t protocol_type_suppressed)
{
	int status = 1;
	uint16_t ppdu_length_field;
	rle_ppdu_header_comp_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_comp_t **)&f_buff->ppdu.start;

	status = f_buff_ppdu_push(f_buff, sizeof(**p_ppdu_header));

	if (status == 0) {
		ppdu_length_field = f_buff_get_current_ppdu_len(f_buff) -
		                            f_buff_get_ppdu_header_len(f_buff);

		(*p_ppdu_header)->start_ind = 1;
		(*p_ppdu_header)->end_ind = 1;
		rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header, ppdu_length_field);
		(*p_ppdu_header)->label_type = alpdu_label_type;
		(*p_ppdu_header)->proto_type_supp = protocol_type_suppressed;
	}

	return status;
}

static int push_start_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                  const uint8_t frag_id, const uint8_t alpdu_label_type,
                                  const uint8_t protocol_type_suppressed,
                                  const uint8_t use_alpdu_crc)
{
	int status = 1;
	uint16_t ppdu_length_field;
	uint16_t total_length_field;
	rle_ppdu_header_start_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_start_t **)&f_buff->ppdu.start;

	status = f_buff_ppdu_push(f_buff, sizeof(**p_ppdu_header));

	ppdu_length_field = f_buff_get_current_ppdu_len(f_buff) - f_buff_get_ppdu_header_len(f_buff);
	total_length_field = f_buff_get_alpdu_header_len(f_buff) + f_buff->sdu_info.size +
	                             f_buff_get_alpdu_trailer_len(f_buff);

	if (status == 0) {
		(*p_ppdu_header)->start_ind = 1;
		(*p_ppdu_header)->end_ind = 0;
		rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header, ppdu_length_field);
		(*p_ppdu_header)->frag_id = frag_id;
		(*p_ppdu_header)->use_crc = use_alpdu_crc;
		rle_ppdu_header_start_set_total_length(*p_ppdu_header, total_length_field);
		(*p_ppdu_header)->label_type = alpdu_label_type;
		(*p_ppdu_header)->proto_type_supp = protocol_type_suppressed;
	}

	return status;
}

static int push_cont_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                 const uint8_t frag_id)
{
	int status = 1;
	uint16_t ppdu_length_field;
	rle_ppdu_header_cont_end_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_cont_end_t **)&f_buff->ppdu.start;

	status = f_buff_ppdu_push(f_buff, sizeof(**p_ppdu_header));

	ppdu_length_field = f_buff_get_current_ppdu_len(f_buff) - f_buff_get_ppdu_header_len(f_buff);

	if (status == 0) {
		(*p_ppdu_header)->start_ind = 0;
		(*p_ppdu_header)->end_ind = 0;
		rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header, ppdu_length_field);
		(*p_ppdu_header)->frag_id = frag_id;
	}

	return status;
}

static int push_end_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                                const uint8_t frag_id)
{
	int status = 1;
	uint16_t ppdu_length_field;
	rle_ppdu_header_cont_end_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_cont_end_t **)&f_buff->ppdu.start;

	status = f_buff_ppdu_push(f_buff, sizeof(**p_ppdu_header));

	ppdu_length_field = f_buff_get_current_ppdu_len(f_buff) - f_buff_get_ppdu_header_len(f_buff);

	if (status == 0) {
		(*p_ppdu_header)->start_ind = 0;
		(*p_ppdu_header)->end_ind = 1;
		rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header, ppdu_length_field);
		(*p_ppdu_header)->frag_id = frag_id;
	}

	return status;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS CODE-------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int push_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                      const struct rle_configuration *const rle_conf)
{
	int status = 1;
	uint16_t protocol_type;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	protocol_type = f_buff->sdu_info.protocol_type;

	/* ALPDU: 4 cases, len € {0,1,2,3} */

	/* don't fill ALPDU ptype field if given ptype is equal to the default one and suppression is
	 * active, or if given ptype is for signalling packet */
	if (!ptype_is_omissible(protocol_type, rle_conf)) {

		const uint16_t net_protocol_type = ntohs(protocol_type);

		if (!rle_conf_get_ptype_compression(rle_conf)) {
			/* No compression, no suppression, ALPDU len = 2 */
			status = push_uncompressed_alpdu_header(f_buff, net_protocol_type);
		} else {
			/* No suppression, compression */
			if (rle_header_ptype_is_compressible(protocol_type) == C_OK) {
				/* Supported case, ALPDU len = 1 */
				uint8_t compressed_ptype = rle_header_ptype_compression(protocol_type);
				status = push_compressed_supported_alpdu_header(f_buff, compressed_ptype);
			} else {
				/* Fallback case, ALPDU len = 3 */
				status = push_compressed_fallback_alpdu_header(f_buff, net_protocol_type);
			}
		}
	} else {
		/* Nothing to do, ALDPU len == 0 */
		status = 0;
	}

	return status;
}

int push_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                     const struct rle_configuration *const rle_conf,
                     const size_t ppdu_length, struct rle_ctx_management *const rle_ctx)
{
	int status = 1;
	size_t alpdu_fragment_len = ppdu_length;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (f_buff_is_fragmented(f_buff)) {

		if (!rle_ctx) {
			PRINT_RLE_ERROR("RLE context needed.");
			goto out;
		}

		if (ppdu_length < sizeof(rle_ppdu_header_cont_end_t)) {
			status = 2;
			goto out;
		}

		alpdu_fragment_len -= sizeof(rle_ppdu_header_cont_end_t);
		/* /!\ TODO Currently 0-octets wide ALPDU fragment accepted /!\ */

		if (f_buff_get_remaining_alpdu_length(f_buff) > alpdu_fragment_len) {

			/* Continuation PPDU */

			f_buff_ppdu_put(f_buff, ppdu_length - sizeof(rle_ppdu_header_cont_end_t));

			status = push_cont_ppdu_header(f_buff, rle_ctx->frag_id);
		} else {

			/* End PPDU */

			f_buff_ppdu_put(f_buff, ppdu_length - sizeof(rle_ppdu_header_cont_end_t));

			status = push_end_ppdu_header(f_buff, rle_ctx->frag_id);
		}
	} else {

		const int protocol_type_suppressed = (f_buff_get_alpdu_header_len(f_buff) == 0);
		const int alpdu_label_type = get_alpdu_label_type(f_buff->sdu_info.protocol_type,
		                                                  protocol_type_suppressed);

		alpdu_fragment_len -= sizeof(rle_ppdu_header_comp_t);

		if (f_buff_get_remaining_alpdu_length(f_buff) > alpdu_fragment_len) {

			/* Start PPDU */

			const int use_alpdu_crc = rle_conf_get_crc_check((struct rle_configuration *)rle_conf);

			if (!rle_ctx) {
				PRINT_RLE_ERROR("RLE context needed.");
				goto out;
			}

			if (ppdu_length < sizeof(rle_ppdu_header_start_t)) {
				status = 2;
				goto out;
			}

			push_alpdu_trailer(f_buff, rle_conf, rle_ctx);

			f_buff_ppdu_put(f_buff, ppdu_length - sizeof(rle_ppdu_header_start_t));


			status = push_start_ppdu_header(f_buff, rle_ctx->frag_id, alpdu_label_type,
			                                protocol_type_suppressed, use_alpdu_crc);
		} else {

			/* Complete PPDU */
			if (ppdu_length < sizeof(rle_ppdu_header_comp_t)) {
				status = 2;
				goto out;
			}

			f_buff_ppdu_put(f_buff, ppdu_length - sizeof(rle_ppdu_header_comp_t));

			status = push_comp_ppdu_header(f_buff, alpdu_label_type, protocol_type_suppressed);
		}
	}

	status |= f_buff_set_cur_pos(f_buff);

	status = 0;

out:
	return status;
}

int comp_ppdu_extract_alpdu_fragment(const unsigned char comp_ppdu[], const size_t ppdu_len,
                                     const unsigned char *alpdu_fragment[],
                                     size_t *alpdu_fragment_len)
{
	int status = 0;

	const rle_ppdu_header_comp_t *const comp_ppdu_header = (rle_ppdu_header_comp_t *)comp_ppdu;

	*alpdu_fragment = comp_ppdu + sizeof(rle_ppdu_header_comp_t);
	*alpdu_fragment_len = rle_ppdu_header_get_ppdu_length((rle_ppdu_header_t *)comp_ppdu_header);

	if (ppdu_len != sizeof(rle_ppdu_header_comp_t) + *alpdu_fragment_len) {
		PRINT_RLE_ERROR("corrupted PPDU, expected ALPDU fragment length: %zu, retrieved one: %zu.",
		                ppdu_len - sizeof(rle_ppdu_header_comp_t), *alpdu_fragment_len);
		status = 1;
	}

	return status;
}

int start_ppdu_extract_alpdu_fragment(const unsigned char start_ppdu[], const size_t ppdu_len,
                                      const unsigned char *alpdu_fragment[],
                                      size_t *const alpdu_fragment_len,
                                      size_t *const alpdu_total_len, int *const is_crc_used)
{
	int status = 0;

	const rle_ppdu_header_start_t *const start_ppdu_header = (rle_ppdu_header_start_t *)start_ppdu;

	*alpdu_fragment = start_ppdu + sizeof(rle_ppdu_header_start_t);
	*alpdu_fragment_len = rle_ppdu_header_get_ppdu_length((rle_ppdu_header_t *)start_ppdu_header);
	*alpdu_total_len = rle_ppdu_header_start_get_total_length(start_ppdu_header);
	*is_crc_used = start_ppdu_header->use_crc;

	if (ppdu_len != sizeof(rle_ppdu_header_start_t) + *alpdu_fragment_len) {
		PRINT_RLE_ERROR("corrupted PPDU, expected ALPDU fragment length: %zu, retrieved one: %zu.",
		                ppdu_len - sizeof(rle_ppdu_header_start_t), *alpdu_fragment_len);
		status = 1;
	}

	return status;
}

int cont_end_ppdu_extract_alpdu_fragment(const unsigned char cont_end_ppdu[], const size_t ppdu_len,
                                         const unsigned char *alpdu_fragment[],
                                         size_t *const alpdu_fragment_len)
{
	int status = 0;

	const rle_ppdu_header_cont_end_t *const cont_end_ppdu_header =
	        (rle_ppdu_header_cont_end_t *)cont_end_ppdu;

	*alpdu_fragment = cont_end_ppdu + sizeof(rle_ppdu_header_cont_end_t);
	*alpdu_fragment_len = rle_ppdu_header_get_ppdu_length(
	                              (rle_ppdu_header_t *)cont_end_ppdu_header);

	if (ppdu_len != sizeof(rle_ppdu_header_cont_end_t) + *alpdu_fragment_len) {
		PRINT_RLE_ERROR("corrupted PPDU, expected ALPDU fragment length: %zu, retrieved one: %zu.",
		                ppdu_len - sizeof(rle_ppdu_header_cont_end_t), *alpdu_fragment_len);
		status = 1;
	}

	return status;
}

int signal_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                      const size_t alpdu_fragment_len, uint16_t *protocol_type,
                                      const unsigned char *sdu_fragment[],
                                      size_t *const sdu_fragment_len)
{
	*protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
	*sdu_fragment = alpdu_fragment;
	*sdu_fragment_len = alpdu_fragment_len;

	return 0;
}

int suppressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                          const size_t alpdu_fragment_len, uint16_t *protocol_type,
                                          const unsigned char *sdu_fragment[],
                                          size_t *const sdu_fragment_len,
                                          const struct rle_configuration *const rle_conf)
{
	int status = 0;
	const uint8_t default_ptype = rle_conf_get_default_ptype(rle_conf);

	*sdu_fragment = alpdu_fragment;
	*sdu_fragment_len = alpdu_fragment_len;

	if (default_ptype == RLE_PROTO_TYPE_IP_COMP) {
		uint8_t ip_version = (*sdu_fragment[0] >> 4) & 0x0F;
		if (ip_version == 4) {
			*protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP;
		} else if (ip_version == 6) {
			*protocol_type = RLE_PROTO_TYPE_IPV6_UNCOMP;
		} else {
			PRINT_RLE_ERROR("Unsupported IP Version %d\n", ip_version);
			status = 1;
			goto out;
		}
	} else {
		*protocol_type = rle_header_ptype_decompression(default_ptype);
	}

out:
	return status;
}

int uncompressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                            const size_t alpdu_fragment_len,
                                            uint16_t *protocol_type,
                                            const unsigned char *sdu_fragment[],
                                            size_t *const sdu_fragment_len)
{
	int status = 0;
	const rle_alpdu_header_uncompressed_t *const uncompressed_alpdu_header =
	        (rle_alpdu_header_uncompressed_t *)alpdu_fragment;

	if (alpdu_fragment_len < sizeof(rle_alpdu_header_uncompressed_t)) {
		PRINT_RLE_ERROR("Invalid alpdu fragment len: %zu\n", alpdu_fragment_len);
		status = 1;
		goto out;
	}
	*protocol_type = htons(uncompressed_alpdu_header->proto_type);
	*sdu_fragment = alpdu_fragment + sizeof(rle_alpdu_header_uncompressed_t);
	*sdu_fragment_len = alpdu_fragment_len - sizeof(rle_alpdu_header_uncompressed_t);

out:
	return status;
}

int compressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                          const size_t alpdu_fragment_len, uint16_t *protocol_type,
                                          const unsigned char *sdu_fragment[],
                                          size_t *const sdu_fragment_len,
                                          size_t *const sdu_total_len)
{
	int status = 0;
	const rle_alpdu_header_t *const alpdu_header = (rle_alpdu_header_t *)alpdu_fragment;
	const uint8_t compressed_protocol_type = alpdu_header->compressed_supported.proto_type;

	if (compressed_protocol_type == RLE_PROTO_TYPE_FALLBACK) {
		if (alpdu_fragment_len < sizeof(alpdu_header->compressed_fallback)) {
			PRINT_RLE_ERROR("Alpdu fragment smaller (%zu) than a header (%zu)\n", alpdu_fragment_len,
			                sizeof(alpdu_header->compressed_fallback));
			status = 1;
			goto out;
		}
		*protocol_type = htons(alpdu_header->compressed_fallback.uncompressed.proto_type);
		*sdu_fragment = alpdu_fragment + sizeof(alpdu_header->compressed_fallback);
		*sdu_fragment_len = alpdu_fragment_len - sizeof(alpdu_header->compressed_fallback);
		if (sdu_total_len) {
			*sdu_total_len -= sizeof(alpdu_header->compressed_fallback);
		}
	} else {
		if (alpdu_fragment_len < sizeof(alpdu_header->compressed_supported)) {
			PRINT_RLE_ERROR("Alpdu fragment smaller (%zu) than a header (%zu)\n", alpdu_fragment_len,
			                sizeof(alpdu_header->compressed_supported));
			status = 1;
			goto out;
		}
		*protocol_type = rle_header_ptype_decompression(alpdu_header->compressed_supported.proto_type);
		*sdu_fragment = alpdu_fragment + sizeof(alpdu_header->compressed_supported);
		*sdu_fragment_len = alpdu_fragment_len - sizeof(alpdu_header->compressed_supported);
		if (sdu_total_len) {
			*sdu_total_len -= sizeof(alpdu_header->compressed_supported);
		}
	}

out:
	return status;
}

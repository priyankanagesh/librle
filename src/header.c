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
#include "crc.h"

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
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the SDU protocol_type.
 *
 *  @ingroup
 */
static void push_uncompressed_alpdu_header(struct rle_frag_buf *const frag_buf,
                                           const uint16_t protocol_type);

/**
 *  @brief         create and push compressed supported ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the compressed SDU protocol_type.
 *
 *  @ingroup
 */
static void push_compressed_supported_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                   const uint8_t protocol_type);

/**
 *  @brief         create and push compressed fallback ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the SDU protocol_type.
 *
 *  @ingroup
 */
static void push_compressed_fallback_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                  const uint16_t protocol_type);

/**
 *  @brief         create and push COMPLETE PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf                   the fragmentation buffer in use.
 *  @param[in]     alpdu_label_type         the ALPDU label type field.
 *  @param[in]     protocol_type_suppressed the protocol type suppressed field.
 *
 *  @ingroup
 */
static void push_comp_ppdu_header(struct rle_frag_buf *const frag_buf,
                                  const uint8_t alpdu_label_type,
                                  const uint8_t protocol_type_suppressed);

/**
 *  @brief         create and push START PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf                   the fragmentation buffer in use.
 *  @param[in]     frag_id                  the fragmentation context ID.
 *  @param[in]     alpdu_label_type         the ALPDU label type field.
 *  @param[in]     protocol_type_suppressed the protocol type suppressed field.
 *  @param[in]     use_alpdu_crc            the use ALPDU CRC field.
 *
 *  @ingroup
 */
static void push_start_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id,
                                   const uint8_t alpdu_label_type,
                                   const uint8_t protocol_type_suppressed,
                                   const bool use_alpdu_crc);

/**
 *  @brief         create and push CONT PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @ingroup
 */
static void push_cont_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id);

/**
 *  @brief         create and push END PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @ingroup
 */
static void push_end_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PRIVATE FUNCTIONS CODE ------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static void push_uncompressed_alpdu_header(struct rle_frag_buf *const frag_buf,
                                           const uint16_t protocol_type)
{
	rle_alpdu_header_uncompressed_t **p_alpdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_alpdu_header = (rle_alpdu_header_uncompressed_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**p_alpdu_header));
	(*p_alpdu_header)->proto_type = protocol_type;
}

static void push_compressed_supported_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                   const uint8_t protocol_type)
{
	rle_alpdu_header_compressed_supported_t **p_alpdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_alpdu_header = (rle_alpdu_header_compressed_supported_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**p_alpdu_header));
	(*p_alpdu_header)->proto_type = protocol_type;
}

static void push_compressed_fallback_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                  const uint16_t protocol_type)
{
	rle_alpdu_header_compressed_fallback_t **p_alpdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_alpdu_header = (rle_alpdu_header_compressed_fallback_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**p_alpdu_header));
	(*p_alpdu_header)->compressed.proto_type = RLE_PROTO_TYPE_FALLBACK;
	(*p_alpdu_header)->uncompressed.proto_type = protocol_type;
}

static void push_comp_ppdu_header(struct rle_frag_buf *const frag_buf,
                                  const uint8_t alpdu_label_type,
                                  const uint8_t protocol_type_suppressed)
{
	uint16_t ppdu_length_field;
	rle_ppdu_header_comp_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_comp_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) -
	                    frag_buf_get_ppdu_header_len(frag_buf);

	(*p_ppdu_header)->start_ind = 1;
	(*p_ppdu_header)->end_ind = 1;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->label_type = alpdu_label_type;
	(*p_ppdu_header)->proto_type_supp = protocol_type_suppressed;
}

static void push_start_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id,
                                   const uint8_t alpdu_label_type,
                                   const uint8_t protocol_type_suppressed,
                                   const bool use_alpdu_crc)
{
	uint16_t ppdu_length_field;
	uint16_t total_length_field;
	rle_ppdu_header_start_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_start_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - frag_buf_get_ppdu_header_len(
	        frag_buf);
	total_length_field = frag_buf_get_alpdu_header_len(frag_buf) + frag_buf->sdu_info.size +
	                     frag_buf_get_alpdu_trailer_len(frag_buf);

	(*p_ppdu_header)->start_ind = 1;
	(*p_ppdu_header)->end_ind = 0;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->frag_id = frag_id;
	(*p_ppdu_header)->use_crc = (use_alpdu_crc ? 1 : 0);
	rle_ppdu_header_start_set_total_length(*p_ppdu_header, total_length_field);
	(*p_ppdu_header)->label_type = alpdu_label_type;
	(*p_ppdu_header)->proto_type_supp = protocol_type_suppressed;
}

static void push_cont_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id)
{
	uint16_t ppdu_length_field;
	rle_ppdu_header_cont_end_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_cont_end_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - frag_buf_get_ppdu_header_len(
	        frag_buf);

	(*p_ppdu_header)->start_ind = 0;
	(*p_ppdu_header)->end_ind = 0;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->frag_id = frag_id;
}

static void push_end_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id)
{
	uint16_t ppdu_length_field;
	rle_ppdu_header_cont_end_t **p_ppdu_header;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	p_ppdu_header = (rle_ppdu_header_cont_end_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - frag_buf_get_ppdu_header_len(
	        frag_buf);

	(*p_ppdu_header)->start_ind = 0;
	(*p_ppdu_header)->end_ind = 1;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->frag_id = frag_id;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS CODE-------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

void push_alpdu_header(struct rle_frag_buf *const frag_buf,
                       const struct rle_config *const rle_conf)
{
	uint16_t protocol_type;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	protocol_type = frag_buf->sdu_info.protocol_type;

	/* ALPDU: 4 cases, len € {0,1,2,3} */

	/* don't fill ALPDU ptype field if given ptype is equal to the default one and suppression is
	 * active, or if given ptype is for signalling packet */
	if (!ptype_is_omissible(protocol_type, rle_conf)) {
		const uint16_t net_protocol_type = ntohs(protocol_type);

		if (!rle_conf->use_compressed_ptype) {
			/* No compression, no suppression, ALPDU len = 2 */
			push_uncompressed_alpdu_header(frag_buf, net_protocol_type);
		} else {
			/* No suppression, compression */
			if (rle_header_ptype_is_compressible(protocol_type) == C_OK) {
				/* Supported case, ALPDU len = 1 */
				uint8_t compressed_ptype = rle_header_ptype_compression(
				        protocol_type);
				push_compressed_supported_alpdu_header(frag_buf, compressed_ptype);
			} else {
				/* Fallback case, ALPDU len = 3 */
				push_compressed_fallback_alpdu_header(frag_buf, net_protocol_type);
			}
		}
	} else {
		/* Nothing to do, ALDPU len == 0 */
	}
}

int push_ppdu_header(struct rle_frag_buf *const frag_buf,
                     const struct rle_config *const rle_conf,
                     const size_t ppdu_length,
                     struct rle_ctx_management *const rle_ctx)
{
	int status = 1;
	size_t max_alpdu_fragment_len = ppdu_length;
	const size_t remain_alpdu_len = frag_buf_get_remaining_alpdu_length(frag_buf);
	const bool use_alpdu_crc =
		(rle_conf->allow_alpdu_sequence_number ? false : !!rle_conf->allow_alpdu_crc);

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (frag_buf_is_fragmented(frag_buf)) {
		/* ALPDU is fragmented, use CONT or END PPDU */

		/* RLE context needed if ALPDU is fragmented */
		assert(rle_ctx != NULL);

		if (ppdu_length < sizeof(rle_ppdu_header_cont_end_t)) {
			/* buffer is too small for the smallest PPDU CONT or END fragment */
			status = 2;
			goto out;
		}

		max_alpdu_fragment_len -= sizeof(rle_ppdu_header_cont_end_t);

		/* /!\ TODO Currently 0-octets wide ALPDU fragment accepted /!\ */

		/* Determine whether a END PPDU is possible or not: a END PPDU is possible only if all
		 * remaining ALPDU bytes may fit into the available room after the END PPDU header
		 *
		 * If END PPDU is not possible, use a CONT PPDU. The RLE reassembler does not support
		 * when the ALPDU trailer (CRC or seqnum) is fragmented. The seqnum fits into one
		 * single byte, so it cannot be fragmented. The CRC fits into 32 bits. So, if the RLE
		 * transmitter is configured for CRC, we should avoid to fragment the last 4 bytes of
		 * the ALPDU.
		 * Note: the `remain_alpdu_len` contain the ALPDU trailer length */
		if (remain_alpdu_len <= max_alpdu_fragment_len) {
			/* END PPDU is possible: put all remaining bytes into the PPDU payload, then build
			 * the END PPDU header before the payload */
			frag_buf_ppdu_put(frag_buf, remain_alpdu_len);
			push_end_ppdu_header(frag_buf, rle_ctx->frag_id);

		} else {
			/* CONT PPDU is required: determine whether the trailer is fully contained in the
			 * next PPDU fragment or not ; if not, the trailer would be fragmented, so make
			 * the CONT PPDU fragment smaller to avoid the trailer fragmentation */

			const size_t trailer_len = (use_alpdu_crc ? RLE_CRC_SIZE : 0);
			const size_t alpdu_overflow_len = remain_alpdu_len - max_alpdu_fragment_len;

			if (alpdu_overflow_len < trailer_len) {
				/* the number of ALPDU bytes that will be put in the next fragments is smaller
				 * than the ALPDU trailer, so the current CONT PPDU contains some bytes of the
				 * trailer, so make the PPDU fragment shorter */

				size_t trailer_len_in_cur_ppdu = trailer_len - alpdu_overflow_len;

				frag_buf_ppdu_put(frag_buf, max_alpdu_fragment_len - trailer_len_in_cur_ppdu);
				push_cont_ppdu_header(frag_buf, rle_ctx->frag_id);

			} else {
				/* the ALPDU trailer will be fully transmitted in one of the next fragments,
				 * there is no risk of trailer fragmentation, so use the full room of the buffer */
				frag_buf_ppdu_put(frag_buf, max_alpdu_fragment_len);
				push_cont_ppdu_header(frag_buf, rle_ctx->frag_id);
			}
		}

	} else {
		const bool protocol_type_suppressed = (frag_buf_get_alpdu_header_len(frag_buf) == 0);
		const uint8_t alpdu_label_type =
			get_alpdu_label_type(frag_buf->sdu_info.protocol_type,
			                     protocol_type_suppressed,
			                     rle_conf->type_0_alpdu_label_size);

		max_alpdu_fragment_len -= sizeof(rle_ppdu_header_comp_t);

		if (remain_alpdu_len > max_alpdu_fragment_len) {
			/* Start PPDU */

			const size_t ppdu_and_alpdu_hdrs_len =
				sizeof(rle_ppdu_header_start_t) + frag_buf_get_alpdu_header_len(frag_buf);

			/* RLE context needed if ALPDU is fragmented */
			if (!rle_ctx) {
				PRINT_RLE_ERROR("RLE context needed.");
				goto out;
			}

			if (ppdu_length < (ppdu_and_alpdu_hdrs_len + 1)) {
				/* buffer is too small for the smallest PPDU START fragment: the buffer shall be large
				 * enough for the PPDU START header, the full ALDPU header and at least one byte of
				 * ALPDU because the fragmentation of the ALPDU header is not supported by the RLE
				 * reassembler yet */
				status = 2;
				goto out;
			}

			push_alpdu_trailer(frag_buf, rle_conf, rle_ctx);

			frag_buf_ppdu_put(frag_buf, ppdu_length - sizeof(rle_ppdu_header_start_t));

			push_start_ppdu_header(frag_buf, rle_ctx->frag_id, alpdu_label_type,
			                       protocol_type_suppressed, use_alpdu_crc);

		} else {
			/* Complete PPDU */
			if (ppdu_length < sizeof(rle_ppdu_header_comp_t)) {
				status = 2;
				goto out;
			}

			frag_buf_ppdu_put(frag_buf, ppdu_length - sizeof(rle_ppdu_header_comp_t));

			push_comp_ppdu_header(frag_buf, alpdu_label_type, protocol_type_suppressed);
		}
	}

	frag_buf_set_cur_pos(frag_buf);

	status = 0;

out:
	return status;
}

void comp_ppdu_extract_alpdu_fragment(const unsigned char comp_ppdu[], const size_t ppdu_len,
                                      const unsigned char *alpdu_fragment[],
                                      size_t *alpdu_fragment_len)
{
	const rle_ppdu_header_comp_t *const comp_ppdu_header = (rle_ppdu_header_comp_t *)comp_ppdu;

	*alpdu_fragment = comp_ppdu + sizeof(rle_ppdu_header_comp_t);
	*alpdu_fragment_len = rle_ppdu_header_get_ppdu_length((rle_ppdu_header_t *)comp_ppdu_header);

	assert(ppdu_len == (sizeof(rle_ppdu_header_comp_t) + (*alpdu_fragment_len)));
}

void start_ppdu_extract_alpdu_fragment(const unsigned char start_ppdu[], const size_t ppdu_len,
                                       const unsigned char *alpdu_fragment[],
                                       size_t *const alpdu_fragment_len,
                                       size_t *const alpdu_total_len,
                                       int *const is_crc_used)
{
	const rle_ppdu_header_start_t *const start_ppdu_header =
	        (rle_ppdu_header_start_t *)start_ppdu;

	*alpdu_fragment = start_ppdu + sizeof(rle_ppdu_header_start_t);
	*alpdu_fragment_len = rle_ppdu_header_get_ppdu_length(
	        (rle_ppdu_header_t *)start_ppdu_header);
	*alpdu_total_len = rle_ppdu_header_start_get_total_length(start_ppdu_header);
	*is_crc_used = start_ppdu_header->use_crc;

	assert(ppdu_len == (sizeof(rle_ppdu_header_start_t) + (*alpdu_fragment_len)));
}

void cont_end_ppdu_extract_alpdu_fragment(const unsigned char cont_end_ppdu[], const size_t ppdu_len,
                                          const unsigned char *alpdu_fragment[],
                                          size_t *const alpdu_fragment_len)
{
	const rle_ppdu_header_cont_end_t *const cont_end_ppdu_header =
	        (rle_ppdu_header_cont_end_t *)cont_end_ppdu;

	*alpdu_fragment = cont_end_ppdu + sizeof(rle_ppdu_header_cont_end_t);
	*alpdu_fragment_len = rle_ppdu_header_get_ppdu_length(
	        (rle_ppdu_header_t *)cont_end_ppdu_header);

	assert(ppdu_len == (sizeof(rle_ppdu_header_cont_end_t) + (*alpdu_fragment_len)));
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
                                          const struct rle_config *const rle_conf)
{
	int status = 0;
	const uint8_t default_ptype = rle_conf->implicit_protocol_type;

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
                                          size_t *const alpdu_hdr_len)
{
	int status = 0;
	const rle_alpdu_header_t *const alpdu_header = (rle_alpdu_header_t *)alpdu_fragment;
	const uint8_t compressed_protocol_type = alpdu_header->compressed_supported.proto_type;

	if (compressed_protocol_type == RLE_PROTO_TYPE_FALLBACK) {
		if (alpdu_fragment_len < sizeof(alpdu_header->compressed_fallback)) {
			PRINT_RLE_ERROR("Alpdu fragment smaller (%zu) than a header (%zu)\n",
			                alpdu_fragment_len,
			                sizeof(alpdu_header->compressed_fallback));
			status = 1;
			goto out;
		}
		*protocol_type = htons(alpdu_header->compressed_fallback.uncompressed.proto_type);
		*sdu_fragment = alpdu_fragment + sizeof(alpdu_header->compressed_fallback);
		*sdu_fragment_len = alpdu_fragment_len - sizeof(alpdu_header->compressed_fallback);
		if (alpdu_hdr_len) {
			*alpdu_hdr_len = sizeof(alpdu_header->compressed_fallback);
		}
	} else {
		if (alpdu_fragment_len < sizeof(alpdu_header->compressed_supported)) {
			PRINT_RLE_ERROR("Alpdu fragment smaller (%zu) than a header (%zu)\n",
			                alpdu_fragment_len,
			                sizeof(alpdu_header->compressed_supported));
			status = 1;
			goto out;
		}
		*protocol_type = rle_header_ptype_decompression(
		        alpdu_header->compressed_supported.proto_type);
		*sdu_fragment = alpdu_fragment + sizeof(alpdu_header->compressed_supported);
		*sdu_fragment_len = alpdu_fragment_len - sizeof(alpdu_header->compressed_supported);
		if (alpdu_hdr_len) {
			*alpdu_hdr_len = sizeof(alpdu_header->compressed_supported);
		}
	}

out:
	return status;
}

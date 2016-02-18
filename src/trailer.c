/**
 * @file   header.c
 * @brief  RLE encapsulation functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "rle.h"

#include "rle_transmitter.h"
#include "constants.h"
#include "fragmentation_buffer.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"
#include "header.h"
#include "crc.h"

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

#define MODULE_NAME "TRAILER"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PRIVATE FUNCTIONS --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief         Compute the CRC of a gven SDU for CRC ALPDU trailer.
 *
 *
 *  @param[in]     frag_buf               the SDU.
 *
 *  @return        the CRC32
 *
 *  @ingroup
 */
static uint32_t compute_crc32(const struct rle_sdu *const sdu);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PRIVATE FUNCTIONS CODE ------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static uint32_t compute_crc32(const struct rle_sdu *const sdu)
{
	/* CRC must be computed on PDU data and the original two bytes protocol type field whatever it
	 * is suppressed or compressed */
	uint32_t crc32 = 0;
	uint16_t field_value = 0;
	size_t length = 0;

#ifdef DEBUG
	PRINT_RLE_DEBUG("RLE ctx -> 0x%p\n", MODULE_NAME, rle_ctx);
#endif

	/* first compute protocol type CRC */
	field_value = sdu->protocol_type;
	crc32 = compute_crc((unsigned char *)&field_value, RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP,
	                    RLE_CRC_INIT);

	/* compute SDU CRC */
	length = sdu->size;
	crc32 = compute_crc((unsigned char *)sdu->buffer, length, crc32);

#ifdef DEBUG
	PRINT_RLE_DEBUG("PDU length %zu & protocol type 0x%x CRC %x\n", MODULE_NAME, length,
	                field_value, crc32);
#endif

	return crc32;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS CODE-------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int push_alpdu_trailer(struct rle_frag_buf *const frag_buf,
                       const struct rle_configuration *const rle_conf,
                       struct rle_ctx_management *const rle_ctx)
{
	int status = 1;
	const int use_alpdu_crc = rle_conf_get_crc_check((struct rle_configuration *)rle_conf);
	size_t alpdu_trailer_len;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	rle_alpdu_trailer_t *const trailer = (rle_alpdu_trailer_t *)frag_buf->alpdu.end;

	if (use_alpdu_crc) {
		alpdu_trailer_len = sizeof(rle_alpdu_crc_trailer_t);
		trailer->crc_trailer.crc = compute_crc32(&frag_buf->sdu_info);
	} else {
		uint8_t seq_no = rle_ctx_get_seq_nb(rle_ctx);
		alpdu_trailer_len = sizeof(rle_alpdu_seqno_trailer_t);
		trailer->seqno_trailer.seq_no = seq_no;
		rle_ctx_incr_seq_nb(rle_ctx);
	}

	frag_buf_alpdu_put(frag_buf, alpdu_trailer_len);

	return status;
}

void trailer_alpdu_crc_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                            const size_t alpdu_fragment_len,
                                            const unsigned char *sdu_fragment[],
                                            size_t *const sdu_fragment_len,
                                            const rle_alpdu_crc_trailer_t **const trailer)
{
	*sdu_fragment = alpdu_fragment;
	*sdu_fragment_len = alpdu_fragment_len - sizeof **(trailer);
	*trailer = (rle_alpdu_crc_trailer_t *)(alpdu_fragment + *sdu_fragment_len);
}

void trailer_alpdu_seqno_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                              const size_t alpdu_fragment_len,
                                              const unsigned char *sdu_fragment[],
                                              size_t *const sdu_fragment_len,
                                              const rle_alpdu_seqno_trailer_t **const trailer)
{
	*sdu_fragment = alpdu_fragment;
	*sdu_fragment_len = alpdu_fragment_len - sizeof **(trailer);
	*trailer = (rle_alpdu_seqno_trailer_t *)(alpdu_fragment + *sdu_fragment_len);
}

int check_alpdu_trailer(const rle_alpdu_trailer_t *const trailer,
                        const rle_rasm_buf_t *const rasm_buf,
                        struct rle_ctx_management *const rle_ctx,
                        size_t *const lost_packets)
{
	int status = 0;
	const int use_alpdu_crc = rle_ctx_get_use_crc(rle_ctx);

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif /* DEBUG */

	*lost_packets = 0;

	if (use_alpdu_crc) {
		const uint32_t expected_crc = compute_crc32(&rasm_buf->sdu_info);
		if (trailer->crc_trailer.crc != expected_crc) {
			status = 1;
			*lost_packets = 1;
		}
	} else {
		const uint8_t next_seq_no = rle_ctx_get_seq_nb(rle_ctx);
		const uint8_t received_seq_no = trailer->seqno_trailer.seq_no;
		if (received_seq_no != next_seq_no) {
			if (received_seq_no != 0) {
				status = 1;
				*lost_packets = (received_seq_no - next_seq_no) % RLE_MAX_SEQ_NO;
				PRINT_RLE_ERROR(
				        "sequence number inconsistency, received [%d] expected [%d]\n",
				        received_seq_no, next_seq_no);
#ifdef DEBUG
			} else {
				PRINT_RLE_WARNING(
				        "sequence number null, supposing relog, received [%d] expected "
				        "[%d]\n", received_seq_no, next_seq_no);
#endif /* DEBUG */
			}
			/* update sequence with received one
			 * and increment it to resynchronize
			 * with sender sequence */
		}
		rle_ctx_set_seq_nb(rle_ctx, (received_seq_no + 1) % RLE_MAX_SEQ_NO);
	}

	return status;
}

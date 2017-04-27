/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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

#define MODULE_ID RLE_MOD_ID_TRAILER


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PRIVATE FUNCTIONS CODE ------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

uint32_t compute_crc32(const struct rle_sdu *const sdu)
{
	/* CRC must be computed on PDU data and the original two bytes protocol type field whatever it
	 * is suppressed or compressed */
	uint32_t crc32 = 0;
	uint16_t field_value = 0;
	size_t length = 0;

	/* first compute protocol type CRC */
	field_value = sdu->protocol_type;
	crc32 = compute_crc((unsigned char *)&field_value, RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP,
	                    RLE_CRC_INIT);

	/* compute SDU CRC */
	length = sdu->size;
	crc32 = compute_crc((unsigned char *)sdu->buffer, length, crc32);

	PRINT_RLE_DEBUG("PDU length %zu & protocol type 0x%x CRC %x\n", length,
	                field_value, crc32);

	return crc32;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS CODE-------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int push_alpdu_trailer(struct rle_frag_buf *const frag_buf,
                       const struct rle_config *const rle_conf,
                       struct rle_ctx_management *const rle_ctx)
{
	int status = 1;
	const bool use_alpdu_crc =
		(rle_conf->allow_alpdu_sequence_number ? 0 : rle_conf->allow_alpdu_crc);
	size_t alpdu_trailer_len;

	PRINT_RLE_DEBUG("");

	rle_alpdu_trailer_t *const trailer = (rle_alpdu_trailer_t *)frag_buf->alpdu.end;

	if (use_alpdu_crc) {
		alpdu_trailer_len = sizeof(rle_alpdu_crc_trailer_t);
		trailer->crc_trailer.crc = frag_buf->crc;
	} else {
		uint8_t seq_no = rle_ctx_get_seq_nb(rle_ctx);
		alpdu_trailer_len = sizeof(rle_alpdu_seqno_trailer_t);
		trailer->seqno_trailer.seq_no = seq_no;
		rle_ctx_incr_seq_nb(rle_ctx);
	}

	frag_buf_alpdu_put(frag_buf, alpdu_trailer_len);

	return status;
}

int check_alpdu_trailer(const rle_alpdu_trailer_t *const trailer,
                        const struct rle_sdu *const reassembled_sdu,
                        struct rle_ctx_management *const rle_ctx,
                        bool *const is_ctx_seqnum_init,
                        size_t *const lost_packets)
{
	int status = 0;
	const bool use_alpdu_crc = rle_ctx_get_use_crc(rle_ctx);

	PRINT_RLE_DEBUG("");

	*lost_packets = 0;

	if (use_alpdu_crc) {
		const uint32_t expected_crc = compute_crc32(reassembled_sdu);
		if (trailer->crc_trailer.crc != expected_crc) {
			PRINT_RLE_ERROR("wrong CRC for %zu-byte SDU of protocol 0x%02x: 0x%08x found while 0x%08x "
			                "expected", reassembled_sdu->size, reassembled_sdu->protocol_type,
			                ntohl(trailer->crc_trailer.crc), expected_crc);
			status = 1;
			*lost_packets = 1;
		}
	} else {
		const uint8_t received_seq_no = trailer->seqno_trailer.seq_no;
		if (!(*is_ctx_seqnum_init)) {
			/* first fragmented ALPDU received, accept any seqno */
			*is_ctx_seqnum_init = true;
			/* update sequence with received one */
			rle_ctx_set_seq_nb(rle_ctx, received_seq_no);
		} else {
			const uint8_t next_seq_no = rle_ctx_get_seq_nb(rle_ctx);
			if (received_seq_no != next_seq_no) {
				if (received_seq_no != 0) {
					status = 1;
					*lost_packets = (received_seq_no - next_seq_no) % RLE_MAX_SEQ_NO;
					PRINT_RLE_ERROR("sequence number inconsistency, received [%u] expected [%u]\n",
					                received_seq_no, next_seq_no);
				} else {
					PRINT_RLE_WARNING("sequence number null, supposing relog, received [%u] expected "
					                  "[%u]\n", received_seq_no, next_seq_no);
				}
				/* update sequence with received one */
				rle_ctx_set_seq_nb(rle_ctx, received_seq_no);
			}
		}
		/* increment seqno to resynchronize with sender sequence */
		rle_ctx_incr_seq_nb(rle_ctx);
	}

	return status;
}

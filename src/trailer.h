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
 * @file   trailer.h
 * @brief  Definition of RLE trailer constants, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "reassembly_buffer.h"

#ifndef __TRAILER_H__
#define __TRAILER_H__

/** Max Sequence Number value */
#define RLE_MAX_SEQ_NO          256
/** Size of Seq_No trailer in Bytes */
#define RLE_SEQ_NO_FIELD_SIZE   1
/** Size of CRC32 trailer in Bytes */
#define RLE_CRC32_FIELD_SIZE    4

/** RLE packet Seq No trailer. */
struct rle_alpdu_seqno_trailer {
	uint8_t seq_no;
} __attribute__ ((packed));

/** RLE packet Seq No trailer definition. */
typedef struct rle_alpdu_seqno_trailer rle_alpdu_seqno_trailer_t;

/** RLE packet CRC trailer. */
struct rle_alpdu_crc_trailer {
	uint32_t crc;
} __attribute__ ((packed));

/** RLE packet CRC trailer definition. */
typedef struct rle_alpdu_crc_trailer rle_alpdu_crc_trailer_t;

/** RLE packet trailer definition. */
union rle_alpdu_trailer {
	rle_alpdu_seqno_trailer_t seqno_trailer;
	rle_alpdu_crc_trailer_t crc_trailer;
} __attribute__ ((packed));

typedef union rle_alpdu_trailer rle_alpdu_trailer_t;

/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS -----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/


/**
 *  @brief         create and put ALPDU trailer into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     rle_conf             the RLE configuration
 *  @param[in,out] rle_ctx              the RLE context for seqno.
 *
 *  @return C_ERROR if KO
 *                C_OK if OK
 *
 *  @ingroup RLE trailer.
 */
int push_alpdu_trailer(struct rle_frag_buf *const frag_buf,
                       const struct rle_config *const rle_conf,
                       struct rle_ctx_management *const rle_ctx);

/**
 *  @brief         check the ALPDU trailer with its SDU.
 *
 *
 *  @param[in]     trailer              the trailer to check.
 *  @param[in]     reassembled_sdu      the reassembly buffer containing the SDU.
 *  @param[in,out] rle_ctx              the RLE context.
 *  @param[out]    lost_packets         number of lost packets.
 *
 *  @ingroup RLE trailer.
 */
int check_alpdu_trailer(const rle_alpdu_trailer_t *const trailer,
                        const struct rle_sdu *const reassembled_sdu,
                        struct rle_ctx_management *const rle_ctx,
                        bool *const is_ctx_seqnum_init,
                        size_t *const lost_packets);

/**
 * @brief Compute the CRC of a gven SDU for CRC ALPDU trailer
 *
 * @param sdu  the SDU to compute a CRC for
 * @return     the computed CRC32
 *
 * @ingroup RLE trailer.
 */
uint32_t compute_crc32(const struct rle_sdu *const sdu)
	__attribute__((warn_unused_result, nonnull(1)));


#endif /* __TRAILER_H__ */

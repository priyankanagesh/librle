/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file   rle_receiver.h
 * @brief  Definition of RLE receiver context and status structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __RLE_RECEIVER_H__
#define __RLE_RECEIVER_H__

#ifndef __KERNEL__

#include <stddef.h>

#else

#include <linux/stddef.h>

#endif

#include "rle_ctx.h"
#include "header.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief RLE receiver module used for reassembly & deencapsulation.
 *        Provides a context structure for each fragment_id.
 *
 * @ingroup RLE receiver
 */
struct rle_receiver {
	/** Reassembly contexts */
	struct rle_ctx_mngt rle_ctx_man[RLE_MAX_FRAG_NUMBER];
	/** Whether seqnum is known yet */
	bool is_ctx_seqnum_init[RLE_MAX_FRAG_NUMBER];
	struct rle_config conf;  /**< RLE configuration */
	uint8_t free_ctx;        /**< List of free contexts */
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief Deencapsulate RLE fragment from a buffer and bufferize/reassemble it while waiting for
 *        remaining data to be received
 *
 * @param[in,out] _this        The receiver module to use for deencapsulation.
 * @param[in]      ppdu        The PPDU to decapsulate.
 * @param[in]      ppdu_length The PPDU length.
 * @param[out]     index_ctx   The index of the context.
 *
 * @return C_ERROR         if error occured while reassembling SDU
 *         C_REASSEMBLY_OK if SDU is completely reassembled
 *         C_OK            if deencapsulation and reassembly is successfull
 *
 * @ingroup RLE receiver
 */
int rle_receiver_deencap_data(struct rle_receiver *_this,
                              unsigned char ppdu[],
                              const size_t ppdu_length,
                              int *const index_ctx,
                              struct rle_sdu *const potential_sdu);

/**
 * @brief Set to idle the fragment context.
 *
 * @param[in,out] _this        The receiver module to use for deencapsulation
 * @param[in]     fragment_id  Fragmentation context to use to get the PDU
 *
 * @ingroup RLE receiver
 */
void rle_receiver_free_context(struct rle_receiver *_this, uint8_t fragment_id);

/**
 * @brief Set to non free the state to a given context knowing its fragment ID.
 *
 * @param[in,out] _this        The receiver module to use for deencapsulation.
 * @param[in]     fragment_id  Fragmentation context to use to get the PDU
 *
 * @ingroup RLE receiver
 */
static inline void set_nonfree_frag_ctx(struct rle_receiver *const _this, const size_t fragment_id);

/**
 * @brief Set the state to free to a given context knowing its fragment ID.
 *
 * @param[in,out] _this        The receiver module to use for deencapsulation.
 * @param[in]     fragment_id  Fragmentation context to use to get the PDU
 *
 * @ingroup RLE receiver
 */
static inline void set_free_frag_ctx(struct rle_receiver *const _this, const size_t fragment_id);

/**
 * @brief Return the state of a given context knowing its fragment ID.
 *
 * @param[in,out] _this        The receiver module to use for deencapsulation.
 * @param[in]     fragment_id  Fragmentation context to use to get the SDU.
 *
 * @ingroup RLE receiver
 */
static inline int is_context_free(struct rle_receiver *const _this, const size_t fragment_id);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static inline void set_nonfree_frag_ctx(struct rle_receiver *const _this, const size_t fragment_id)
{
	rle_ctx_set_nonfree(&_this->free_ctx, fragment_id);
	return;
}

static inline void set_free_frag_ctx(struct rle_receiver *const _this, const size_t fragment_id)
{
	rle_ctx_set_free(&_this->free_ctx, fragment_id);
	return;
}

static inline int is_context_free(struct rle_receiver *const _this, const size_t fragment_id)
{
	return rle_ctx_is_free(_this->free_ctx, fragment_id);
}


#endif /* __RLE_RECEIVER_H__ */

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
 * @file   reassembly.h
 * @brief  Definition of RLE reassembly structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __REASSEMBLY_H__
#define __REASSEMBLY_H__

#include "rle_ctx.h"


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------------- PUBLIC FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx			the rle reassembly context
 *  @param pdu_buffer		pdu buffer's address to reassemble
 *  @param pdu_proto_type	the pdu protocol type
 *  @param pdu_length		the pdu buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_get_pdu(struct rle_ctx_management *rle_ctx, void *pdu_buffer, int *pdu_proto_type,
                       uint32_t *pdu_length);

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx			the rle reassembly context
 *  @param rle_conf        the rle configuration
 *  @param data_buffer		data buffer's address to reassemble
 *  @param data_length		the data_buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
                              struct rle_config *rle_conf,
                              void *data_buffer,
                              size_t data_length,
                              int frag_type);

/**
 * @brief Reassemble complete PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    reassembled_sdu  The reassembled SDU.
 *
 * @ingroup RLE receiver
 */
int reassembly_comp_ppdu(struct rle_receiver *_this,
                         unsigned char *const ppdu,
                         const size_t ppdu_length,
                         struct rle_sdu *const reassembled_sdu);

/**
 * @brief Start reassembly with start PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    index_ctx        The index of the reassmbly context.
 *
 * @ingroup RLE receiver
 */
int reassembly_start_ppdu(struct rle_receiver *_this,
                          unsigned char ppdu[],
                          const size_t ppdu_length,
                          int *const index_ctx);

/**
 * @brief Continue reassembly with cont PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    index_ctx        The index of the reassmbly context.
 *
 * @ingroup RLE receiver
 */
int reassembly_cont_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                         const size_t ppdu_length,
                         int *const index_ctx);

/**
 * @brief End reassembly with end PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    reassembled_sdu  The reassembled SDU.
 *
 * @ingroup RLE receiver
 */
int reassembly_end_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                        const size_t ppdu_length, int *const index_ctx,
                        struct rle_sdu *const reassembled_sdu);


#endif /* __REASSEMBLY_H__ */

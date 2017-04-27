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
 * @file   fragmentation.h
 * @brief  RLE fragmentation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __FRAGMENTATION_H__
#define __FRAGMENTATION_H__

#ifndef __KERNEL__

#include <stddef.h>

#else

#include <linux/stddef.h>

#endif

#include "rle_ctx.h"


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------------- PUBLIC FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief Split encapsulated PDU into fragments
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param rle_conf					the rle configuration
 *  @param burst_payload_buffer	data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *  @param protocol_type         the protocol type
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_fragment_pdu(struct rle_ctx_management *rle_ctx,
                               struct rle_config *rle_conf,
                               void *burst_payload_buffer,
                               size_t burst_payload_length,
                               uint16_t protocol_type);

/**
 *  @brief Copy encapsulated PDU into burst
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param rle_conf              the rle configuration
 *  @param burst_payload_buffer	data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *  @param protocol_type			the protocol type
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_copy_complete_frag(struct rle_ctx_management *rle_ctx,
                                     struct rle_config *rle_conf,
                                     void *burst_payload_buffer,
                                     size_t burst_payload_length);

/**
 *  @brief Add RLE header to fragment
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param rle_conf					the rle configuration
 *  @param burst_payload_buffer	data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *  @param type_rle_header			RLE header type to add
 *  @param protocol_type			protocol type
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_add_header(struct rle_ctx_management *rle_ctx,
                             struct rle_config *rle_conf,
                             void *burst_payload_buffer,
                             size_t burst_payload_length,
                             int type_rle_header,
                             uint16_t protocol_type);

/**
 *  @brief Modify RLE header to fragment
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param burst_payload_buffer	data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_modify_header(struct rle_ctx_management *rle_ctx, void *burst_payload_buffer,
                                size_t burst_payload_length);

/**
 *  @brief Add RLE trailer to the last fragment
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param burst_payload_buffer	data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_add_trailer(struct rle_ctx_management *rle_ctx, void *burst_payload_buffer,
                              size_t burst_payload_length);

/**
 *  @brief Create a RLE fragment, reset memory if it's a START packet
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param rle_conf					the rle configuration
 *  @param burst_payload_buffer	data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *  @param frag_type					RLE fragment type to create
 *  @param protocol_type			protocol type
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_create_frag(struct rle_ctx_management *rle_ctx,
                              struct rle_config *rle_conf,
                              void *burst_payload_buffer,
                              size_t burst_payload_length,
                              int frag_type,
                              uint16_t protocol_type);

/**
 *  @brief Add RLE trailer to the last fragment
 *
 *  @warning
 *
 *  @param rle_ctx					the rle fragment context
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_is_needed(struct rle_ctx_management *rle_ctx, size_t burst_payload_length);

#endif /* __FRAGMENTATION_H__ */

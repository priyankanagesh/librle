/**
 * @file   fragmentation.h
 * @author Aurelien Castanie
 *
 * @brief  RLE fragmentation functions
 *
 *
 */

#ifndef _FRAGMENTATION_H
#define _FRAGMENTATION_H

#include <stddef.h>
#include "rle_ctx.h"
#include "rle_conf.h"

/**
 *  @brief Split encapsulated PDU into fragments
 *
 *  @warning
 *
 *  @param rle_ctx			the rle fragment context
 *  @param burst_payload_buffer		data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_fragment_pdu(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length,
		uint16_t protocol_type);

/**
 *  @brief Copy encapsulated PDU into burst
 *
 *  @warning
 *
 *  @param rle_ctx			the rle fragment context
 *  @param burst_payload_buffer		data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_copy_complete_frag(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length);

/**
 *  @brief Add RLE header to fragment
 *
 *  @warning
 *
 *  @param rle_ctx		the rle fragment context
 *  @param burst_payload_buffer		data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_add_header(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length,
		int type_rle_header, uint16_t protocol_type);

/**
 *  @brief Modify RLE header to fragment
 *
 *  @warning
 *
 *  @param rle_ctx		the rle fragment context
 *  @param burst_payload_buffer		data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_modify_header(struct rle_ctx_management *rle_ctx,
		void *burst_payload_buffer, size_t burst_payload_length);

/**
 *  @brief Add RLE trailer to the last fragment
 *
 *  @warning
 *
 *  @param rle_ctx		the rle fragment context
 *  @param burst_payload_buffer		data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_add_trailer(struct rle_ctx_management *rle_ctx,
		void *burst_payload_buffer, size_t burst_payload_length);

/**
 *  @brief Add RLE trailer to the last fragment
 *
 *  @warning
 *
 *  @param rle_ctx		the rle fragment context
 *  @param burst_payload_buffer		data buffer's address to encapsulate
 *  @param burst_payload_length	payload length available
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int fragmentation_is_needed(struct rle_ctx_management *rle_ctx, size_t burst_payload_length);

#endif /* _FRAGMENTATION_H */


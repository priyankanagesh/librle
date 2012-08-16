/**
 * @file   reassembly.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE reassembly structure, functions and variables
 *
 *
 */

#ifndef _REASSEMBLY_H
#define _REASSEMBLY_H

#include "rle_ctx.h"

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length, int frag_type);

/**
 *  @brief Remove RLE header from fragment
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *  @param type_rle_header	the RLE header type
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_remove_header(struct rle_ctx_management *rle_ctx,
		void *data_buffer, int type_rle_header);

/**
 *  @brief Modify RLE header to reassemble
 *
 *  @warning
 *
 *  @param rle_ctx		the rle fragment context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_modify_header(struct rle_ctx_management *rle_ctx,
		void *data_buffer);

/**
 *  @brief Compute RLE packet length
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_compute_packet_length(struct rle_ctx_management *rle_ctx,
		void *data_buffer);

/**
 *  @brief Check RLE reassembled packet validity with seq nb or CRC
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_check_packet_validity(struct rle_ctx_management *rle_ctx,
		void *data_buffer);

#endif /* _REASSEMBLY_H */

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
 * RLE receiver module used
 * for reassembly & deencapsulation.
 * Provides a context structure for each
 * fragment_id.
 */
struct rle_receiver {
	struct rle_ctx_management rle_ctx_man[RLE_MAX_FRAG_NUMBER];
	struct rle_configuration *rle_conf[RLE_MAX_FRAG_NUMBER];
	uint8_t free_ctx;
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief Deencapsulate RLE fragment from a buffer
 *		and bufferize/reassemble it while waiting for remaining data
 *		to be received
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param data_buffer	Data buffer's address to deencapsulate
 *  @param data_length	Data length to deencapsulate
 *  @param index_ctx		The index of the context
 *
 *  @return	C_ERROR		if error occured while reassembling PDU
 *		C_ERROR_TOO_MUCH_FRAG	if the PDU was too fragmented (> 256 fragments)
 *		C_REASSEMBLY_OK	if PDU is completely reassembled
 *		C_OK		if deencapsulation and reassembly is successfull
 *
 *  @ingroup
 */
int rle_receiver_deencap_data(struct rle_receiver *_this, void *data_buffer, size_t data_length,
                              int *index_ctx);

/**
 *  @brief Retrieve reassembled PDU data and copy it
 *		to a buffer
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param fragment_id	Fragmentation context to use to get the PDU
 *  @param pdu_buffer	Destination of reassembled PDU
 *  @param pdu_proto_type	Reassembled PDU protocol type
 *  @param pdu_length	Reassembled PDU length
 *
 *  @return	C_ERROR		if error occured while retrieving PDU
 *		C_ERROR_BUF	if given buffer (PDU, protocol type or PDU length) is invalid
 *		C_OK		otherwise
 *
 *  @ingroup
 */
int rle_receiver_get_packet(struct rle_receiver *_this, uint8_t fragment_id, void *pdu_buffer,
                            int *pdu_proto_type,
                            uint32_t *pdu_length);

/**
 *  @brief Set to idle the fragment context
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param fragment_id	Fragmentation context to use to get the PDU
 *
 *  @ingroup
 */
void rle_receiver_free_context(struct rle_receiver *_this, uint8_t fragment_id);

#endif /* __RLE_RECEIVER_H__ */

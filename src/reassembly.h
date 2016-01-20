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
#include "rle_conf.h"


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
 *  @param rle_conf 			the rle configuration
 *  @param data_buffer		data buffer's address to reassemble
 *  @param data_length		the data_buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
                              struct rle_configuration *rle_conf, void *data_buffer,
                              size_t data_length,
                              int frag_type);

#endif /* __REASSEMBLY_H__ */

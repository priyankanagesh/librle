/**
 * @file   encap.h
 * @brief  Definition of RLE encapsulation structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __ENCAP_H__
#define __ENCAP_H__

#include "rle_ctx.h"


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------------- PUBLIC FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief encapsulate data into an rle packet
 *
 *  @warning
 *
 *  @param rle_ctx			the rle fragment context
 *  @param rle_conf			the rle configuration
 *  @param data_buffer		data buffer's address to encapsulate
 *  @param data_length		data length to encapsulate
 *  @param protocol_type	the protocol type
 *
 *  @return C_ERROR if KO
 *		C_OK if OK
 *
 *  @ingroup
 */
int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx,
                          struct rle_config *rle_conf,
                          void *data_buffer, size_t data_length,
                          uint16_t protocol_type);

#endif /* __ENCAP_H__ */

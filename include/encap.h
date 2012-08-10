/**
 * @file   encap.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE encapsulation structure, functions and variables
 *
 *
 */

#ifndef _ENCAP_H
#define _ENCAP_H

#include "rle_ctx.h"

/**
 *  @brief encapsulate data into an rle packet
 *
 *  @warning
 *
 *  @param _this	the rle fragment context
 *  @param data_buffer	data buffer's address to encapsulate
 *  @param data_length	data length to encapsulate
 *
 *  @return
 *
 *  @ingroup
 */
int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length);
/**
 *  @brief Check validity of input PDU
 *
 *  @warning
 *
 *  @param data_buffer	data buffer's address to encapsulate
 *
 *  @return	C_ERROR if KO
 *		C_OK if OK
 *
 *  @ingroup
 */
int encap_check_pdu_validity(void *data_buffer);

#endif /* _ENCAP_H */

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
#include "rle_conf.h"

/**
 *  @brief encapsulate data into an rle packet
 *
 *  @warning
 *
 *  @param rle_ctx              the rle fragment context
 *  @param rle_conf             the rle configuration
 *  @param data_buffer          data buffer's address to encapsulate
 *  @param data_length          data length to encapsulate
 *  @param protocol_type        the protocol type
 *
 *  @return C_ERROR if KO
 *                C_OK if OK
 *
 *  @ingroup
 */
int create_header(struct rle_ctx_management *rle_ctx, struct rle_configuration *rle_conf,
                  void *data_buffer, size_t data_length, uint16_t protocol_type);
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
int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx, struct rle_configuration *rle_conf,
                          void *data_buffer, size_t data_length,
                          uint16_t protocol_type);

/**
 *  @brief Check L2 validity of input PDU
 *
 *  @warning
 *
 *  @param pdu_buffer		data buffer's address to check
 *  @param pdu_length		length of the buffer
 *  @param protocol_type	the protocol type
 *
 *  @return	C_ERROR if KO
 *		C_OK if OK
 *
 *  @ingroup
 */
int encap_check_l2_pdu_validity(void *pdu_buffer, size_t pdu_length, uint16_t protocol_type);

/**
 *  @brief Check L3 validity of input PDU
 *
 *  @warning
 *
 *  @param pdu_buffer		data buffer's address to check
 *  @param pdu_length		length of the buffer
 *  @param protocol_type	the protocol type
 *
 *  @return	C_ERROR if KO
 *		C_OK if OK
 *
 *  @ingroup
 */
int encap_check_l3_pdu_validity(void *pdu_buffer, size_t pdu_length, uint16_t protocol_type);

/**
 *  @brief Check validity of input PDU
 *
 *  @warning
 *
 *  @param pdu_length		length of the buffer
 *
 *  @return	C_ERROR if KO
 *		C_OK if OK
 *
 *  @ingroup
 */
int encap_check_pdu_validity(const size_t pdu_length);

#endif /* __ENCAP_H__ */

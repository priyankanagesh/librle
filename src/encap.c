/**
 * @file   encap.c
 * @brief  RLE encapsulation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>

#else

#include <linux/types.h>

#endif

#include "rle.h"
#include "rle_transmitter.h"
#include "encap.h"
#include "constants.h"
#include "rle_ctx.h"
#include "zc_buffer.h"
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "ENCAP"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PRIVATE FUNCTIONS --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

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
static int encap_check_pdu_validity(const size_t pdu_length);


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int encap_check_pdu_validity(const size_t pdu_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME, __FILE__, __func__, __LINE__);
#endif

	if (pdu_length > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s %s:%s:%d: PDU too large for RL Encapsulation, size [%zu]\n", MODULE_NAME,
		      __FILE__, __func__, __LINE__, pdu_length);
		return C_ERROR;
	}

	return C_OK;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_encap_status rle_encapsulate(struct rle_transmitter *const transmitter,
                                      const struct rle_sdu sdu,
                                      const uint8_t frag_id)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	int ret = 0;

	if (transmitter == NULL) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto exit_label;
	}

	if (sdu.size > RLE_MAX_PDU_SIZE) {
		status = RLE_ENCAP_ERR_SDU_TOO_BIG;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	ret = rle_transmitter_encap_data(transmitter, sdu.buffer, sdu.size, sdu.protocol_type, frag_id);

	if (ret == C_OK) {
		status = RLE_ENCAP_OK;
	}

exit_label:
	return status;
}

int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx, struct rle_configuration *rle_conf,
                          void *pdu_buffer, size_t pdu_length,
                          uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif
	rle_ctx_incr_counter_in(rle_ctx);
	rle_ctx_incr_counter_bytes_in(rle_ctx, pdu_length);

	if (encap_check_pdu_validity(pdu_length) == C_ERROR) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, pdu_length);
		return C_ERROR;
	}

	if (create_header(rle_ctx, rle_conf,
	                  pdu_buffer, pdu_length,
	                  protocol_type) == C_ERROR) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, pdu_length);
		return C_ERROR;
	}

	/* set PDU buffer address to the rle_ctx ptr */
	rle_ctx->pdu_buf = pdu_buffer;

	return C_OK;
}

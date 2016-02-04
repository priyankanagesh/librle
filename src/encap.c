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
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"
#include "fragmentation_buffer.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "ENCAP"


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_encap_status rle_encapsulate(struct rle_transmitter *const transmitter,
                                      const struct rle_sdu *const sdu, const uint8_t frag_id)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	int ret = 0;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (transmitter == NULL) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto exit_label;
	}

	if (sdu->size > RLE_MAX_PDU_SIZE) {
		status = RLE_ENCAP_ERR_SDU_TOO_BIG;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	ret = rle_transmitter_encap_data(transmitter, sdu, frag_id);

	if (ret == C_OK) {
		status = RLE_ENCAP_OK;
	}

exit_label:
	return status;
}

enum rle_encap_status rle_encap_contextless(struct rle_transmitter *const transmitter,
                                            struct rle_fragmentation_buffer *const f_buff)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	struct rle_configuration *rle_conf;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!transmitter) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto out;
	}

	rle_conf = transmitter->rle_conf;

	if (!f_buff) {
		status = RLE_ENCAP_ERR_NULL_F_BUFF;
		goto out;
	}

	if (!f_buff_in_use(f_buff)) {
		status = RLE_ENCAP_ERR_N_INIT_F_BUFF;
		goto out;
	}

	if (push_alpdu_header(f_buff, rle_conf) == 0) {
		status = RLE_ENCAP_OK;
	}

out:
	return status;
}


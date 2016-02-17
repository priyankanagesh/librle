/**
 * @file   fragmentation.c
 * @brief  RLE fragmentation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdio.h>
#include <string.h>

#else

#include <linux/stddef.h>
#include <linux/types.h>

#endif

#include "rle.h"

#include "fragmentation_buffer.h"
#include "rle_transmitter.h"
#include "header.h"
#include "fragmentation.h"
#include "constants.h"
#include "rle_ctx.h"
#include "crc.h"
#include "rle_header_proto_type_field.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "FRAGMENTATION"


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PUBLIC FUNCTIONS CODE --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_frag_status rle_fragment(struct rle_transmitter *const transmitter, const uint8_t frag_id,
                                  const size_t remaining_burst_size, unsigned char **const ppdu,
                                  size_t *const ppdu_length)
{
	enum rle_frag_status status = RLE_FRAG_ERR; /* Error by default. */

	int ret_push = 0;
	rle_f_buff_t *f_buff;
	struct rle_ctx_management *rle_ctx;
	const struct rle_configuration *rle_conf;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	*ppdu_length = 0;

	if (transmitter == NULL) {
		status = RLE_FRAG_ERR_NULL_TRMT;
		goto out;
	}

	if (frag_id >= RLE_MAX_FRAG_NUMBER) {
		goto out;
	}

	rle_conf = transmitter->rle_conf;
	rle_ctx = &transmitter->rle_ctx_man[frag_id];

	if (rle_ctx_is_free(transmitter->free_ctx, frag_id)) {
		status = RLE_FRAG_ERR_CONTEXT_IS_NULL;
		rle_transmitter_free_context(transmitter, frag_id);
		goto out;
	}

	f_buff = (rle_f_buff_t *)rle_ctx->buff;

	f_buff_ppdu_init(f_buff);

	ret_push = push_ppdu_header(f_buff, rle_conf, remaining_burst_size, rle_ctx);

	if (ret_push != 0) {
		if (ret_push == 2) {
			/* Burst to small for header. */
			status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		}
		goto out;
	}

	*ppdu = f_buff->ppdu.start;
	*ppdu_length = f_buff_get_current_ppdu_len(f_buff);

	if (f_buff_get_remaining_alpdu_length(f_buff) == 0) {
		rle_transmitter_free_context(transmitter, frag_id);
		rle_ctx_incr_counter_ok(rle_ctx);
	}
	rle_ctx_incr_counter_bytes_ok(rle_ctx, *ppdu_length);

	status = RLE_FRAG_OK;

out:
	return status;
}

enum rle_frag_status rle_frag_contextless(struct rle_transmitter *const transmitter,
                                          struct rle_fragmentation_buffer *const f_buff,
                                          unsigned char **const ppdu, size_t *const ppdu_length)
{
	enum rle_frag_status status = RLE_FRAG_ERR;
	const struct rle_configuration *rle_conf;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!transmitter) {
		status = RLE_FRAG_ERR_NULL_TRMT;
		goto out;
	}

	rle_conf = transmitter->rle_conf;

	if (!f_buff) {
		status = RLE_FRAG_ERR_NULL_F_BUFF;
		goto out;
	}

	if (!f_buff_in_use(f_buff)) {
		status = RLE_FRAG_ERR_N_INIT_F_BUFF;
		goto out;
	}

	if (!ppdu_length) {
		PRINT_RLE_ERROR("No PPDU length provided.");
		goto out;
	}

	if (*ppdu_length < sizeof(rle_ppdu_header_comp_t)) {
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		goto out;
	}

	f_buff_ppdu_init(f_buff);

	if (push_ppdu_header(f_buff, rle_conf, *ppdu_length, NULL) != 0) {
		goto out;
	}

	*ppdu_length = f_buff_get_current_ppdu_len(f_buff);

	*ppdu = f_buff->ppdu.start;

	status = RLE_FRAG_OK;

out:
	return status;
}

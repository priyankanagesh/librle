/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file   fragmentation.c
 * @brief  RLE fragmentation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "fragmentation_buffer.h"
#include "rle_transmitter.h"
#include "header.h"
#include "fragmentation.h"
#include "constants.h"
#include "rle_ctx.h"
#include "crc.h"
#include "rle_header_proto_type_field.h"

#include "rle.h"

#ifndef __KERNEL__

#include <stdio.h>
#include <string.h>

#else

#include <linux/stddef.h>
#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_FRAGMENTATION


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PUBLIC FUNCTIONS CODE --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_frag_status rle_fragment(struct rle_transmitter *const transmitter,
                                  const uint8_t frag_id,
                                  const size_t remaining_burst_size,
                                  unsigned char *ppdu[],
                                  size_t *const ppdu_length)
{
	enum rle_frag_status status = RLE_FRAG_ERR; /* Error by default. */

	rle_frag_buf_t *frag_buf;
	struct rle_ctx_mngt *rle_ctx;

	if (transmitter == NULL) {
		status = RLE_FRAG_ERR_NULL_TRMT;
		goto out;
	}

	if (frag_id >= RLE_MAX_FRAG_NUMBER || ppdu == NULL || ppdu_length == NULL) {
		goto out;
	}

	*ppdu_length = 0;

	rle_ctx = &transmitter->rle_ctx_man[frag_id];

	if (rle_ctx_is_free(transmitter->free_ctx, frag_id)) {
		status = RLE_FRAG_ERR_CONTEXT_IS_NULL;
		rle_transmitter_free_context(transmitter, frag_id);
		goto out;
	}

	frag_buf = (rle_frag_buf_t *)rle_ctx->buff;

	frag_buf_ppdu_init(frag_buf);

	if (!push_ppdu_hdr(frag_buf, &transmitter->conf, remaining_burst_size, rle_ctx)) {
		/* Burst to small for header. */
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		goto out;
	}

	*ppdu = frag_buf->ppdu.start;
	*ppdu_length = frag_buf_get_current_ppdu_len(frag_buf);

	/* PPDU shall always be > 2, sending 0 byte of payload is useless, and even a problem:
	 * a CONT PPDU with 0 byte of payload may be confused with padding */
	assert((*ppdu_length) > 2);

	if (frag_buf_get_remaining_alpdu_length(frag_buf) == 0) {
		rle_transmitter_free_context(transmitter, frag_id);
		rle_ctx_incr_counter_ok(rle_ctx);
	}
	rle_ctx_incr_counter_bytes_ok(rle_ctx, *ppdu_length);

	status = RLE_FRAG_OK;

out:
	return status;
}

enum rle_frag_status rle_frag_contextless(struct rle_transmitter *const transmitter,
                                          struct rle_frag_buf *const frag_buf,
                                          unsigned char **const ppdu,
                                          size_t *const ppdu_length)
{
	enum rle_frag_status status = RLE_FRAG_ERR;

	if (!transmitter) {
		status = RLE_FRAG_ERR_NULL_TRMT;
		goto out;
	}

	if (!frag_buf) {
		status = RLE_FRAG_ERR_NULL_F_BUFF;
		goto out;
	}

	if (!frag_buf_in_use(frag_buf)) {
		status = RLE_FRAG_ERR_N_INIT_F_BUFF;
		goto out;
	}

	if (!ppdu) {
		goto out;
	}
	if (!ppdu_length) {
		RLE_ERR("No PPDU length provided");
		goto out;
	}
	if (*ppdu_length < sizeof(rle_ppdu_hdr_comp_t)) {
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		goto out;
	}

	frag_buf_ppdu_init(frag_buf);

	if (!push_ppdu_hdr(frag_buf, &transmitter->conf, *ppdu_length, NULL)) {
		goto out;
	}

	*ppdu_length = frag_buf_get_current_ppdu_len(frag_buf);

	*ppdu = frag_buf->ppdu.start;

	status = RLE_FRAG_OK;

out:
	return status;
}

/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file   encap.c
 * @brief  RLE encapsulation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "encap.h"
#include "rle_transmitter.h"
#include "constants.h"
#include "rle_ctx.h"
#include "rle_header_proto_type_field.h"
#include "rle.h"
#include "fragmentation_buffer.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/ethernet.h>

#else

#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_ENCAP


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int is_frag_ctx_free(struct rle_transmitter *const _this, const size_t ctx_index)
{
	PRINT_RLE_DEBUG("");

	return rle_ctx_is_free(_this->free_ctx, ctx_index);
}

static void set_nonfree_frag_ctx(struct rle_transmitter *const _this, const size_t ctx_index)
{
	PRINT_RLE_DEBUG("");

	rle_ctx_set_nonfree(&_this->free_ctx, ctx_index);

	return;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_encap_status rle_encapsulate(struct rle_transmitter *const transmitter,
                                      const struct rle_sdu *const sdu,
                                      const uint8_t frag_id)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	enum rle_encap_status ret_encap;
	struct rle_ctx_management *rle_ctx;
	rle_frag_buf_t *frag_buf;
	int ret;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

	if (transmitter == NULL) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto out;
	}

	if (sdu == NULL || frag_id >= RLE_MAX_FRAG_NUMBER) {
		goto out;
	}
	PRINT_RLE_DEBUG("encapsulate one %zu-byte SDU in context with ID %u",
                    sdu->size, frag_id);

	rle_ctx = &transmitter->rle_ctx_man[frag_id];
	frag_buf = (rle_frag_buf_t *)rle_ctx->buff;

	if (sdu->size <= 0 || sdu->size > RLE_MAX_PDU_SIZE) {
		status = RLE_ENCAP_ERR_SDU_TOO_BIG;
		rle_transmitter_free_context(transmitter, frag_id);
		goto out;
	}

	if (is_frag_ctx_free(transmitter, frag_id) == false) {
		PRINT_RLE_ERROR("frag id %d is not free", frag_id);
		goto out;
	}

	/* set to 'used' the previously free frag context */
	set_nonfree_frag_ctx(transmitter, frag_id);

	ret = rle_frag_buf_init(frag_buf);
	assert(ret == 0); /* cannot fail since frag_buf is not NULL */

	ret = rle_frag_buf_cpy_sdu(frag_buf, sdu);
	assert(ret == 0); /* cannot fail since SDU length was already checked */

	ret_encap = rle_encap_contextless(transmitter, frag_buf);
	assert(ret_encap == RLE_ENCAP_OK); /* no way to fail here */

	rle_ctx_incr_counter_in(rle_ctx);
	rle_ctx_incr_counter_bytes_in(rle_ctx, sdu->size);

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld]\n", tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	status = RLE_ENCAP_OK;
	PRINT_RLE_DEBUG("%zu-byte SDU successfully encapsulated in context with ID %u",
                    sdu->size, frag_id);

out:
	return status;
}

enum rle_encap_status rle_encap_contextless(struct rle_transmitter *const transmitter,
                                            struct rle_frag_buf *const frag_buf)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;

	PRINT_RLE_DEBUG("");

	if (!transmitter) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto out;
	}

	if (!frag_buf) {
		status = RLE_ENCAP_ERR_NULL_F_BUFF;
		goto out;
	}

	if (!frag_buf_in_use(frag_buf)) {
		status = RLE_ENCAP_ERR_N_INIT_F_BUFF;
		goto out;
	}

	if (transmitter->conf.allow_alpdu_sequence_number == 0 &&
	    transmitter->conf.allow_alpdu_crc == 1) {
		frag_buf->crc = compute_crc32(&frag_buf->sdu_info);
	}

	push_alpdu_header(frag_buf, &transmitter->conf);
	status = RLE_ENCAP_OK;

out:
	return status;
}

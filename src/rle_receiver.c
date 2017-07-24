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
 * @file   rle_receiver.c
 * @brief  RLE receiver functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_receiver.h"
#include "reassembly.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "constants.h"
#include "header.h"
#include "trailer.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#endif

#ifdef TIME_DEBUG
#include <sys/time.h>
#endif

/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_RECEIVER


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PRIVATE FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief          Check if a receiver queue context is valid and extract it.
 *
 * @param[in]      receiver                 The receiver with the context to extract.
 * @param[in]      fragment_id              The fragment ID linked to the context to extract.
 * @param[out]     ctx_man                  The extracted context.
 *
 * @return         0 if OK, else 1.
 */
static int get_receiver_context(const struct rle_receiver *const receiver,
                                const uint8_t fragment_id,
                                const struct rle_ctx_mngt **const ctx_man);


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int get_receiver_context(const struct rle_receiver *const receiver,
                                const uint8_t fragment_id,
                                const struct rle_ctx_mngt **const ctx_man)
{
	int status = 1;

	assert(ctx_man != NULL);

	if (receiver == NULL || fragment_id >= RLE_MAX_FRAG_NUMBER) {
		/* Out of bound */
		goto error;
	}

	*ctx_man = &receiver->rle_ctx_man[fragment_id];

	status = 0;

error:
	return status;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

struct rle_receiver * rle_receiver_new(const struct rle_config *const conf)
{
	struct rle_receiver *receiver = NULL;
	size_t i;

	if (!rle_config_check(conf)) {
		RLE_ERR("failed to created RLE receiver: invalid configuration");
		goto error;
	}

	receiver = (struct rle_receiver *)MALLOC(sizeof(struct rle_receiver));
	if (!receiver) {
		RLE_ERR("allocating receiver module failed");
		goto error;
	}

	memcpy(&receiver->conf, conf, sizeof(struct rle_config));

	memset(receiver->rle_ctx_man, 0, RLE_MAX_FRAG_NUMBER * sizeof(struct rle_ctx_mngt));
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		struct rle_ctx_mngt *const ctx_man = &receiver->rle_ctx_man[i];
		if (rle_ctx_init_rasm_buf(ctx_man) != C_OK) {
			RLE_ERR("failed to allocate memory for reassembly context with ID %zu", i);
			goto free_ctxts;
		}
		ctx_man->frag_id = i;
		rle_ctx_set_seq_nb(ctx_man, 0);
		receiver->is_ctx_seqnum_init[i] = false;
	}

	receiver->free_ctx = 0;

	return receiver;

free_ctxts:
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		struct rle_ctx_mngt *const ctx_man = &receiver->rle_ctx_man[i];
		if (ctx_man->buff != NULL) {
			rle_ctx_destroy_rasm_buf(ctx_man);
		}
	}
	FREE(receiver);
error:
	return NULL;
}

void rle_receiver_destroy(struct rle_receiver **const receiver)
{
	size_t i;

	if (!receiver) {
		/* Nothing to do. */
		goto out;
	}

	if (!*receiver) {
		/* Nothing to do. */
		goto out;
	}

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; ++i) {
		struct rle_ctx_mngt *const ctx_man = &(*receiver)->rle_ctx_man[i];
		rle_ctx_destroy_rasm_buf(ctx_man);
	}

	FREE(*receiver);
	*receiver = NULL;

out:

	return;
}

int rle_receiver_deencap_data(struct rle_receiver *_this,
                              unsigned char ppdu[],
                              const size_t ppdu_length,
                              int *const index_ctx,
                              struct rle_sdu *const potential_sdu)
{
	const size_t ppdu_base_hdr_len = 2;
	int ret = C_ERROR;
	int frag_type = 0;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

	assert(index_ctx != NULL);

	*index_ctx = -1;

	/* check PPDU validity */
	assert(ppdu_length <= (RLE_MAX_PPDU_PL_SIZE + ppdu_base_hdr_len));

	/* retrieve frag id if its a fragmented packet to append data to the * right frag id context
	 * (SE bits)
	 */
	frag_type = rle_ppdu_get_fragment_type((const rle_ppdu_hdr_t *)ppdu);

	switch (frag_type) {
	case RLE_PDU_COMPLETE:
		ret = reassembly_comp_ppdu(_this, ppdu, ppdu_length, potential_sdu);
		break;
	case RLE_PDU_START_FRAG:
		ret = reassembly_start_ppdu(_this, ppdu, ppdu_length, index_ctx);
		break;
	case RLE_PDU_CONT_FRAG:
		ret = reassembly_cont_ppdu(_this, ppdu, ppdu_length, index_ctx);
		break;
	case RLE_PDU_END_FRAG:
		ret = reassembly_end_ppdu(_this, ppdu, ppdu_length, index_ctx, potential_sdu);
		break;
	default:
		RLE_ERR("Unhandled fragment type '%i'.", frag_type);
		assert(0);
		break;
	}

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	RLE_DEBUG("duration [%04ld.%06ld].", tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	return ret;
}

void rle_receiver_free_context(struct rle_receiver *_this, uint8_t fragment_id)
{
	/* set to idle this fragmentation context */
	set_free_frag_ctx(_this, fragment_id);
}

size_t rle_receiver_stats_get_queue_size(const struct rle_receiver *const receiver,
                                         const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto out;
	}

	stat = rasm_buf_get_reassembled_sdu_len((rle_rasm_buf_t *)ctx_man->buff);

out:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_sdus_received(const struct rle_receiver *const receiver,
                                                      const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_in(ctx_man);

error:

	return stat;
}


uint64_t rle_receiver_stats_get_counter_sdus_reassembled(const struct rle_receiver *const receiver,
                                                         const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_ok(ctx_man);

error:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_sdus_dropped(const struct rle_receiver *const receiver,
                                                     const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_dropped(ctx_man);

error:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_sdus_lost(const struct rle_receiver *const receiver,
                                                  const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_lost(ctx_man);

error:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_bytes_received(const struct rle_receiver *const receiver,
                                                       const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_bytes_in(ctx_man);

error:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_bytes_reassembled(const struct rle_receiver *const receiver,
                                                          const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_bytes_ok(ctx_man);

error:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_bytes_dropped(const struct rle_receiver *const receiver,
                                                      const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_bytes_dropped(ctx_man);

error:
	return stat;
}

int rle_receiver_stats_get_counters(const struct rle_receiver *const receiver,
                                    const uint8_t fragment_id,
                                    struct rle_receiver_stats *const stats)
{
	int status = 1;
	const struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!stats) {
		goto error;
	}

	stats->sdus_received = rle_ctx_get_counter_in(ctx_man);
	stats->sdus_reassembled = rle_ctx_get_counter_ok(ctx_man);
	stats->sdus_dropped = rle_ctx_get_counter_dropped(ctx_man);
	stats->sdus_lost = rle_ctx_get_counter_lost(ctx_man);
	stats->bytes_received = rle_ctx_get_counter_bytes_in(ctx_man);
	stats->bytes_reassembled = rle_ctx_get_counter_bytes_ok(ctx_man);
	stats->bytes_dropped = rle_ctx_get_counter_bytes_dropped(ctx_man);

	status = 0;

error:
	return status;
}

void rle_receiver_stats_reset_counters(struct rle_receiver *const receiver,
                                       const uint8_t fragment_id)
{
	struct rle_ctx_mngt *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id,
	                         (const struct rle_ctx_mngt **)&ctx_man)) {
		goto error;
	}

	rle_ctx_reset_counters(ctx_man);

error:
	return;
}

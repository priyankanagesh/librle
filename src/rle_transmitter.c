/**
 * @file   rle_transmitter.c
 * @brief  RLE transmitter functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_transmitter.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "constants.h"
#include "encap.h"
#include "fragmentation.h"
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

#define MODULE_NAME "TRANSMITTER"


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PRIVATE FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief          Check if a transmitter queue context is valid and extract it.
 *
 * @param[in]      transmitter              The transmitter with the context to extract.
 * @param[in]      fragment_id              The fragment ID linked to the context to extract.
 * @param[out]     ctx_man                  The extracted context.
 *
 * @return         0 if OK, else 1.
 */
static int get_transmitter_context(const struct rle_transmitter *const transmitter,
                                   const uint8_t fragment_id,
                                   const struct rle_ctx_management **const ctx_man);


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int get_transmitter_context(const struct rle_transmitter *const transmitter,
                                   const uint8_t fragment_id,
                                   const struct rle_ctx_management **const ctx_man)
{
	int status = 1;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	assert(ctx_man != NULL);

	if (transmitter == NULL || fragment_id >= RLE_MAX_FRAG_NUMBER) {
		/* Out of bound */
		goto error;
	}

	*ctx_man = &transmitter->rle_ctx_man[fragment_id];

	status = 0;

error:
	return status;
}

static void set_free_frag_ctx(struct rle_transmitter *const _this, const size_t ctx_index)
{
#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	rle_ctx_set_free(&_this->free_ctx, ctx_index);

	return;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

struct rle_transmitter *rle_transmitter_new(const struct rle_config *const conf)
{
	struct rle_transmitter *transmitter = NULL;
	size_t iterator;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!rle_config_check(conf)) {
		PRINT_RLE_ERROR("failed to created RLE transmitter: invalid configuration");
		goto error;
	}

	transmitter = (struct rle_transmitter *)MALLOC(sizeof(struct rle_transmitter));
	if (!transmitter) {
		PRINT_RLE_ERROR("allocating transmitter module failed\n");

		goto error;
	}

	/* initialize fragmentation contexts */
	memset(transmitter->rle_ctx_man, 0,
	       RLE_MAX_FRAG_NUMBER * sizeof(struct rle_ctx_management));
	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
		struct rle_ctx_management *const ctx_man = &transmitter->rle_ctx_man[iterator];
		if (rle_ctx_init_frag_buf(ctx_man) != C_OK) {
			PRINT_RLE_ERROR("failed to allocate memory for fragmentation context with "
			                "ID %zu\n", iterator);
			goto free_ctxts;
		}
		ctx_man->frag_id = iterator;
		rle_ctx_set_seq_nb(ctx_man, 0);
	}

	transmitter->free_ctx = 0;

	memcpy(&transmitter->conf, conf, sizeof(struct rle_config));

	return transmitter;

free_ctxts:
	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
		struct rle_ctx_management *const ctx_man = &transmitter->rle_ctx_man[iterator];
		if (ctx_man->buff != NULL) {
			rle_ctx_destroy_frag_buf(ctx_man);
		}
	}
	FREE(transmitter);
error:
	return NULL;
}

void rle_transmitter_destroy(struct rle_transmitter **const transmitter)
{
	size_t iterator;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!transmitter) {
		goto exit_label;
	}

	if (!*transmitter) {
		/* Transmitter already NULL, nothing to do. */
		goto exit_label;
	}

	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; iterator++) {
		struct rle_ctx_management *const ctx_man = &(*transmitter)->rle_ctx_man[iterator];

		rle_ctx_destroy_frag_buf(ctx_man);
	}

	FREE(*transmitter);
	*transmitter = NULL;

exit_label:

	return;
}

void rle_transmitter_free_context(struct rle_transmitter *const _this, const uint8_t fragment_id)
{
#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	/* set to idle this fragmentation context */
	set_free_frag_ctx(_this, fragment_id);
}

size_t rle_transmitter_stats_get_queue_size(const struct rle_transmitter *const transmitter,
                                            const uint8_t fragment_id)
{
	const struct rle_ctx_management *ctx_man = NULL;
	const rle_frag_buf_t *frag_buf = NULL;
	size_t stat;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		stat = 0;
		goto error;
	}

	if (rle_ctx_is_free(transmitter->free_ctx, fragment_id)) {
		stat = 0;
	} else {
		frag_buf = (rle_frag_buf_t *)ctx_man->buff;
		stat = frag_buf_get_remaining_alpdu_length(frag_buf);
	}

error:
	return stat;
}

uint64_t rle_transmitter_stats_get_counter_sdus_in(const struct rle_transmitter *const transmitter,
                                                   const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_in(ctx_man);

error:

	return stat;
}

uint64_t rle_transmitter_stats_get_counter_sdus_sent(
        const struct rle_transmitter *const transmitter, const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_ok(ctx_man);

error:

	return stat;
}

uint64_t rle_transmitter_stats_get_counter_sdus_dropped(
        const struct rle_transmitter *const transmitter, const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_dropped(ctx_man);

error:

	return stat;
}

uint64_t rle_transmitter_stats_get_counter_bytes_in(const struct rle_transmitter *const transmitter,
                                                    const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_bytes_in(ctx_man);

error:

	return stat;
}

uint64_t rle_transmitter_stats_get_counter_bytes_sent(
        const struct rle_transmitter *const transmitter, const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_bytes_ok(ctx_man);

error:

	return stat;
}

uint64_t rle_transmitter_stats_get_counter_bytes_dropped(
        const struct rle_transmitter *const transmitter, const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = rle_ctx_get_counter_bytes_dropped(ctx_man);

error:

	return stat;
}

int rle_transmitter_stats_get_counters(const struct rle_transmitter *const transmitter,
                                       const uint8_t fragment_id,
                                       struct rle_transmitter_stats *const stats)
{
	int status = 1;
	const struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!stats) {
		goto error;
	}

	stats->sdus_in = rle_ctx_get_counter_in(ctx_man);
	stats->sdus_sent = rle_ctx_get_counter_ok(ctx_man);
	stats->sdus_dropped = rle_ctx_get_counter_dropped(ctx_man);
	stats->bytes_in = rle_ctx_get_counter_bytes_in(ctx_man);
	stats->bytes_sent = rle_ctx_get_counter_bytes_ok(ctx_man);
	stats->bytes_dropped = rle_ctx_get_counter_bytes_dropped(ctx_man);

	status = 0;

error:

	return status;
}

void rle_transmitter_stats_reset_counters(struct rle_transmitter *const transmitter,
                                          const uint8_t fragment_id)
{
	struct rle_ctx_management *ctx_man = NULL;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (get_transmitter_context(transmitter, fragment_id,
	                            (const struct rle_ctx_management **)&ctx_man)) {
		goto error;
	}

	rle_ctx_reset_counters(ctx_man);

error:

	return;
}

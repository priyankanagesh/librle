/**
 * @file   rle_receiver.c
 * @brief  RLE receiver functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>

#endif

#ifdef TIME_DEBUG
#include <sys/time.h>
#endif
#include "rle_receiver.h"
#include "reassembly.h"
#include "rle_ctx.h"
#include "constants.h"
#include "header.h"
#include "trailer.h"
#include "deencap.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "RECEIVER"


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
                                const struct rle_ctx_management **const ctx_man);

/* TODO */


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int get_receiver_context(const struct rle_receiver *const receiver,
                                const uint8_t fragment_id,
                                const struct rle_ctx_management **const ctx_man)
{
	int status = 1;

	if (fragment_id >= RLE_MAX_FRAG_ID) {
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

struct rle_receiver *rle_receiver_new(const struct rle_context_configuration *const configuration)
{
	struct rle_receiver *receiver = NULL;
	size_t iterator;
	struct rle_configuration **rx_conf;

	if (configuration->implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
		PRINT_RLE_ERROR("could not initialize receiver with 0x31 as implicit protocol type : "
		                "Not supported yet.");
		goto out;
	}

	receiver = (struct rle_receiver *)MALLOC(sizeof(struct rle_receiver));

	if (!receiver) {
		PRINT_RLE_ERROR("allocating receiver module failed");
		goto out;
	}

	rx_conf = &receiver->rle_conf_ctxtless;
	*rx_conf = rle_conf_new();
	if (!*rx_conf) {
		PRINT_RLE_ERROR("allocating receiver module configuration failed");
		rle_receiver_destroy(&receiver);
		receiver = NULL;

		goto out;
	}
	rle_conf_init(*rx_conf);
	rle_conf_set_default_ptype(*rx_conf, configuration->implicit_protocol_type);
	rle_conf_set_crc_check(*rx_conf, configuration->use_alpdu_crc);
	rle_conf_set_ptype_compression(*rx_conf, configuration->use_compressed_ptype);
	rle_conf_set_ptype_suppression(*rx_conf, configuration->use_ptype_omission);

	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
		struct rle_ctx_management *const ctx_man = &receiver->rle_ctx_man[iterator];
		rx_conf = &receiver->rle_conf[iterator];
		*rx_conf = rle_conf_new();
	if (!*rx_conf) {
			PRINT_RLE_ERROR("allocating receiver module configuration failed.");
			rle_receiver_destroy(&receiver);
			receiver = NULL;

			goto out;
		}
		rle_ctx_init_r_buff(ctx_man);
		rle_ctx_set_frag_id(ctx_man, iterator);
		rle_ctx_set_seq_nb(ctx_man, 0);
		rle_conf_init(*rx_conf);
		rle_conf_set_default_ptype(*rx_conf, configuration->implicit_protocol_type);
		rle_conf_set_crc_check(*rx_conf, configuration->use_alpdu_crc);
		rle_conf_set_ptype_compression(*rx_conf, configuration->use_compressed_ptype);
		rle_conf_set_ptype_suppression(*rx_conf, configuration->use_ptype_omission);
	}

	receiver->free_ctx = 0;

out:

	return receiver;
}

void rle_receiver_destroy(struct rle_receiver **const receiver)
{
	size_t iterator;

	if (!receiver) {
		/* Nothing to do. */
		goto out;
	}

	if (!*receiver) {
		/* Nothing to do. */
		goto out;
	}

	if ((*receiver)->rle_conf_ctxtless) {
		rle_conf_destroy((*receiver)->rle_conf_ctxtless);
	}

	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
		struct rle_configuration **const conf = &(*receiver)->rle_conf[iterator];
		struct rle_ctx_management *const ctx_man = &(*receiver)->rle_ctx_man[iterator];

		if (*conf) {
			rle_conf_destroy(*conf);
		}

		if (ctx_man) {
			rle_ctx_destroy_r_buff(ctx_man);
		}
	}

	FREE(*receiver);
	*receiver = NULL;

out:

	return;
}

int rle_receiver_deencap_data(struct rle_receiver *_this, const unsigned char ppdu[],
                              const size_t ppdu_length, int *const index_ctx,
                              struct rle_sdu *const potential_sdu)
{
	int ret = C_ERROR;
	int frag_type = 0;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	/* check PPDU validity */
	if (ppdu_length > RLE_MAX_PDU_SIZE) {
		PRINT_RLE_ERROR("Packet too long [%zu].", ppdu_length);
		goto out;
	}

	/* retrieve frag id if its a fragmented packet to append data to the * right frag id context
	 * (SE bits)
	 */
	frag_type = rle_ppdu_get_fragment_type((const rle_ppdu_header_t *)ppdu);

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
		break;
	}

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld].", MODULE_NAME, tv_delta.tv_sec, tv_delta.tv_usec);
#endif

out:
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id,
	                         (const struct rle_ctx_management **const)&ctx_man)) {
		goto out;
	}

	if (!ctx_man) {
		goto out;
	}

	stat = r_buff_get_reassembled_sdu_length((rle_r_buff_t *)ctx_man->buff);

out:

	return stat;
}

uint64_t rle_receiver_stats_get_counter_sdus_received(const struct rle_receiver *const receiver,
                                                      const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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
	const struct rle_ctx_management *ctx_man = NULL;

	if (!receiver) {
		goto error;
	}

	if (get_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!stats) {
		goto error;
	}

	stats->sdus_received     = rle_ctx_get_counter_in(ctx_man);
	stats->sdus_reassembled  = rle_ctx_get_counter_ok(ctx_man);
	stats->sdus_dropped      = rle_ctx_get_counter_dropped(ctx_man);
	stats->sdus_lost         = rle_ctx_get_counter_lost(ctx_man);
	stats->bytes_received    = rle_ctx_get_counter_bytes_in(ctx_man);
	stats->bytes_reassembled = rle_ctx_get_counter_bytes_ok(ctx_man);
	stats->bytes_dropped     = rle_ctx_get_counter_bytes_dropped(ctx_man);

	status = 0;

error:
	return status;
}

void rle_receiver_stats_reset_counters(struct rle_receiver *const receiver,
                                       const uint8_t fragment_id)
{
	struct rle_ctx_management *ctx_man = NULL;

	if (!receiver) {
		goto error;
	}

	if (get_receiver_context(receiver, fragment_id, (const struct rle_ctx_management **)&ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
		goto error;
	}

	rle_ctx_reset_counters(ctx_man);

error:
	return;
}

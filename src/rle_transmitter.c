/**
 * @file   rle_transmitter.c
 * @brief  RLE transmitter functions
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
#include "rle_transmitter.h"
#include "rle_ctx.h"
#include "constants.h"
#include "encap.h"
#include "fragmentation.h"
#include "trailer.h"


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
static int valid_transmitter_context(const struct rle_transmitter *const transmitter,
                                     const uint8_t fragment_id,
                                     const struct rle_ctx_management **const ctx_man);


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int valid_transmitter_context(const struct rle_transmitter *const transmitter,
                                     const uint8_t fragment_id,
                                     const struct rle_ctx_management **const ctx_man)
{
	int status = 1;

	if (!transmitter) {
		/* Transmitter null. */
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		/* Out of bound */
		goto error;
	}

	if (!ctx_man) {
		/* Context manager null. */
		goto error;
	}

	*ctx_man = &transmitter->rle_ctx_man[fragment_id];

	status = 1;

error:
	return status;
}

static int is_frag_ctx_free(struct rle_transmitter *const _this, const uint8_t frag_id)
{
	int is_free = C_FALSE;

	is_free = ((_this->free_ctx >> frag_id) & 0x1) ? C_TRUE : C_FALSE;

	return is_free;
}

static void set_nonfree_frag_ctx(struct rle_transmitter *_this, int index)
{
	_this->free_ctx |= (1 << index);
}

static void set_free_frag_ctx(struct rle_transmitter *_this, int index)
{
	_this->free_ctx = (0 << index) & 0xff;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

struct rle_transmitter *rle_transmitter_new(const struct rle_context_configuration configuration)
{
	struct rle_transmitter *transmitter = NULL;
	size_t iterator = 0;
	struct rle_configuration **tx_conf;

	if (configuration.implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
		PRINT("ERROR: could not initialize transmitter with 0x31 as implicit protocol type : "
		      "Not supported yet.\n");

		goto exit_label;
	}

	transmitter = (struct rle_transmitter *)MALLOC(sizeof(struct rle_transmitter));

	if (!transmitter) {
		PRINT("ERROR %s:%s:%d: allocating transmitter module failed\n", __FILE__, __func__,
		      __LINE__);

		goto exit_label;
	}

	tx_conf = &transmitter->rle_conf;

	/* allocate a new RLE configuration structure */
	*tx_conf = rle_conf_new();

	if (!*tx_conf) {
		PRINT("ERROR %s:%s:%d: allocating RLE configuration failed\n", __FILE__, __func__,
		      __LINE__);
		/* free rle transmitter */
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;

		goto exit_label;
	}

	/* initialize both RLE transmitter & the configuration structure */
	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
		struct rle_ctx_management *const ctx_man = &transmitter->rle_ctx_man[iterator];

		rle_ctx_init(ctx_man);
		rle_ctx_set_frag_id(ctx_man, iterator);
		rle_ctx_set_seq_nb(ctx_man, 0);
		rle_ctx_set_alpdu_length(ctx_man, 0);
		rle_ctx_set_pdu_length(ctx_man, 0);
		rle_ctx_set_remaining_alpdu_length(ctx_man, 0);
		rle_ctx_set_remaining_pdu_length(ctx_man, 0);
	}

	transmitter->free_ctx = 0;

	rle_conf_set_default_ptype(*tx_conf, configuration.implicit_protocol_type);
	rle_conf_set_crc_check(*tx_conf, configuration.use_alpdu_crc);
	rle_conf_set_ptype_compression(*tx_conf, configuration.use_compressed_ptype);
	rle_conf_set_ptype_suppression(*tx_conf, configuration.use_ptype_omission);

exit_label:

	return transmitter;
}

void rle_transmitter_destroy(struct rle_transmitter *const transmitter)
{
	size_t iterator;

	if (!transmitter) {
		/* Transmitter already NULL, nothing to do. */
		goto exit_label;
	}

	for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; iterator++) {
		struct rle_ctx_management *const ctx_man = &transmitter->rle_ctx_man[iterator];

		rle_ctx_destroy(ctx_man);
	}

	if (rle_conf_destroy(transmitter->rle_conf) != C_OK) {
		PRINT("ERROR %s:%s:%d: destroying RLE configuration failed\n", __FILE__, __func__,
		      __LINE__);
	}

	FREE(transmitter);

exit_label:

	/*
	 * TODO For resetting transmitter to NULL, the pointer to the pointer of the transmitter must
	 * be given as argument, but the interface will be modified.
	 *
	 * *p_transmitter = NULL;
	 *
	 */

	return;
}

int rle_transmitter_encap_data(struct rle_transmitter *_this, void *data_buffer, size_t data_length,
                               uint16_t protocol_type,
                               uint8_t frag_id)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME, __FILE__, __func__, __LINE__);
#endif

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	gettimeofday(&tv_start, NULL);
#endif

	int ret = C_ERROR;

	if (!data_buffer) {
		PRINT("ERROR %s:%s:%d: data buffer is invalid\n", __FILE__, __func__, __LINE__);
		return ret;
	}

	if (!_this) {
		PRINT("ERROR %s:%s:%d: transmitter module is invalid\n", __FILE__, __func__, __LINE__);
		return ret;
	}

	if (is_frag_ctx_free(_this, frag_id)) {
		PRINT("ERROR %s:%s:%d: frag id is not free\n", __FILE__, __func__, __LINE__);
		return ret;
	}

	/* set to 'used' the previously free frag context */
	set_nonfree_frag_ctx(_this, frag_id);

	if (encap_encapsulate_pdu(&_this->rle_ctx_man[frag_id],
		                      _this->rle_conf,
		                      data_buffer, data_length,
		                      protocol_type) == C_ERROR) {
		struct rle_ctx_management *rle_ctx = &_this->rle_ctx_man[frag_id];
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, data_length);
		set_free_frag_ctx(_this, frag_id);
		PRINT("ERROR %s:%s:%d: cannot encapsulate data\n", __FILE__, __func__, __LINE__);
		return ret;
	}

#ifdef TIME_DEBUG
	struct timeval tv_delta;
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT("DEBUG %s %s:%s:%d: duration [%04ld.%06ld]\n", MODULE_NAME, __FILE__, __func__, __LINE__,
	      tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	ret = C_OK;

	return ret;
}

int rle_transmitter_get_packet(struct rle_transmitter *_this, void *burst_buffer,
                               size_t burst_length, uint8_t fragment_id,
                               uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	gettimeofday(&tv_start, NULL);
#endif

	uint16_t number_frags = _this->rle_ctx_man[fragment_id].nb_frag_pdu;
	int ret = C_ERROR;

	if (number_frags >= RLE_MAX_SEQ_NO) {
		PRINT("ERROR %s %s:%s:%d: fragment_id [%d] Packet too much fragmented\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__,
		      fragment_id);
		ret = C_ERROR_TOO_MUCH_FRAG;
		goto return_val;
	}

	/* call fragmentation module */
	ret = fragmentation_fragment_pdu(&_this->rle_ctx_man[fragment_id],
	                                 _this->rle_conf,
	                                 burst_buffer, burst_length,
	                                 protocol_type);

#ifdef TIME_DEBUG
	struct timeval tv_delta;
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT("DEBUG %s %s:%s:%d: duration [%04ld.%06ld]\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__,
	      tv_delta.tv_sec, tv_delta.tv_usec);
#endif

return_val:
	if ((ret != C_OK) && (ret != C_ERROR_FRAG_SIZE)) {
		struct rle_ctx_management *const rle_ctx = &_this->rle_ctx_man[fragment_id];
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, rle_ctx_get_remaining_alpdu_length(rle_ctx));
		set_free_frag_ctx(_this, fragment_id);
	}

	return ret;
}

void rle_transmitter_free_context(struct rle_transmitter *_this, uint8_t fragment_id)
{
	/* set to idle this fragmentation context */
	set_free_frag_ctx(_this, fragment_id);
}

int rle_transmitter_get_queue_state(struct rle_transmitter *_this, uint8_t fragment_id)
{
	/* get info from rle context */
	if (rle_ctx_get_remaining_alpdu_length(&_this->rle_ctx_man[fragment_id])
	    == 0) {
		return C_TRUE;
	}

	return C_FALSE;
}

uint32_t rle_transmitter_get_queue_size(struct rle_transmitter *_this, uint8_t fragment_id)
{
	/* get info from rle context */
	/*return rle_ctx_get_remaining_pdu_length(&_this->rle_ctx_man[fragment_id]);*/
	return rle_ctx_get_remaining_alpdu_length(&_this->rle_ctx_man[fragment_id]);
}

void rle_transmitter_dump_alpdu(struct rle_transmitter *_this, uint8_t frag_id,
                                unsigned char alpdu_buffer[], const size_t alpdu_buffer_size,
                                size_t *const alpdu_length)
{
	rle_ctx_dump_alpdu(rle_ctx_get_proto_type(
	                           &_this->rle_ctx_man[frag_id]), &_this->rle_ctx_man[frag_id],
	                   _this->rle_conf, alpdu_buffer,
	                   alpdu_buffer_size, alpdu_length);
	return;
}

enum check_frag_status rle_transmitter_check_frag_integrity(
        const struct rle_transmitter *const _this, uint8_t frag_id)
{
	return rle_ctx_check_frag_integrity(&_this->rle_ctx_man[frag_id]);
}

size_t rle_transmitter_stats_get_queue_size(const struct rle_transmitter *const transmitter,
                                            const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
		goto error;
	}

	stat = ctx_man->remaining_alpdu_size;

error:

	return stat;
}

uint64_t rle_transmitter_stats_get_counter_sdus_in(const struct rle_transmitter *const transmitter,
                                                   const uint8_t fragment_id)
{
	size_t stat = 0;
	const struct rle_ctx_management *ctx_man = NULL;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
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

	if (!transmitter) {
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		goto error;
	}

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	if (!stats) {
		goto error;
	}

	if (!ctx_man) {
		goto error;
	}

	stats->sdus_in       = rle_ctx_get_counter_in(ctx_man);
	stats->sdus_sent     = rle_ctx_get_counter_ok(ctx_man);
	stats->sdus_dropped  = rle_ctx_get_counter_dropped(ctx_man);
	stats->bytes_in      = rle_ctx_get_counter_bytes_in(ctx_man);
	stats->bytes_sent    = rle_ctx_get_counter_bytes_ok(ctx_man);
	stats->bytes_dropped = rle_ctx_get_counter_bytes_dropped(ctx_man);

	status = 0;

error:

	return status;
}

void rle_transmitter_stats_reset_counters(struct rle_transmitter *const transmitter,
                                          const uint8_t fragment_id)
{
	struct rle_ctx_management *ctx_man = NULL;

	if (!transmitter) {
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		goto error;
	}

	if (!valid_transmitter_context(transmitter, fragment_id,
	                               (const struct rle_ctx_management **)&ctx_man)) {
		goto error;
	}

	if (!ctx_man) {
		goto error;
	}

	rle_ctx_reset_counters(ctx_man);

error:

	return;
}

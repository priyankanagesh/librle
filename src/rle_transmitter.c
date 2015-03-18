/**
 * @file   rle_transmitter.c
 * @brief  RLE transmitter functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <stdlib.h>
#include <stdio.h>
#ifdef TIME_DEBUG
#include <sys/time.h>
#endif
#include "rle_transmitter.h"
#include "rle_ctx.h"
#include "constants.h"
#include "encap.h"
#include "fragmentation.h"
#include "trailer.h"

#define MODULE_NAME "TRANSMITTER"

static int get_first_free_frag_ctx(struct transmitter_module *_this)
{
	int i;

	pthread_mutex_lock(&_this->ctx_mutex);
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		if (((_this->free_ctx >> i) & 0x1) == 0) {
			pthread_mutex_unlock(&_this->ctx_mutex);
			return i;
		}
	}
	pthread_mutex_unlock(&_this->ctx_mutex);

	return C_ERROR;
}

static void set_nonfree_frag_ctx(struct transmitter_module *_this, int index)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx |= (1 << index);
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static void set_free_frag_ctx(struct transmitter_module *_this, int index)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx = (0 << index) & 0xff;
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static void set_free_all_frag_ctx(struct transmitter_module *_this)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx = 0;
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static void init(struct transmitter_module *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	int i;
	/* allocating buffer for each frag_id
	 * and initialize sequence number and
	 * fragment id */
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_init(&_this->rle_ctx_man[i]);
		rle_ctx_set_frag_id(&_this->rle_ctx_man[i], i);
		rle_ctx_set_seq_nb(&_this->rle_ctx_man[i], 0);
	}

	pthread_mutex_init(&_this->ctx_mutex, NULL);

	/* all frag_id are set to idle */
	set_free_all_frag_ctx(_this);
}

struct transmitter_module *rle_transmitter_new(void)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	struct transmitter_module *_this = NULL;

	/* allocate a new RLE transmitter */
	_this = MALLOC(sizeof(struct transmitter_module));

	if (!_this) {
		PRINT("ERROR %s:%s:%d: allocating transmitter module failed\n",
		      __FILE__, __func__, __LINE__);
		return NULL;
	}

	/* allocate a new RLE configuration structure */
	_this->rle_conf = rle_conf_new();

	if (!_this->rle_conf) {
		PRINT("ERROR %s:%s:%d: allocating RLE configuration failed\n",
		      __FILE__, __func__, __LINE__);
		/* free rle transmitter */
		FREE(_this);
		_this = NULL;
		return NULL;
	}

	/* initialize both RLE transmitter
	* & the configuration structure */
	init(_this);

	rle_conf_init(_this->rle_conf);

	return _this;
}

void rle_transmitter_destroy(struct transmitter_module *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_destroy(&_this->rle_ctx_man[i]);
	}

	set_free_all_frag_ctx(_this);

	if (rle_conf_destroy(_this->rle_conf) != C_OK) {
		PRINT("ERROR %s:%s:%d: destroying RLE configuration failed\n",
		      __FILE__, __func__, __LINE__);
	}

	FREE(_this);
	_this = NULL;
}

int rle_transmitter_encap_data(struct transmitter_module *_this, void *data_buffer,
                               size_t data_length,
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

	int ret = C_ERROR;

	if (!data_buffer) {
		PRINT("ERROR %s:%s:%d: data buffer is invalid\n",
		      __FILE__, __func__, __LINE__);
		return ret;
	}

	if (!_this) {
		PRINT("ERROR %s:%s:%d: transmitter module is invalid\n",
		      __FILE__, __func__, __LINE__);
		return ret;
	}

	/* get first free frag context */
	int index_ctx = get_first_free_frag_ctx(_this);
	if (index_ctx < 0) {
		PRINT("ERROR %s:%s:%d: no free fragmentation context available "
		      "for encapsulation\n",
		      __FILE__, __func__, __LINE__);
		return ret;
	}

	/* set to 'used' the previously free frag context */
	set_nonfree_frag_ctx(_this, index_ctx);

	if (encap_encapsulate_pdu(&_this->rle_ctx_man[index_ctx],
	                          _this->rle_conf,
	                          data_buffer, data_length,
	                          protocol_type)
	    == C_ERROR) {
		rle_ctx_incr_counter_dropped(&_this->rle_ctx_man[index_ctx]);
		set_free_frag_ctx(_this, index_ctx);
		PRINT("ERROR %s:%s:%d: cannot encapsulate data\n",
		      __FILE__, __func__, __LINE__);
		return ret;
	}

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

	ret = C_OK;
	return ret;
}

int rle_transmitter_get_packet(struct transmitter_module *_this, void *burst_buffer,
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
	if (ret != C_OK) {
		rle_ctx_incr_counter_dropped(&_this->rle_ctx_man[fragment_id]);
		set_free_frag_ctx(_this, fragment_id);
	}

	return ret;
}

void rle_transmitter_free_context(struct transmitter_module *_this, uint8_t fragment_id)
{
	/* set to idle this fragmentation context */
	set_free_frag_ctx(_this, fragment_id);
}

int rle_transmitter_get_queue_state(struct transmitter_module *_this, uint8_t fragment_id)
{
	/* get info from rle context */
	if (rle_ctx_get_remaining_pdu_length(&_this->rle_ctx_man[fragment_id])
	    == 0) {
		return C_TRUE;
	}

	return C_FALSE;
}

uint32_t rle_transmitter_get_queue_size(struct transmitter_module *_this, uint8_t fragment_id)
{
	/* get info from rle context */
	return rle_ctx_get_remaining_pdu_length(&_this->rle_ctx_man[fragment_id]);
}

uint64_t rle_transmitter_get_counter_ok(struct transmitter_module *_this)
{
	int i;
	uint64_t ctr_packet_ok = 0L;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		struct rle_ctx_management *rle_ctx = &_this->rle_ctx_man[i];
		ctr_packet_ok += rle_ctx_get_counter_ok(rle_ctx);
	}

	return ctr_packet_ok;
}

uint64_t rle_transmitter_get_counter_dropped(struct transmitter_module *_this)
{
	int i;
	uint64_t ctr_packet_dropped = 0L;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		struct rle_ctx_management *rle_ctx = &_this->rle_ctx_man[i];
		ctr_packet_dropped += rle_ctx_get_counter_dropped(rle_ctx);
	}

	return ctr_packet_dropped;
}

uint64_t rle_transmitter_get_counter_lost(struct transmitter_module *_this)
{
	int i;
	uint64_t ctr_packet_lost = 0L;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		struct rle_ctx_management *rle_ctx = &_this->rle_ctx_man[i];
		ctr_packet_lost += rle_ctx_get_counter_lost(rle_ctx);
	}

	return ctr_packet_lost;
}

uint64_t rle_transmitter_get_counter_bytes(struct transmitter_module *_this)
{
	int i;
	uint64_t ctr_bytes = 0L;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		struct rle_ctx_management *rle_ctx = &_this->rle_ctx_man[i];
		ctr_bytes += rle_ctx_get_counter_bytes(rle_ctx);
	}

	return ctr_bytes;
}

void rle_transmitter_dump(struct transmitter_module *_this)
{
	int i;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_dump(&_this->rle_ctx_man[i],
		             _this->rle_conf);
	}
}

#ifdef __KERNEL__
EXPORT_SYMBOL(rle_transmitter_new);
EXPORT_SYMBOL(rle_transmitter_init);
EXPORT_SYMBOL(rle_transmitter_destroy);
EXPORT_SYMBOL(rle_transmitter_encap_data);
EXPORT_SYMBOL(rle_transmitter_get_packet);
EXPORT_SYMBOL(rle_transmitter_get_queue_state);
EXPORT_SYMBOL(rle_transmitter_get_queue_size);
EXPORT_SYMBOL(rle_transmitter_dump);
#endif

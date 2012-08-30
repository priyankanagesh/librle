/**
 * @file   rle_transmitter.c
 * @author Aurelien Castanie
 *
 * @brief  RLE transmitter functions
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include "rle_transmitter.h"
#include "rle_ctx.h"
#include "constants.h"
#include "encap.h"
#include "fragmentation.h"

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

static void set_nonfree_frag_ctx(struct transmitter_module *_this,
				int index)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx |= (1 << index);
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static void set_free_frag_ctx(struct transmitter_module *_this,
				int index)
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
/*        _this->ctx_mutex = PTHREAD_MUTEX_INITIALIZER;*/

	/* all frag_id are set to idle */
	set_free_all_frag_ctx(_this);
}

struct transmitter_module *rle_transmitter_new(void)
{
	struct transmitter_module *_this = NULL;

	/* allocate a new RLE transmitter */
	_this = MALLOC(sizeof(struct transmitter_module));

	if (!_this) {
		PRINT("ERROR %s:%s:%d: allocating transmitter module failed\n",
				__FILE__, __func__, __LINE__);
		return NULL;
	}

	/* allocate a new RLE configuration structure */
	_this->rle_conf = rle_conf_new(_this->rle_conf);

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
	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++)
		rle_ctx_destroy(&_this->rle_ctx_man[i]);

	set_free_all_frag_ctx(_this);

	if (rle_conf_destroy(_this->rle_conf) != C_OK)
		PRINT("ERROR %s:%s:%d: destroying RLE configuration failed\n",
				__FILE__, __func__, __LINE__);

	FREE(_this);
	_this = NULL;
}


int rle_transmitter_encap_data(struct transmitter_module *_this,
				void *data_buffer, size_t data_length,
				uint16_t protocol_type)
{
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
		set_free_frag_ctx(_this, index_ctx);
		PRINT("ERROR %s:%s:%d: cannot encapsulate data\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	ret = C_OK;
	return ret;
}

int rle_transmitter_get_packet(struct transmitter_module *_this,
		void *burst_buffer,
		size_t burst_length,
		uint8_t fragment_id,
		uint16_t protocol_type)
{
	/* call fragmentation module */
	int ret = fragmentation_fragment_pdu(&_this->rle_ctx_man[fragment_id],
			_this->rle_conf,
			burst_buffer, burst_length,
			protocol_type);

	return ret;
}

void rle_transmitter_dump(struct transmitter_module *_this)
{
	int i;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_dump(&_this->rle_ctx_man[i],
				_this->rle_conf);
	}
	PRINT("-------> Free context [0x%0x]\n", _this->free_ctx);
}

#ifdef __KERNEL__
EXPORT_SYMBOL(rle_transmitter_new);
EXPORT_SYMBOL(rle_transmitter_init);
EXPORT_SYMBOL(rle_transmitter_destroy);
EXPORT_SYMBOL(rle_transmitter_encap_data);
EXPORT_SYMBOL(rle_transmitter_get_packet);
EXPORT_SYMBOL(rle_transmitter_dump);
#endif

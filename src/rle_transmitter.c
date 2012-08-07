/**
 * @file   rle_transmitter.c
 * @author Aurelien Castanie
 * @date   Mon Aug  6 09:27:35 CEST 2012
 *
 * @brief  RLE transmitter functions
 *
 *
 */

#include "rle_transmitter.h"

static void init(struct transmitter_module *_this)
{
	/* allocating buffer for each frag_id
	 * and initialize sequence number and
	 * fragment id */
	for (int i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_init(_this->rle_ctx_man[i]);
		rle_ctx_set_frag_id(_this->rle_ctx_man[i], i);
		rle_ctx_set_seq_nb(_this->rle_ctx_man[i], 0);
	}

	/* all frag_id are set to idle */
	_this->free_ctx = 0;
}

static int get_first_free_frag_ctx(struct transmitter_module *_this)
{
	for (int i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		if ((_this->free_ctx >> i) == 0)
			return i;
	}

	return C_ERROR;
}

static void set_nonfree_frag_ctx(struct transmitter_module *_this,
				int index)
{
	_this->free_ctx = (1 << index);
}


struct transmitter_module *rle_transmitter_new(void)
{
	struct transmitter_module *_this = NULL;
	_this = malloc(sizeof(struct transmitter_module));
	if (!_this) {
		printf("ERROR %s:%s:%d: allocating transmitter module failed\n",
				__FILE__, __func__, __LINE__);
		return NULL;
	}

	init(_this);

	return(_this);
}

void rle_transmitter_destroy(struct transmitter_module *_this)
{
	for (int i = 0; i < RLE_MAX_FRAG_NUMBER; i++)
		rle_ctx_destroy(_this->rle_ctx_man[i]);

	free(_this);
	_this = NULL;
}


void rle_transmitter_encap_data(struct transmitter_module *_this,
				void *data_buffer, size_t data_length)
{
	if (!data_buffer) {
		printf("ERROR %s:%s:%d: data buffer is invalid\n",
				__FILE__, __func__, __LINE__);
		return;
	}

	if (!_this) {
		printf("ERROR %s:%s:%d: transmitter module is invalid\n",
				__FILE__, __func__, __LINE__);
		return;
	}

	/* get first free frag context */
	int index_ctx = get_first_free_frag_ctx(_this);
	if (index_ctx < 0) {
		printf("ERROR %s:%s:%d: no free fragmentation context available "
				"for encapsulation\n",
				__FILE__, __func__, __LINE__);
		return;
	}

	/* set to 'used' the previously free frag context */
	set_nonfree_frag_ctx(_this, index_ctx);

	/* encap data if found */
	encap_encapsulate_pdu(_this->rle_ctx_man[index_ctx], data_buffer, data_length);
}


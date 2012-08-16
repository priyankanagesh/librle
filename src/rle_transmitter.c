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


static int get_first_free_frag_ctx(struct transmitter_module *_this)
{
	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		if (((_this->free_ctx >> i) & 0x1) == 0)
			return i;
	}

	return C_ERROR;
}

static void set_nonfree_frag_ctx(struct transmitter_module *_this,
				int index)
{
	_this->free_ctx |= (1 << index);
}

static void set_free_frag_ctx(struct transmitter_module *_this,
				int index)
{
	_this->free_ctx = (0 << index) & 0xff;
}

static void set_free_all_frag_ctx(struct transmitter_module *_this)
{
	_this->free_ctx = 0;
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

	/* all frag_id are set to idle */
	set_free_all_frag_ctx(_this);
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

	return _this;
}

void rle_transmitter_destroy(struct transmitter_module *_this)
{
	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++)
		rle_ctx_destroy(&_this->rle_ctx_man[i]);

	set_free_all_frag_ctx(_this);

	free(_this);
	_this = NULL;
}


int rle_transmitter_encap_data(struct transmitter_module *_this,
				void *data_buffer, size_t data_length)
{
	int ret = C_ERROR;

	if (!data_buffer) {
		printf("ERROR %s:%s:%d: data buffer is invalid\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	if (!_this) {
		printf("ERROR %s:%s:%d: transmitter module is invalid\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	/* get first free frag context */
	int index_ctx = get_first_free_frag_ctx(_this);
	if (index_ctx < 0) {
		printf("ERROR %s:%s:%d: no free fragmentation context available "
				"for encapsulation\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	/* set to 'used' the previously free frag context */
	set_nonfree_frag_ctx(_this, index_ctx);

	if (encap_encapsulate_pdu(&_this->rle_ctx_man[index_ctx], data_buffer, data_length)
			== C_ERROR) {
		set_free_frag_ctx(_this, index_ctx);
		printf("ERROR %s:%s:%d: cannot encapsulate data\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	ret = C_OK;
	return ret;
}

void rle_transmitter_dump(struct transmitter_module *_this)
{
	int i;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_dump(&_this->rle_ctx_man[i]);
	}
	printf("-------> Free context [0x%0x]\n", _this->free_ctx);
}

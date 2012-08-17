/**
 * @file   rle_receiver.c
 * @author Aurelien Castanie
 *
 * @brief  RLE receiver functions
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include "rle_receiver.h"
#include "rle_ctx.h"
#include "constants.h"
#include "header.h"
#include "trailer.h"
#include "deencap.h"
#include "reassembly.h"

static int get_first_free_frag_ctx(struct receiver_module *_this)
{
	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		if (((_this->free_ctx >> i) & 0x1) == 0)
			return i;
	}

	return C_ERROR;
}

static void set_nonfree_frag_ctx(struct receiver_module *_this,
				int index)
{
	_this->free_ctx |= (1 << index);
}

static void set_free_frag_ctx(struct receiver_module *_this,
				int index)
{
	_this->free_ctx = (0 << index) & 0xff;
}

static void set_free_all_frag_ctx(struct receiver_module *_this)
{
	_this->free_ctx = 0;
}

static int get_fragment_type(void *data_buffer)
{
	union rle_header_all *head = (union rle_header_all *)data_buffer;
	int type_rle_frag = C_ERROR;

	switch (head->b.start_ind) {
		case 0x0:
			if (head->b.end_ind == 0x0)
				type_rle_frag = RLE_PDU_CONT_FRAG;
			else
				type_rle_frag = RLE_PDU_END_FRAG;
			break;
		case 0x1:
			if (head->b.end_ind == 0x0)
				type_rle_frag = RLE_PDU_START_FRAG;
			else
				type_rle_frag = RLE_PDU_COMPLETE;
			break;
		default:
			printf("ERROR %s:%s:%d: invalid/unknown RLE fragment type S [%x] E [%x]\n",
					__FILE__, __func__, __LINE__,
					head->b.start_ind, head->b.end_ind);
			break;
	}

	return type_rle_frag;
}

static uint16_t get_fragment_id(void *data_buffer)
{
	union rle_header_all *head = (union rle_header_all *)data_buffer;

	return head->b.frag_id;
}

/* provided data_buffer pointer needs
 * to be set after data payload */
static uint8_t get_seq_no(void *data_buffer) __attribute__ ((unused));
static uint8_t get_seq_no(void *data_buffer)
{
	struct rle_trailer *trl = (struct rle_trailer *)data_buffer;

	return trl->seq_no;
}

/* provided data_buffer pointer needs
 * to be set after data payload */
static uint32_t get_crc(void *data_buffer) __attribute__ ((unused));
static uint32_t get_crc(void *data_buffer)
{
	struct rle_trailer *trl = (struct rle_trailer *)data_buffer;

	return trl->crc;
}

static uint16_t get_rle_packet_length(void *data_buffer) __attribute__ ((unused));
static uint16_t get_rle_packet_length(void *data_buffer)
{
	union rle_header_all *head = (union rle_header_all *)data_buffer;

	return head->b.rle_packet_length;
}

static void init(struct receiver_module *_this)
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

struct receiver_module *rle_receiver_new(void)
{
	struct receiver_module *_this = NULL;

	_this = malloc(sizeof(struct receiver_module));

	if (!_this) {
		printf("ERROR %s:%s:%d: allocating receiver module failed\n",
				__FILE__, __func__, __LINE__);
		return NULL;
	}

	init(_this);

	return _this;
}

void rle_receiver_destroy(struct receiver_module *_this)
{
	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++)
		rle_ctx_destroy(&_this->rle_ctx_man[i]);

	free(_this);
	_this = NULL;
}

int rle_receiver_deencap_data(struct receiver_module *_this,
				void *data_buffer, size_t data_length)
{
	int ret = C_ERROR;

	if (!data_buffer) {
		printf("ERROR %s:%s:%d: data buffer is invalid\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	if (!_this) {
		printf("ERROR %s:%s:%d: receiver module is invalid\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	/* check PPDU validity */
	if (data_length > RLE_MAX_PDU_SIZE) {
		printf("ERROR %s:%s:%d: Packet too long [%zu]\n",
				__FILE__, __func__, __LINE__, data_length);
		return ret;
	}

	/* retrieve frag id if its a fragmented packet to append data to the
	 * right frag id context (SE bits)
	 * or
	 * search for the first free frag id context to put data into it */
	int frag_type = get_fragment_type(data_buffer);
	int index_ctx = -1;

	switch (frag_type) {
		case RLE_PDU_COMPLETE:
			index_ctx = get_first_free_frag_ctx(_this);
			if (index_ctx < 0) {
				printf("ERROR %s:%s:%d: no free reassembly context available "
						"for deencapsulation\n",
						__FILE__, __func__, __LINE__);
				return C_ERROR;
			}
			break;
		case RLE_PDU_START_FRAG:
		case RLE_PDU_CONT_FRAG:
		case RLE_PDU_END_FRAG:
			index_ctx = get_fragment_id(data_buffer);
			if ((index_ctx < 0) || (index_ctx > RLE_MAX_FRAG_ID)) {
				printf("ERROR %s:%s:%d: invalid fragment id [%d]\n",
						__FILE__, __func__, __LINE__, index_ctx);
				return C_ERROR;
			}
			break;
		default:
			return C_ERROR;
			break;
	}

	/* set the previously free frag ctx
	 * or force already
	 * set frag ctx to 'used' state */
	set_nonfree_frag_ctx(_this, index_ctx);

	/* reassemble all fragments */
	if (reassembly_reassemble_pdu(&_this->rle_ctx_man[index_ctx],
				data_buffer,
				data_length,
				frag_type) != C_OK) {
		/* received RLE packet is invalid,
		 * we have to flush all status info */
		rle_ctx_invalid_ctx(&_this->rle_ctx_man[index_ctx]);
		set_free_frag_ctx(_this, index_ctx);
		printf("ERROR %s:%s:%d: cannot reassemble data\n",
				__FILE__, __func__, __LINE__);
		return ret;
	}

	ret = C_OK;
	return ret;
}

void rle_receiver_dump(struct receiver_module *_this)
{
	int i;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_dump(&_this->rle_ctx_man[i]);
	}
	printf("-------> Free context [0x%0x]\n", _this->free_ctx);
}

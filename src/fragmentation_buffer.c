/**
 * @file   fragmentation_buffer.c
 * @brief  RLE fragmentation buffer functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "rle.h"
#include "constants.h"
#include "fragmentation_buffer.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>

#else

#include <linux/string.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_FRAGMENTATION_BUFFER


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

struct rle_frag_buf *rle_frag_buf_new(void)
{
	struct rle_frag_buf *frag_buf =
	        (struct rle_frag_buf *)MALLOC(sizeof(struct rle_frag_buf));

	if (!frag_buf) {
		PRINT_RLE_ERROR("fragmentation buffer not allocated.");
		goto out;
	}

	frag_buf->sdu.frag_buf = frag_buf;
	frag_buf->alpdu.frag_buf = frag_buf;
	frag_buf->ppdu.frag_buf = frag_buf;

out:

	return frag_buf;
}

void rle_frag_buf_del(struct rle_frag_buf **const frag_buf)
{
	if (!frag_buf) {
		PRINT_RLE_WARNING("fragmentation buffer pointer NULL, nothing can be done.");
		goto out;
	}

	if (!*frag_buf) {
		PRINT_RLE_WARNING("fragmentation buffer NULL, nothing to do.");
		goto out;
	}

	FREE(*frag_buf);
	*frag_buf = NULL;

out:

	return;
}

int rle_frag_buf_init(struct rle_frag_buf *const frag_buf)
{
	if (frag_buf == NULL) {
		return 1;
	}

	memset(frag_buf->buffer, '\0', RLE_F_BUFF_LEN);

	frag_buf->cur_pos = frag_buf->buffer + sizeof(rle_ppdu_header_t) +
	                    sizeof(rle_alpdu_header_t);

	frag_buf_ptrs_set(&frag_buf->sdu, frag_buf->cur_pos);
	frag_buf_ptrs_set(&frag_buf->alpdu, frag_buf->cur_pos);
	frag_buf_ptrs_set(&frag_buf->ppdu, frag_buf->cur_pos);

	return 0;
}

int rle_frag_buf_cpy_sdu(struct rle_frag_buf *const frag_buf, const struct rle_sdu *const sdu)
{
	if (sdu->size > RLE_MAX_PDU_SIZE || frag_buf_in_use(frag_buf)) {
		return 1;
	}

	frag_buf_sdu_put(frag_buf, sdu->size);
	frag_buf->sdu_info.buffer = frag_buf->sdu.start;
	frag_buf->sdu_info.protocol_type = sdu->protocol_type;
	frag_buf->sdu_info.size = sdu->size;

	memcpy(frag_buf->sdu.start, sdu->buffer, sdu->size);

	return 0;
}

void frag_buf_sdu_push(rle_frag_buf_t *const frag_buf, const ssize_t size)
{
	frag_buf_ptrs_push(&frag_buf->sdu, size);
	frag_buf_ptrs_push(&frag_buf->alpdu, size);
	frag_buf_ptrs_set(&frag_buf->ppdu, frag_buf->alpdu.start);
	frag_buf_set_cur_pos(frag_buf);
}

void frag_buf_ppdu_put(rle_frag_buf_t *const frag_buf, const size_t size)
{
	const size_t ppdu_base_hdr_len = 2;
	size_t bounded_size;

	assert(size <= (RLE_MAX_PPDU_PL_SIZE + ppdu_base_hdr_len));

	if (frag_buf_get_remaining_alpdu_length(frag_buf) < size) {
		bounded_size = frag_buf_get_remaining_alpdu_length(frag_buf);
	} else {
		bounded_size = size;
	}

	frag_buf_ptrs_put(&frag_buf->ppdu, bounded_size);
}

size_t frag_buf_get_remaining_alpdu_length(const rle_frag_buf_t *const frag_buf)
{
	size_t remaining_alpdu_length;

	assert(frag_buf_in_use(frag_buf));
	assert(frag_buf->alpdu.end >= frag_buf->cur_pos);

	remaining_alpdu_length = frag_buf->alpdu.end - frag_buf->cur_pos;

	return remaining_alpdu_length;
}

size_t frag_buf_get_current_ppdu_len(const rle_frag_buf_t *const frag_buf)
{
	size_t current_ppdu_len;

	assert(frag_buf_in_use(frag_buf));

	current_ppdu_len = frag_buf->ppdu.end - frag_buf->ppdu.start;

	return current_ppdu_len;
}


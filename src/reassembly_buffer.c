/**
 * @file   reassembly_buffer.c
 * @brief  RLE reassembly buffer functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "reassembly_buffer.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "REASSEMBLY_BUFFER"


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

void rasm_buf_sdu_frag_put(rle_rasm_buf_t *const rasm_buf, const size_t size)
{
	assert((rasm_buf->sdu_frag.end + size) <= rasm_buf->sdu.end);

	rasm_buf_ptrs_put(&rasm_buf->sdu_frag, size);
}

void rasm_buf_cpy_sdu_frag(rle_rasm_buf_t *const rasm_buf,
                           const unsigned char sdu_frag[])
{
	assert(rasm_buf_in_use(rasm_buf));

	if (rasm_buf->sdu_frag.end != rasm_buf->sdu_frag.start) {
		memcpy(rasm_buf->sdu_frag.start, sdu_frag,
		       rasm_buf->sdu_frag.end - rasm_buf->sdu_frag.start);
	}
}

size_t rasm_buf_get_sdu_length(const rle_rasm_buf_t *const rasm_buf)
{
	assert(rasm_buf->sdu.end >= rasm_buf->sdu.start);
	return (rasm_buf->sdu.end - rasm_buf->sdu.start);
}

size_t rasm_buf_get_reassembled_sdu_length(const rle_rasm_buf_t *const rasm_buf)
{
	assert(rasm_buf->sdu_frag.end >= rasm_buf->sdu.start);
	return (rasm_buf->sdu_frag.end - rasm_buf->sdu.start);
}


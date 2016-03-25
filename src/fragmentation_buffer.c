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

#define MODULE_NAME "FRAGMENTATION_BUFFER"


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
	int status;

	if (frag_buf == NULL) {
		return 1;
	}

	memset(frag_buf->buffer, '\0', RLE_F_BUFF_LEN);

	frag_buf->cur_pos = frag_buf->buffer + sizeof(rle_ppdu_header_t) +
	                    sizeof(rle_alpdu_header_t);

	status = frag_buf_ptrs_set(&frag_buf->sdu, frag_buf->cur_pos);
	status |= frag_buf_ptrs_set(&frag_buf->alpdu, frag_buf->cur_pos);
	status |= frag_buf_ptrs_set(&frag_buf->ppdu, frag_buf->cur_pos);

	return status;
}

int rle_frag_buf_cpy_sdu(struct rle_frag_buf *const frag_buf, const struct rle_sdu *const sdu)
{
	int status = 1;

	if (sdu->size > RLE_MAX_PDU_SIZE) {
		PRINT_RLE_ERROR("SDU is too big (%zu/%d).", sdu->size, RLE_MAX_PDU_SIZE);
		goto out;
	}

	if (frag_buf_in_use(frag_buf)) {
		PRINT_RLE_ERROR("fragmentation buffer in use.");
		goto out;
	}

	if (frag_buf_sdu_put(frag_buf, sdu->size) != 0) {
		PRINT_RLE_ERROR("unable to reserve space for sdu.");
		goto out;
	}

	frag_buf->sdu_info.buffer = frag_buf->sdu.start;
	frag_buf->sdu_info.protocol_type = sdu->protocol_type;
	frag_buf->sdu_info.size = sdu->size;

	memcpy(frag_buf->sdu.start, sdu->buffer, sdu->size);

	status = 0;

out:

	return status;
}

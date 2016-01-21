/**
 * @file   fragmentation_buffer.c
 * @brief  RLE fragmentation buffer functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>

#else

#include <linux/string.h>

#endif

#include "rle.h"
#include "constants.h"
#include "fragmentation_buffer.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "FRAGMENTATION_BUFFER"


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

struct rle_fragmentation_buffer *rle_f_buff_new(void)
{
	struct rle_fragmentation_buffer *f_buff =
	        (struct rle_fragmentation_buffer *)MALLOC(sizeof(struct rle_fragmentation_buffer));

	if (!f_buff) {
		PRINT_RLE_ERROR("fragmentation buffer not allocated.");
		goto out;
	}

	f_buff->sdu.f_buff   = f_buff;
	f_buff->alpdu.f_buff = f_buff;
	f_buff->ppdu.f_buff  = f_buff;

out:

	return f_buff;
}

void rle_f_buff_del(struct rle_fragmentation_buffer **const f_buff)
{
	if (!f_buff) {
		PRINT_RLE_WARNING("fragmentation buffer pointer NULL, nothing can be done.");
		goto out;
	}

	if (!*f_buff) {
		PRINT_RLE_WARNING("fragmentation buffer NULL, nothing to do.");
		goto out;
	}

	FREE(*f_buff);
	*f_buff = NULL;

out:

	return;
}

int rle_f_buff_init(struct rle_fragmentation_buffer *const f_buff)
{
	int status = 1;

	memset(f_buff->buffer, '\0', RLE_F_BUFF_LEN);

	f_buff->cur_pos = f_buff->buffer + sizeof(rle_ppdu_header_t) + sizeof(rle_alpdu_header_t);

	status =  f_buff_ptrs_set(&f_buff->sdu,   f_buff->cur_pos);
	status |= f_buff_ptrs_set(&f_buff->alpdu, f_buff->cur_pos);
	status |= f_buff_ptrs_set(&f_buff->ppdu,  f_buff->cur_pos);

	return status;
}

int rle_f_buff_cpy_sdu(struct rle_fragmentation_buffer *const f_buff,
                       const struct rle_sdu *const sdu)
{
	int status = 1;

	if (sdu->size > RLE_MAX_PDU_SIZE) {
		PRINT_RLE_ERROR("SDU is too big (%zu/%d).", sdu->size, RLE_MAX_PDU_SIZE);
		goto out;
	}

	if (f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer in use.");
		goto out;
	}

	if (f_buff_sdu_put(f_buff, sdu->size) != 0) {
		PRINT_RLE_ERROR("unable to reserve space for sdu.");
		goto out;
	}

	f_buff->sdu_info.buffer = f_buff->sdu.start;
	f_buff->sdu_info.protocol_type = sdu->protocol_type;
	f_buff->sdu_info.size = sdu->size;

	memcpy(f_buff->sdu.start, sdu->buffer, sdu->size);

	status = 0;

out:

	return status;
}

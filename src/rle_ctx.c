/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file   rle_ctx.c
 * @brief  RLE transmitter functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_ctx.h"
#include "constants.h"
#include "fragmentation_buffer.h"
#include "reassembly_buffer.h"

#ifndef __KERNEL__

#include <stddef.h>
#include <stdbool.h>
#include <assert.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_CTX


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PRIVATE FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief  Flush all data and pointer of a RLE context structure.
 *
 *  @param[in,out]  _this  Pointer to the RLE context structure.
 *
 *  @ingroup RLE context
 */
static void flush(struct rle_ctx_mngt *_this);

/**
 *  @brief  Flush all data and pointer of a RLE context structure with fragmentation buffers.
 *
 *  @param[in,out]  _this  Pointer to the RLE context structure.
 *
 *  @ingroup RLE context
 */
static void flush_ctxt_frag_buf(struct rle_ctx_mngt *_this);

/**
 *  @brief  Flush all data and pointer of a RLE context structure with reassembly buffers.
 *
 *  @param[in,out]  _this  Pointer to the RLE context structure.
 *
 *  @ingroup RLE context
 */
static void flush_ctxt_rasm_buf(struct rle_ctx_mngt *_this);


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static void flush(struct rle_ctx_mngt *_this)
{
	_this->frag_id = 0xff;
	_this->next_seq_nb = 0xff;
	_this->use_crc = false;
	rle_ctx_reset_counters(_this);

	return;
}

static void flush_ctxt_frag_buf(struct rle_ctx_mngt *_this)
{
	int ret;

	flush(_this);

	ret = rle_frag_buf_init((rle_frag_buf_t *)_this->buff);
	assert(ret == 0); /* cannot fail since frag_buf is not NULL */

	return;
}

static void flush_ctxt_rasm_buf(struct rle_ctx_mngt *_this)
{
	flush(_this);
	rasm_buf_init((rle_rasm_buf_t *)_this->buff);

	return;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int rle_ctx_init_frag_buf(struct rle_ctx_mngt *_this)
{
	int status = C_ERROR;

	assert(_this != NULL);

	_this->buff = (void *)rle_frag_buf_new();

	/* allocate enough memory space for the fragmentation */
	if (!_this->buff) {
		RLE_ERR("fragmentation buffer allocation failed.");
		goto out;
	}

	/* set to zero or invalid values all variables */
	flush_ctxt_frag_buf(_this);

	status = C_OK;

out:
	return status;
}

int rle_ctx_init_rasm_buf(struct rle_ctx_mngt *_this)
{
	int status = C_ERROR;

	assert(_this != NULL);

	/* allocate enough memory space for the reassembly */
	_this->buff = (void *)rasm_buf_new();
	if (!_this->buff) {
		RLE_ERR("reassembly buffer allocation failed.");
		goto out;
	}

	/* set to zero or invalid values all variables */
	flush_ctxt_rasm_buf(_this);

	status = C_OK;

out:
	return status;
}

void rle_ctx_destroy_frag_buf(struct rle_ctx_mngt *_this)
{
	assert(_this != NULL);
	assert(_this->buff != NULL);

	flush(_this);

	rle_frag_buf_del((rle_frag_buf_t **)&_this->buff);
}

void rle_ctx_destroy_rasm_buf(struct rle_ctx_mngt *_this)
{
	assert(_this != NULL);
	assert(_this->buff != NULL);

	rasm_buf_del((rle_rasm_buf_t **)&_this->buff);
}

void rle_ctx_set_seq_nb(struct rle_ctx_mngt *_this, uint8_t val)
{
	_this->next_seq_nb = val;
}

uint8_t rle_ctx_get_seq_nb(const struct rle_ctx_mngt *const _this)
{
	return _this->next_seq_nb;
}

void rle_ctx_incr_seq_nb(struct rle_ctx_mngt *_this)
{
	_this->next_seq_nb = (_this->next_seq_nb + 1) % RLE_MAX_SEQ_NO;
}

void rle_ctx_set_use_crc(struct rle_ctx_mngt *_this, bool val)
{
	_this->use_crc = val;
}

bool rle_ctx_get_use_crc(const struct rle_ctx_mngt *const _this)
{
	return _this->use_crc;
}

size_t get_fragment_length(const unsigned char *const buffer)
{
	const rle_ppdu_hdr_t *const ppdu_hdr = (rle_ppdu_hdr_t *)buffer;

	return (rle_ppdu_hdr_get_ppdu_length(ppdu_hdr) + sizeof(ppdu_hdr->common));
}

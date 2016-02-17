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

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "RLE CTX"


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
static void flush(struct rle_ctx_management *_this);

/**
 *  @brief  Flush all data and pointer of a RLE context structure with fragmentation buffers.
 *
 *  @param[in,out]  _this  Pointer to the RLE context structure.
 *
 *  @ingroup RLE context
 */
static void flush_ctxt_f_buff(struct rle_ctx_management *_this);

/**
 *  @brief  Flush all data and pointer of a RLE context structure with reassembly buffers.
 *
 *  @param[in,out]  _this  Pointer to the RLE context structure.
 *
 *  @ingroup RLE context
 */
static void flush_ctxt_r_buff(struct rle_ctx_management *_this);


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static void flush(struct rle_ctx_management *_this)
{
	_this->frag_id = 0xff;
	_this->next_seq_nb = 0xff;
	_this->use_crc = false;
	rle_ctx_reset_counters(_this);

	return;
}

static void flush_ctxt_f_buff(struct rle_ctx_management *_this)
{
	flush(_this);
	rle_f_buff_init((rle_f_buff_t *)_this->buff);

	return;
}

static void flush_ctxt_r_buff(struct rle_ctx_management *_this)
{

	flush(_this);
	r_buff_init((rle_r_buff_t *)_this->buff);

	return;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int rle_ctx_init_f_buff(struct rle_ctx_management *_this)
{
	int status = C_ERROR;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!_this) {
		PRINT_RLE_ERROR("RLE ctxt fragmentation failed.");
		goto out;
	}

	_this->buff = (void *)rle_f_buff_new();

	/* allocate enough memory space for the fragmentation */
	if (!_this->buff) {
		PRINT_RLE_ERROR("fragmentation buffer allocation failed.");
		goto out;
	}

	/* set to zero or invalid values all variables */
	flush_ctxt_f_buff(_this);

	status = C_OK;

out:
	return status;
}

int rle_ctx_init_r_buff(struct rle_ctx_management *_this)
{
	int status = C_ERROR;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!_this) {
		PRINT_RLE_ERROR("RLE ctxt fragmentation failed.");
		goto out;
	}

	/* allocate enough memory space for the reassembly */
	_this->buff = (void *)r_buff_new();
	if (!_this->buff) {
		PRINT_RLE_ERROR("reassembly buffer allocation failed.");
		goto out;
	}

	/* set to zero or invalid values all variables */
	flush_ctxt_r_buff(_this);

	status = C_OK;

out:
	return status;
}

int rle_ctx_destroy_f_buff(struct rle_ctx_management *_this)
{
	int status = C_ERROR;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!_this) {
		PRINT_RLE_ERROR("RLE context is NULL.");
		goto out;
	}

	flush(_this);

	if (_this->buff) {
		rle_f_buff_del((rle_f_buff_t **)&_this->buff);
	}

	status = C_OK;

out:
	return status;
}

int rle_ctx_destroy_r_buff(struct rle_ctx_management *_this)
{
	int status = C_ERROR;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!_this) {
		PRINT_RLE_ERROR("RLE context is NULL.");
		goto out;
	}

	r_buff_del((rle_r_buff_t **)&_this->buff);

	status = C_OK;

out:
	return status;
}

void rle_ctx_set_frag_id(struct rle_ctx_management *_this, uint8_t val)
{
	if (val > RLE_MAX_FRAG_ID) {
		PRINT_RLE_ERROR("Invalid fragment id.");
	} else {
		_this->frag_id = val;
	}

	return;
}

void rle_ctx_set_seq_nb(struct rle_ctx_management *_this, uint8_t val)
{
	_this->next_seq_nb = val;
}

uint8_t rle_ctx_get_seq_nb(const struct rle_ctx_management *const _this)
{
	return _this->next_seq_nb;
}

void rle_ctx_incr_seq_nb(struct rle_ctx_management *_this)
{
	_this->next_seq_nb++;
}

void rle_ctx_set_use_crc(struct rle_ctx_management *_this, int val)
{
	_this->use_crc = val;
}

int rle_ctx_get_use_crc(const struct rle_ctx_management *const _this)
{
	return _this->use_crc;
}

size_t get_fragment_length(const unsigned char *const buffer)
{
	size_t fragment_length = 0;
	enum frag_states fragment_type = RLE_PDU_COMPLETE;

	fragment_type = rle_ppdu_get_fragment_type((rle_ppdu_header_t *)buffer);

	switch (fragment_type) {
	case RLE_PDU_COMPLETE:
		fragment_length += sizeof(rle_ppdu_header_comp_t);
		break;
	case RLE_PDU_CONT_FRAG:
	case RLE_PDU_END_FRAG:
		fragment_length += sizeof(rle_ppdu_header_cont_end_t);
		break;
	case RLE_PDU_START_FRAG:
		fragment_length += sizeof(rle_ppdu_header_start_t);
		break;
	default:
		PRINT_RLE_ERROR("Unhandled fragment type '%i'.", fragment_type);
		break;
	}

	fragment_length += rle_ppdu_header_get_ppdu_length((rle_ppdu_header_t *)buffer);

	return fragment_length;
}

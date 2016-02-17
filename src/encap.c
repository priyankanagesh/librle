/**
 * @file   encap.c
 * @brief  RLE encapsulation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "encap.h"
#include "rle_transmitter.h"
#include "constants.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"
#include "rle.h"
#include "fragmentation_buffer.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/ethernet.h>

#else

#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "ENCAP"


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static int is_frag_ctx_free(struct rle_transmitter *const _this, const size_t ctx_index)
{
#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	return rle_ctx_is_free(_this->free_ctx, ctx_index);
}

static void set_nonfree_frag_ctx(struct rle_transmitter *const _this, const size_t ctx_index)
{
#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	rle_ctx_set_nonfree(&_this->free_ctx, ctx_index);

	return;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_encap_status rle_encapsulate(struct rle_transmitter *const transmitter,
                                      const struct rle_sdu *const sdu, const uint8_t frag_id)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	enum rle_encap_status ret_encap;
	struct rle_ctx_management *rle_ctx;
	rle_f_buff_t *f_buff;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (transmitter == NULL) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto out;
	}

	if (frag_id >= RLE_MAX_FRAG_NUMBER) {
		goto out;
	}

	rle_ctx = &transmitter->rle_ctx_man[frag_id];
	f_buff = (rle_f_buff_t *)rle_ctx->buff;

	if (sdu->size > RLE_MAX_PDU_SIZE) {
		status = RLE_ENCAP_ERR_SDU_TOO_BIG;
		rle_transmitter_free_context(transmitter, frag_id);
		goto out;
	}

	if (is_frag_ctx_free(transmitter, frag_id) == false) {
		PRINT_RLE_ERROR("frag id %d is not free", frag_id);
		goto out;
	}

	/* set to 'used' the previously free frag context */
	set_nonfree_frag_ctx(transmitter, frag_id);

	rle_f_buff_init(f_buff);
	if (rle_f_buff_cpy_sdu(f_buff, sdu) != 0) {
		PRINT_RLE_ERROR("unable to copy SDU in fragmentation buffer.");
		goto out;
	}

	ret_encap = rle_encap_contextless(transmitter, f_buff);

	rle_ctx_incr_counter_in(rle_ctx);
	rle_ctx_incr_counter_bytes_in(rle_ctx, sdu->size);

	if (ret_encap != RLE_ENCAP_OK) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, sdu->size);
		rle_ctx_set_free(&transmitter->free_ctx, frag_id);
		PRINT_RLE_ERROR("cannot encapsulate data.");
		goto out;
	}

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld]\n", MODULE_NAME, tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	status = RLE_ENCAP_OK;

out:
	return status;
}

enum rle_encap_status rle_encap_contextless(struct rle_transmitter *const transmitter,
                                            struct rle_fragmentation_buffer *const f_buff)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	struct rle_configuration *rle_conf;

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	if (!transmitter) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto out;
	}

	rle_conf = transmitter->rle_conf;

	if (!f_buff) {
		status = RLE_ENCAP_ERR_NULL_F_BUFF;
		goto out;
	}

	if (!f_buff_in_use(f_buff)) {
		status = RLE_ENCAP_ERR_N_INIT_F_BUFF;
		goto out;
	}

	if (push_alpdu_header(f_buff, rle_conf) == 0) {
		status = RLE_ENCAP_OK;
	}

out:
	return status;
}


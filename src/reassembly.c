/**
 * @file   reassembly.c
 * @brief  RLE reassembly functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "reassembly.h"
#include "rle_receiver.h"
#include "constants.h"
#include "header.h"
#include "trailer.h"
#include "crc.h"
#include "rle_header_proto_type_field.h"

#ifndef __KERNEL__

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#else

#include <linux/string.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "REASSEMBLY"


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int reassembly_comp_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                         const size_t ppdu_length,
                         struct rle_sdu *const reassembled_sdu)
{
	int ret = C_ERROR;
	const unsigned char *alpdu_fragment;
	size_t alpdu_fragment_len;
	const unsigned char *sdu_fragment;
	size_t sdu_fragment_len;
	uint16_t protocol_type;
	const rle_ppdu_header_comp_t *const header = (const rle_ppdu_header_comp_t *)ppdu;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	comp_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment, &alpdu_fragment_len);

	if (alpdu_fragment_len == 0) {
		PRINT_RLE_ERROR("Error: No ALPDU in Complete PPDU.");
		goto out;
	}

	if (rle_comp_ppdu_header_get_is_suppressed(header)) {
		/* protocol type is suppressed */
		if (rle_comp_ppdu_header_get_is_signal(header)) {
			/* ALPDU label type 3 means that the implicit protocol type is L2S */
			ret = signal_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
			                                        &protocol_type, &sdu_fragment,
			                                        &sdu_fragment_len);
		} else {
			/* ALPDU label type 0, 1 or 2 mean that the implicit protocol type
			 * is given by the configuration */
			ret = suppressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
			                                            &protocol_type,
			                                            &sdu_fragment, &sdu_fragment_len,
			                                            &_this->conf);
		}
	} else if (_this->conf.use_compressed_ptype) {
		/* protocol type is not suppressed, but compressed */
		ret =
		        compressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                              &protocol_type,
		                                              &sdu_fragment, &sdu_fragment_len,
		                                              NULL);
	} else {
		/* protocol type is not suppressed nor compressed */
		ret = uncompressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                              &protocol_type, &sdu_fragment,
		                                              &sdu_fragment_len);
	}

	if (ret) {
		ret = C_ERROR;
		goto out;
	}

	reassembled_sdu->size = sdu_fragment_len;
	reassembled_sdu->protocol_type = protocol_type;
	memcpy((void *)reassembled_sdu->buffer, (const void *)sdu_fragment, sdu_fragment_len);

	ret = C_REASSEMBLY_OK;

out:
#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld].", MODULE_NAME, tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	return ret;
}

int reassembly_start_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                          const size_t ppdu_length,
                          int *const index_ctx)
{
	int ret = C_ERROR;
	const unsigned char *alpdu_fragment;
	size_t alpdu_fragment_len;
	const unsigned char *sdu_fragment;
	size_t sdu_fragment_len;
	uint16_t protocol_type;
	rle_rasm_buf_t *rasm_buf;
	size_t alpdu_total_len;
	const rle_ppdu_header_start_t *header;
	struct rle_ctx_management *rle_ctx = NULL;
	size_t sdu_total_len;
	int is_crc_used;
	size_t alpdu_hdr_len;
	size_t alpdu_trailer_len;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	*index_ctx = rle_start_ppdu_header_get_fragment_id((rle_ppdu_header_start_t *)ppdu);
#ifdef DEBUG
	PRINT_RLE_DEBUG("fragment_id 0x%0x frag type %d.", MODULE_NAME, *index_ctx, frag_type);
#endif
	assert((*index_ctx) >= 0 && (*index_ctx) <= RLE_MAX_FRAG_ID);

	rle_ctx = &_this->rle_ctx_man[*index_ctx];
	rle_ctx->current_counter = ppdu_length;
	rasm_buf = (rle_rasm_buf_t *)_this->rle_ctx_man[*index_ctx].buff;

	rle_ctx_incr_counter_in(rle_ctx);
	rle_ctx_incr_counter_bytes_in(rle_ctx, ppdu_length);

	if (is_context_free(_this, *index_ctx) == false) {
		PRINT_RLE_ERROR("invalid Start on context not free, frag id [%d].", *index_ctx);
		/* Context is not free, whereas it must be. an error must have occured. */
		/* Freeing context, updating stats, and restarting receiving. */
		goto out;
	}

	set_nonfree_frag_ctx(_this, *index_ctx);

	start_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment, &alpdu_fragment_len,
	                                  &alpdu_total_len, &is_crc_used);
	header = (const rle_ppdu_header_start_t *)ppdu;

	sdu_total_len = alpdu_total_len;

	if (rle_start_ppdu_header_get_is_suppressed(header)) {
		/* protocol type is suppressed */
		if (rle_start_ppdu_header_get_is_signal(header)) {
			/* ALPDU label type 3 means that the implicit protocol type is L2S */
			ret = signal_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
			                                        &protocol_type,
			                                        &sdu_fragment, &sdu_fragment_len);
		} else {
			ret = suppressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
			                                            &protocol_type,
			                                            &sdu_fragment, &sdu_fragment_len,
			                                            &_this->conf);
		}
		alpdu_hdr_len = 0;
	} else if (_this->conf.use_compressed_ptype) {
		/* protocol type is not suppressed, but compressed */
		ret =
		        compressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                              &protocol_type,
		                                              &sdu_fragment, &sdu_fragment_len,
		                                              &alpdu_hdr_len);
	} else {
		/* protocol type is not suppressed nor compressed */
		ret = uncompressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                              &protocol_type, &sdu_fragment,
		                                              &sdu_fragment_len);
		alpdu_hdr_len = sizeof(rle_alpdu_header_uncompressed_t);
	}
	if (ret) {
		ret = C_ERROR;
		goto out;
	}

	if (sdu_fragment_len > sdu_total_len) {
		PRINT_RLE_ERROR("PPDU START with frag id %d contains more SDU bytes than "
		                "expected in total (%zu bytes in fragment, %zu bytes "
		                "expected in total)", *index_ctx, sdu_fragment_len,
		                sdu_total_len);
		goto out;
	}
	sdu_total_len -= alpdu_hdr_len;

	if (is_crc_used) {
		alpdu_trailer_len = sizeof(rle_alpdu_crc_trailer_t);
	} else {
		alpdu_trailer_len = sizeof(rle_alpdu_seqno_trailer_t);
	}
	if (alpdu_trailer_len > sdu_total_len) {
		PRINT_RLE_ERROR("PPDU START with frag id %d contains too few bytes for the "
		                "ALDPU trailer (at least %zu bytes needed, but only %zu "
		                "bytes available", *index_ctx, alpdu_trailer_len,
		                sdu_total_len);
		goto out;
	}
	sdu_total_len -= alpdu_trailer_len;

	rle_ctx_set_use_crc(rle_ctx, is_crc_used);

	if (sdu_fragment_len > sdu_total_len) {
		PRINT_RLE_ERROR("PPDU START with frag id %d contains more SDU bytes than "
		                "expected in total (%zu bytes in fragment, %zu bytes "
		                "expected in total)", *index_ctx, sdu_fragment_len,
		                sdu_total_len);
		goto out;
	}
	rasm_buf_init(rasm_buf);
	rasm_buf_sdu_put(rasm_buf, sdu_total_len);
	rasm_buf_sdu_frag_put(rasm_buf, sdu_fragment_len);
	rasm_buf->sdu_info.protocol_type = protocol_type;
	rasm_buf->sdu_info.size = sdu_total_len;
	rasm_buf_cpy_sdu_frag(rasm_buf, sdu_fragment);

	ret = C_OK;

out:

	if ((ret != C_OK) && rle_ctx) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_lost(rle_ctx, 1);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, rle_ctx->current_counter);
		rle_receiver_free_context(_this, *index_ctx);
	}

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld].", MODULE_NAME, tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	return ret;
}

int reassembly_cont_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                         const size_t ppdu_length,
                         int *const index_ctx)
{
	int ret = C_ERROR;
	const unsigned char *alpdu_fragment;
	size_t alpdu_fragment_len;
	const unsigned char *sdu_fragment;
	size_t sdu_fragment_len;
	rle_rasm_buf_t *rasm_buf;
	struct rle_ctx_management *rle_ctx = NULL;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	*index_ctx = rle_cont_end_ppdu_header_get_fragment_id((rle_ppdu_header_cont_end_t *)ppdu);
#ifdef DEBUG
	PRINT_RLE_DEBUG("fragment_id 0x%0x cont PPDU.", MODULE_NAME, *index_ctx);
#endif
	assert((*index_ctx >= 0) && (*index_ctx <= RLE_MAX_FRAG_ID));

	rle_ctx = &_this->rle_ctx_man[*index_ctx];
	rle_ctx->current_counter += ppdu_length;
	rasm_buf = (rle_rasm_buf_t *)_this->rle_ctx_man[*index_ctx].buff;

	rle_ctx_incr_counter_bytes_in(rle_ctx, ppdu_length);

	if (is_context_free(_this, *index_ctx) == true) {
		PRINT_RLE_ERROR("invalid Cont on context free, frag id [%d].", *index_ctx);
		/* Context is free, whereas it must not. an error must have occured. */
		/* Freeing context and updating stats. At least one packet is partialy lost.*/
		goto out;
	}

	cont_end_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment,
	                                     &alpdu_fragment_len);

	sdu_fragment = alpdu_fragment;
	sdu_fragment_len = alpdu_fragment_len;

	if (sdu_fragment_len > rasm_buf_get_sdu_length(rasm_buf)) {
		PRINT_RLE_ERROR("PPDU CONT with frag id %d contains more SDU bytes than "
		                "expected in total (%zu bytes in fragment, %zu bytes "
		                "expected in total)", *index_ctx, sdu_fragment_len,
		                rasm_buf_get_sdu_length(rasm_buf));
		goto out;
	}
	rasm_buf_init_sdu_frag(rasm_buf);
	rasm_buf_sdu_frag_put(rasm_buf, sdu_fragment_len);
	rasm_buf_cpy_sdu_frag(rasm_buf, sdu_fragment);

	ret = C_OK;

out:

	if ((ret != C_OK) && rle_ctx) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_lost(rle_ctx, 1);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, rle_ctx->current_counter);
		rle_receiver_free_context(_this, *index_ctx);
	}

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld].", MODULE_NAME, tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	return ret;
}

int reassembly_end_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                        const size_t ppdu_length, int *const index_ctx,
                        struct rle_sdu *const reassembled_sdu)
{
	int ret = C_ERROR;
	const unsigned char *alpdu_fragment;
	size_t alpdu_fragment_len;
	const unsigned char *sdu_fragment;
	size_t sdu_fragment_len;
	rle_rasm_buf_t *rasm_buf;
	struct rle_ctx_management *rle_ctx = NULL;
	const rle_alpdu_trailer_t *rle_trailer = NULL;
	size_t lost_packets = 0;

#ifdef TIME_DEBUG
	struct timeval tv_start = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_end = { .tv_sec = 0L, .tv_usec = 0L };
	struct timeval tv_delta;
	gettimeofday(&tv_start, NULL);
#endif

#ifdef DEBUG
	PRINT_RLE_DEBUG("", MODULE_NAME);
#endif

	*index_ctx = rle_cont_end_ppdu_header_get_fragment_id((rle_ppdu_header_cont_end_t *)ppdu);
#ifdef DEBUG
	PRINT_RLE_DEBUG("fragment_id 0x%0x End PPDU.", MODULE_NAME, *index_ctx);
#endif
	assert((*index_ctx >= 0) && (*index_ctx <= RLE_MAX_FRAG_ID));

	rle_ctx = &_this->rle_ctx_man[*index_ctx];
	rle_ctx->current_counter += ppdu_length;
	rasm_buf = (rle_rasm_buf_t *)_this->rle_ctx_man[*index_ctx].buff;

	rle_ctx_incr_counter_bytes_in(rle_ctx, ppdu_length);

	if (is_context_free(_this, *index_ctx) == true) {
		PRINT_RLE_ERROR("invalid End on context free, frag id [%d].", *index_ctx);
		/* Context is free, whereas it must not. an error must have occured. */
		/* Freeing context and updating stats. At least one packet is partialy lost.*/
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_lost(rle_ctx, 1);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, rle_ctx->current_counter);
		rle_receiver_free_context(_this, *index_ctx);

		goto out;
	}

	cont_end_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment,
	                                     &alpdu_fragment_len);

	if (rle_ctx_get_use_crc(rle_ctx)) {
		trailer_alpdu_crc_extract_sdu_fragment(
		        alpdu_fragment, alpdu_fragment_len, &sdu_fragment,
		        &sdu_fragment_len,
		        (const rle_alpdu_crc_trailer_t **)&
		        rle_trailer);
	} else {
		trailer_alpdu_seqno_extract_sdu_fragment(
		        alpdu_fragment, alpdu_fragment_len, &sdu_fragment, &sdu_fragment_len,
		        (const rle_alpdu_seqno_trailer_t **const)&rle_trailer);
	}

	if (sdu_fragment_len > rasm_buf_get_sdu_length(rasm_buf)) {
		PRINT_RLE_ERROR("PPDU END with frag id %d contains more SDU bytes than "
		                "expected in total (%zu bytes in fragment, %zu bytes "
		                "expected in total)", *index_ctx, sdu_fragment_len,
		                rasm_buf_get_sdu_length(rasm_buf));
		goto out;
	}
	rasm_buf_init_sdu_frag(rasm_buf);
	rasm_buf_sdu_frag_put(rasm_buf, sdu_fragment_len);
	rasm_buf_cpy_sdu_frag(rasm_buf, sdu_fragment);

	if (check_alpdu_trailer(rle_trailer, rasm_buf, rle_ctx, &lost_packets) != 0) {
		PRINT_RLE_ERROR("Wrong RLE trailer.");
		goto out;
	}

	reassembled_sdu->size = rasm_buf->sdu_info.size;
	memcpy((void *)reassembled_sdu->buffer, (const void *)rasm_buf->buffer,
	       rasm_buf_get_sdu_length(rasm_buf));

	if (rasm_buf_get_sdu_length(rasm_buf) > rasm_buf_get_reassembled_sdu_length(rasm_buf)) {
		PRINT_RLE_ERROR("End packet received while %zu octets still missing.",
		                rasm_buf_get_sdu_length(
		                        rasm_buf) - rasm_buf_get_reassembled_sdu_length(rasm_buf));
		PRINT_RLE_ERROR("%zu %zu.",
		                rasm_buf_get_sdu_length(
		                        rasm_buf), rasm_buf_get_reassembled_sdu_length(rasm_buf));
	}

	reassembled_sdu->protocol_type = rasm_buf->sdu_info.protocol_type;
	reassembled_sdu->size = rasm_buf_get_sdu_length(rasm_buf);
	memcpy(reassembled_sdu->buffer, rasm_buf->sdu_info.buffer, reassembled_sdu->size);

	/* update link status */
	rle_ctx_incr_counter_bytes_ok(rle_ctx, reassembled_sdu->size);
	rle_ctx_incr_counter_ok(rle_ctx);

	ret = C_REASSEMBLY_OK;

out:

	if ((ret != C_REASSEMBLY_OK) && rle_ctx) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_lost(rle_ctx, lost_packets);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, rle_ctx->current_counter);
	}

	rle_receiver_free_context(_this, *index_ctx);

#ifdef TIME_DEBUG
	gettimeofday(&tv_end, NULL);
	tv_delta.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
	tv_delta.tv_usec = tv_end.tv_usec - tv_start.tv_usec;
	PRINT_RLE_DEBUG("duration [%04ld.%06ld].", MODULE_NAME, tv_delta.tv_sec, tv_delta.tv_usec);
#endif

	return ret;
}

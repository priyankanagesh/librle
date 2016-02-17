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
                         const size_t ppdu_length, struct rle_sdu *const reassembled_sdu)
{
	int ret = C_ERROR;
	struct rle_configuration *rle_conf;
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

	rle_conf = _this->rle_conf_ctxtless;

	comp_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment, &alpdu_fragment_len);

	if (alpdu_fragment_len == 0) {
		PRINT_RLE_ERROR("Error: No ALPDU in Complete PPDU.");
		goto out;
	}

	if (rle_comp_ppdu_header_get_is_signal(header)) {
		ret = signal_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                        &protocol_type, &sdu_fragment, &sdu_fragment_len);
	} else if (rle_comp_ppdu_header_get_is_suppressed(header)) {
		ret = suppressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len, &protocol_type,
		                                            &sdu_fragment, &sdu_fragment_len, rle_conf);
	} else if (rle_conf_get_ptype_compression(rle_conf)) {
		ret = compressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len, &protocol_type,
		                                            &sdu_fragment, &sdu_fragment_len, NULL);
	} else {
		ret = uncompressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                            &protocol_type, &sdu_fragment, &sdu_fragment_len);
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
                          const size_t ppdu_length, int *const index_ctx)
{
	int ret = C_ERROR;
	struct rle_configuration *rle_conf;
	const unsigned char *alpdu_fragment;
	size_t alpdu_fragment_len;
	const unsigned char *sdu_fragment;
	size_t sdu_fragment_len;
	uint16_t protocol_type;
	rle_r_buff_t *r_buff;
	size_t alpdu_total_len;
	const rle_ppdu_header_start_t *header;
	struct rle_ctx_management *rle_ctx = NULL;
	size_t sdu_total_len;
	int is_crc_used;

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
	if ((*index_ctx < 0) || (*index_ctx > RLE_MAX_FRAG_ID)) {
		PRINT_RLE_ERROR("invalid fragment id [%d].", *index_ctx);
		goto out;
	}

	rle_ctx = &_this->rle_ctx_man[*index_ctx];
	rle_ctx->current_counter = ppdu_length;
	r_buff = (rle_r_buff_t *)_this->rle_ctx_man[*index_ctx].buff;

	rle_ctx_incr_counter_in(rle_ctx);
	rle_ctx_incr_counter_bytes_in(rle_ctx, ppdu_length);

	if (is_context_free(_this, *index_ctx) == C_FALSE) {
		PRINT_RLE_ERROR("invalid Start on context not free, frag id [%d].", *index_ctx);
		/* Context is not free, whereas it must be. an error must have occured. */
		/* Freeing context, updating stats, and restarting receiving. */
		goto out;
	}

	set_nonfree_frag_ctx(_this, *index_ctx);

	start_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment, &alpdu_fragment_len,
	                                  &alpdu_total_len, &is_crc_used);
	header = (const rle_ppdu_header_start_t *)ppdu;
	rle_conf = _this->rle_conf[*index_ctx];

	sdu_total_len = alpdu_total_len;

	if (rle_start_ppdu_header_get_is_signal(header)) {
		ret = signal_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len, &protocol_type,
		                                        &sdu_fragment, &sdu_fragment_len);
	} else if (rle_start_ppdu_header_get_is_suppressed(header)) {
		ret = suppressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len, &protocol_type,
		                                            &sdu_fragment, &sdu_fragment_len, rle_conf);
	} else if (rle_conf_get_ptype_compression(rle_conf)) {
		ret = compressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len, &protocol_type,
		                                            &sdu_fragment, &sdu_fragment_len, &sdu_total_len);
	} else {
		sdu_total_len -= sizeof(rle_alpdu_header_uncompressed_t);
		ret = uncompressed_alpdu_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len,
		                                              &protocol_type, &sdu_fragment, &sdu_fragment_len);
	}

	if (ret) {
		ret = C_ERROR;
		goto out;
	}

	if (is_crc_used) {
		sdu_total_len -= sizeof(rle_alpdu_crc_trailer_t);
	} else {
		sdu_total_len -= sizeof(rle_alpdu_seqno_trailer_t);
	}

	rle_ctx_set_use_crc(rle_ctx, is_crc_used);

	if (r_buff_init(r_buff) != 0) {
		PRINT_RLE_ERROR("Unable to init reassembly buffer.");
		goto out;
	}

	if (r_buff_sdu_put(r_buff, sdu_total_len) != 0) {
		PRINT_RLE_ERROR("Unable to reserve %zu-octets for SDU.", sdu_total_len);
		goto out;
	}

	if (r_buff_sdu_frag_put(r_buff, sdu_fragment_len) != 0) {
		PRINT_RLE_ERROR("Unable to reserve %zu-octets for SDU fragment.", sdu_fragment_len);
		goto out;
	}

	r_buff->sdu_info.protocol_type = protocol_type;
	r_buff->sdu_info.size = sdu_total_len;
	r_buff_cpy_sdu_frag(r_buff, sdu_fragment);

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
                          const size_t ppdu_length, int *const index_ctx)
{
	int ret = C_ERROR;
	const unsigned char *alpdu_fragment;
	size_t alpdu_fragment_len;
	const unsigned char *sdu_fragment;
	size_t sdu_fragment_len;
	rle_r_buff_t *r_buff;
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
	if ((*index_ctx < 0) || (*index_ctx > RLE_MAX_FRAG_ID)) {
		PRINT_RLE_ERROR("invalid fragment id [%d].", *index_ctx);
		goto out;
	}

	rle_ctx = &_this->rle_ctx_man[*index_ctx];
	rle_ctx->current_counter += ppdu_length;
	r_buff = (rle_r_buff_t *)_this->rle_ctx_man[*index_ctx].buff;

	rle_ctx_incr_counter_bytes_in(rle_ctx, ppdu_length);

	if (is_context_free(_this, *index_ctx) == C_TRUE) {
		PRINT_RLE_ERROR("invalid Cont on context free, frag id [%d].", *index_ctx);
		/* Context is free, whereas it must not. an error must have occured. */
		/* Freeing context and updating stats. At least one packet is partialy lost.*/
		goto out;
	}

	cont_end_ppdu_extract_alpdu_fragment(ppdu, ppdu_length, &alpdu_fragment, &alpdu_fragment_len);

	sdu_fragment = alpdu_fragment;
	sdu_fragment_len = alpdu_fragment_len;

	if (r_buff_init_sdu_frag(r_buff) != 0) {
		PRINT_RLE_ERROR("Unable to init new SDU fragment.");
		goto out;
	}

	if (r_buff_sdu_frag_put(r_buff, sdu_fragment_len) != 0) {
		PRINT_RLE_ERROR("Unable to reserve %zu-octets for SDU fragment.", sdu_fragment_len);
		goto out;
	}

	r_buff_cpy_sdu_frag(r_buff, sdu_fragment);

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
	rle_r_buff_t *r_buff;
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
	if ((*index_ctx < 0) || (*index_ctx > RLE_MAX_FRAG_ID)) {
		PRINT_RLE_ERROR("invalid fragment id [%d].", *index_ctx);
		goto out;
	}

	rle_ctx = &_this->rle_ctx_man[*index_ctx];
	rle_ctx->current_counter += ppdu_length;
	r_buff = (rle_r_buff_t *)_this->rle_ctx_man[*index_ctx].buff;

	rle_ctx_incr_counter_bytes_in(rle_ctx, ppdu_length);

	if (is_context_free(_this, *index_ctx) == C_TRUE) {
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
		trailer_alpdu_crc_extract_sdu_fragment(alpdu_fragment, alpdu_fragment_len, &sdu_fragment,
		                                       &sdu_fragment_len,
		                                       (const rle_alpdu_crc_trailer_t **)&rle_trailer);
	} else {
		trailer_alpdu_seqno_extract_sdu_fragment(
		        alpdu_fragment, alpdu_fragment_len, &sdu_fragment, &sdu_fragment_len,
		        (const rle_alpdu_seqno_trailer_t ** const)&rle_trailer);
	}

	if (r_buff_init_sdu_frag(r_buff) != 0) {
		PRINT_RLE_ERROR("Unable to init new SDU fragment.");
		goto out;
	}

	if (r_buff_sdu_frag_put(r_buff, sdu_fragment_len) != 0) {
		PRINT_RLE_ERROR("Unable to reserve %zu-octets for SDU fragment.", sdu_fragment_len);
		rle_ctx_incr_counter_dropped(rle_ctx);
		rle_ctx_incr_counter_lost(rle_ctx, 1);
		rle_ctx_incr_counter_bytes_dropped(rle_ctx, rle_ctx->current_counter);
		rle_receiver_free_context(_this, *index_ctx);
		goto out;
	}

	r_buff_cpy_sdu_frag(r_buff, sdu_fragment);

	if (check_alpdu_trailer(rle_trailer, r_buff, rle_ctx, &lost_packets) != 0) {
		PRINT_RLE_ERROR("Wrong RLE trailer.");
		goto out;
	}

	reassembled_sdu->size = r_buff->sdu_info.size;
	memcpy((void *)reassembled_sdu->buffer, (const void *)r_buff->buffer,
	       r_buff_get_sdu_length(r_buff));

	if (r_buff_get_sdu_length(r_buff) > r_buff_get_reassembled_sdu_length(r_buff)) {
		PRINT_RLE_ERROR("End packet received while %zu octets still missing.",
		                r_buff_get_sdu_length(r_buff) - r_buff_get_reassembled_sdu_length(r_buff));
		PRINT_RLE_ERROR("%zu %zu.",
		r_buff_get_sdu_length(r_buff), r_buff_get_reassembled_sdu_length(r_buff));
	}

	reassembled_sdu->protocol_type = r_buff->sdu_info.protocol_type;
	reassembled_sdu->size = r_buff_get_sdu_length(r_buff);
	memcpy(reassembled_sdu->buffer, r_buff->sdu_info.buffer, reassembled_sdu->size);

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

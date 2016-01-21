/**
 * @file   fragmentation.c
 * @brief  RLE fragmentation functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdio.h>
#include <string.h>

#else

#include <linux/stddef.h>
#include <linux/types.h>

#endif

#include "rle.h"
#include "rle_transmitter.h"
#include "header.h"
#include "fragmentation.h"
#include "constants.h"
#include "rle_ctx.h"
#include "zc_buffer.h"
#include "crc.h"
#include "rle_header_proto_type_field.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "FRAGMENTATION"


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PRIVATE FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static uint32_t compute_crc32(struct rle_ctx_management *rle_ctx)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p\n", MODULE_NAME, __FILE__, __func__, __LINE__,
	      rle_ctx);
#endif
	/* CRC must be computed on PDU data and the
	 * original two bytes protocol type field
	 * whatever it is suppressed or compressed */
	uint32_t crc32 = 0;
	uint16_t field_value = 0;
	size_t length = 0;

	/* first compute proto_type CRC */
	field_value = (rle_ctx_get_proto_type(rle_ctx));
	crc32 = compute_crc((unsigned char *)&field_value,
	                    RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP, RLE_CRC_INIT);

	/* compute PDU CRC */
	length = rle_ctx_get_pdu_length(rle_ctx);
	crc32 = compute_crc((unsigned char *)rle_ctx->pdu_buf, length, crc32);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: with PDU length %zu & protocol type 0x%x CRC %x\n",
	      MODULE_NAME, __FILE__, __func__, __LINE__, length, field_value, crc32);
#endif

	return crc32;
}

static void add_trailer(struct rle_ctx_management *rle_ctx,
                        struct rle_configuration *rle_conf __attribute__ (
                                (unused)), void *burst_payload_buffer,
                        size_t burst_payload_length __attribute__ ((unused)))
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:i RLE ctx-> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu\n", MODULE_NAME, __FILE__, __func__, __LINE__, rle_ctx, rle_conf,
	      burst_payload_buffer, burst_payload_length);
#endif

	/* retrieve address beyond
	 * the last end addr pointer
	 * to map a trailer */
	struct zc_rle_trailer *rle_trl =
	        (struct zc_rle_trailer *)rle_ctx_get_end_address(rle_ctx);
	char *buf_last_addr = rle_ctx_get_end_address(rle_ctx);

	if (!rle_ctx->use_crc) {
		uint8_t seq_no = rle_ctx_get_seq_nb(rle_ctx);

		/* fill next seq number field */
		rle_trl->trailer.b.seq_no = seq_no;

		rle_ctx_set_end_address(rle_ctx,
		                        (char *)(buf_last_addr + RLE_SEQ_NO_FIELD_SIZE));

		/* copy trailer to burst payload */
		memcpy(burst_payload_buffer, &seq_no, RLE_SEQ_NO_FIELD_SIZE);

		rle_ctx_decr_remaining_alpdu_length(rle_ctx, RLE_SEQ_NO_FIELD_SIZE);

		rle_ctx_incr_seq_nb(rle_ctx);
	} else {
		/* crc32 is computed by using protocol type
		 * and the PDU */
		rle_trl->trailer.crc = compute_crc32(rle_ctx);

		rle_ctx_set_end_address(rle_ctx,
		                        (char *)(buf_last_addr + RLE_CRC32_FIELD_SIZE));

		/* copy trailer to burst payload */
		memcpy(burst_payload_buffer, &rle_trl->trailer.crc, RLE_CRC32_FIELD_SIZE);

		rle_ctx_decr_remaining_alpdu_length(rle_ctx, RLE_CRC32_FIELD_SIZE);
	}
}

static int add_start_header(struct rle_ctx_management *rle_ctx, struct rle_configuration *rle_conf,
                            void *burst_payload_buffer, size_t burst_payload_length,
                            uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu, protocol type = %04x\n", MODULE_NAME, __FILE__, __func__, __LINE__, rle_ctx,
	      rle_conf, burst_payload_buffer, burst_payload_length, protocol_type);
#endif

	const size_t size_ppdu_header = RLE_START_MANDATORY_HEADER_SIZE;
	size_t size_alpdu_ppdu_header = 0;
	size_t ptype_length = 0;
	uint8_t proto_type_supp = RLE_T_PROTO_TYPE_NO_SUPP;
	uint8_t frag_id = 0;
	size_t offset_payload = 0;
	size_t trailer_size = 0;
	struct rle_header_start_w_ptype *RLE_HEADER = NULL;

	/* map RLE header to the already allocated buffer */
	struct zc_rle_header_start_w_ptype *rle_s_hdr =
	        (struct zc_rle_header_start_w_ptype *)rle_ctx->buf;

	rle_s_hdr->ptrs.start = NULL;
	rle_s_hdr->ptrs.end = NULL;

	/* don't fill ptype field if given ptype
	 * is equal to the default one and suppression is active,
	 * or if given ptype is for signalling packet */
	if (!ptype_is_omissible(protocol_type, rle_conf)) {
		/* remap a complete header with ptype field */
		struct rle_header_start_w_ptype *rle_sp_hdr =
		        (struct rle_header_start_w_ptype *)&rle_s_hdr->header;

		if (rle_conf_get_ptype_compression(rle_conf)) {
			ptype_length = RLE_PROTO_TYPE_FIELD_SIZE_COMP;
			if (rle_header_ptype_is_compressible(protocol_type) == C_OK) {
				rle_sp_hdr->ptype_c_s.c.proto_type = rle_header_ptype_compression(
				        protocol_type);
			} else {
				rle_sp_hdr->ptype_c_s.e.proto_type = 0xFF;
				rle_sp_hdr->ptype_c_s.e.proto_type_uncompressed = ntohs(
				        protocol_type);
				ptype_length += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
			}
		} else {
			rle_sp_hdr->ptype_u_s.proto_type = ntohs(protocol_type);
			ptype_length = RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
		}

	} else {
		/* no protocol type in this packet */
		proto_type_supp = RLE_T_PROTO_TYPE_SUPP;
	}
	size_alpdu_ppdu_header = size_ppdu_header + ptype_length;
	rle_ctx_set_proto_type(rle_ctx, protocol_type);

	/* Robustness: test if available burst payload is smaller
	 * than an RLE START packet header */
	if (burst_payload_length < size_alpdu_ppdu_header) {
		/* Silently return the ERROR to the interface. */
		int ret_ch = C_ERROR;

		void *const data_buffer = rle_ctx->pdu_buf;
		const size_t data_length = rle_ctx->pdu_length;

		ret_ch = create_header(rle_ctx, rle_conf, data_buffer, data_length, protocol_type);

		if (ret_ch != C_ERROR) {
			ret_ch = C_ERROR_FRAG_SIZE;
		}

		return ret_ch;
	}

	/* fill RLE start header */
	rle_s_hdr->header.head.b.start_ind = 1;
	rle_s_hdr->header.head.b.end_ind = 0;
	/* RLE packet length is the sum of packet label, protocol type & data length */
	rle_header_all_set_packet_length(&(rle_s_hdr->header.head),
	                                 (burst_payload_length - RLE_START_MANDATORY_HEADER_SIZE));
	frag_id = rle_ctx_get_frag_id(rle_ctx);
	SET_FRAG_ID(rle_s_hdr->header.head.b.LT_T_FID, frag_id);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: Set ptype %zu proto_type suppressed %d\n",
	      MODULE_NAME, __FILE__, __func__, __LINE__, ptype_length, proto_type_supp);
#endif

	/* fill label_type field accordingly to the
	 * given protocol type (signal or implicit/indicated
	 * by the NCC */
	if (protocol_type == RLE_PROTO_TYPE_SIGNAL_UNCOMP) {
		/* RCS2 requirement */
		rle_s_hdr->header.head_start.b.label_type = RLE_LT_PROTO_SIGNAL;
	} else if (proto_type_supp == RLE_T_PROTO_TYPE_SUPP) {
		rle_s_hdr->header.head_start.b.label_type = RLE_LT_IMPLICIT_PROTO_TYPE;
	} else {
		rle_s_hdr->header.head_start.b.label_type = RLE_T_PROTO_TYPE_NO_SUPP;
	}

	rle_s_hdr->header.head_start.b.proto_type_supp = proto_type_supp;

	/* set start & end PDU data pointers */
	offset_payload = burst_payload_length - size_alpdu_ppdu_header;
	rle_s_hdr->ptrs.start = (char *)rle_ctx->pdu_buf;
	rle_s_hdr->ptrs.end = (char *)((char *)rle_ctx->pdu_buf + offset_payload);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: ptrs.start 0x%p ptrs.end 0x%p\n",
	      MODULE_NAME, __FILE__, __func__, __LINE__, rle_s_hdr->ptrs.start,
	      rle_s_hdr->ptrs.end);
#endif

	/* update rle context :
	 * zero copy last used address is the sum of
	 * end address + size of 1 end @ pointer */
	rle_ctx_set_end_address(rle_ctx,
	                        (char *)(&(rle_s_hdr->ptrs.end) + 1));

	rle_ctx_set_is_fragmented(rle_ctx, C_TRUE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_nb_frag_pdu(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, rle_conf_get_crc_check(rle_conf));
	rle_ctx_set_remaining_pdu_length(rle_ctx,
	                                 (rle_ctx_get_pdu_length(rle_ctx) - offset_payload));
	rle_ctx_set_rle_length(rle_ctx,
	                       (burst_payload_length - ptype_length), ptype_length);
	trailer_size = 0;

	if (rle_conf_get_crc_check(rle_conf) == C_TRUE) {
		trailer_size += RLE_CRC32_FIELD_SIZE;
		rle_s_hdr->header.head_start.b.use_crc = 1;
	} else {
		trailer_size += RLE_SEQ_NO_FIELD_SIZE;
		rle_s_hdr->header.head_start.b.use_crc = 0;
	}
	rle_ctx_incr_alpdu_length(rle_ctx, trailer_size);
	rle_ctx_set_remaining_alpdu_length(rle_ctx, rle_ctx_get_alpdu_length(rle_ctx));

	rle_ctx_decr_remaining_alpdu_length(rle_ctx, burst_payload_length - size_ppdu_header);

	/* RLE total length is the sum of packet label, protocol type & PDU length */
	rle_header_start_set_packet_length(&(rle_s_hdr->header.head_start),
	                                   rle_ctx_get_alpdu_length(rle_ctx));

	rle_ctx_set_qos_tag(rle_ctx, 0); /* TODO */

	/* Copy this fragment to burst payload:
	 * first copy RLE header
	 * second copy PDU region */
	RLE_HEADER = &(rle_s_hdr->header);
	memcpy(burst_payload_buffer, RLE_HEADER, size_alpdu_ppdu_header);
	memcpy((void *)((char *)burst_payload_buffer + size_alpdu_ppdu_header),
	       rle_s_hdr->ptrs.start, offset_payload);

	return C_OK;
}

static int add_cont_end_header(struct rle_ctx_management *rle_ctx,
                               struct rle_configuration *rle_conf, void *burst_payload_buffer,
                               size_t burst_payload_length,
                               int type_rle_frag, uint16_t protocol_type __attribute__ (
                                       (unused)))
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu, type frag = %d, protocol type = 0x%04x\n", MODULE_NAME, __FILE__, __func__,
	      __LINE__, rle_ctx, rle_conf, burst_payload_buffer, burst_payload_length, type_rle_frag,
	      protocol_type);
#endif
	struct zc_rle_header_cont_end *rle_c_e_hdr = NULL;
	size_t trailer_size = 0;
	uint8_t frag_id = 0;
	size_t offset_new_fragment = 0;
	size_t pdu_size_payload = 0;
	int new_remaining_val = 0;

	/* Robustness: test if available burst payload is smaller
	 * than an RLE CONT or END packet header */
	if ((type_rle_frag == RLE_PDU_CONT_FRAG) &&
	    (burst_payload_length - RLE_CONT_HEADER_SIZE) <= 0) {
		/* Silently return the error to the interface. */
		return C_ERROR_FRAG_SIZE;
	}

	/* map RLE header to the already allocated buffer */
	rle_c_e_hdr = (struct zc_rle_header_cont_end *)((void *)rle_ctx_get_end_address(rle_ctx));

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: new fragment start @ 0x%p\n",
	      MODULE_NAME, __FILE__, __func__, __LINE__, rle_c_e_hdr);
#endif

	/* fill RLE continuation or end header (same size) */
	rle_c_e_hdr->header.head.b.start_ind = 0;

	if (type_rle_frag == RLE_PDU_END_FRAG) {
		rle_c_e_hdr->header.head.b.end_ind = 1;
	} else {
		rle_c_e_hdr->header.head.b.end_ind = 0;
	}

	trailer_size = 0;

	if (type_rle_frag == RLE_PDU_END_FRAG) {
		if (rle_conf_get_crc_check(rle_conf) == C_TRUE) {
			trailer_size += RLE_CRC32_FIELD_SIZE;
		} else {
			trailer_size += RLE_SEQ_NO_FIELD_SIZE;
		}
	}

	rle_header_all_set_packet_length(&(rle_c_e_hdr->header.head),
	                                 burst_payload_length - RLE_CONT_HEADER_SIZE);

	frag_id = rle_ctx_get_frag_id(rle_ctx);
	SET_FRAG_ID(rle_c_e_hdr->header.head.b.LT_T_FID, frag_id);

	/* set start & end PDU data pointers to new fragment data region */
	offset_new_fragment = rle_ctx_get_pdu_length(rle_ctx) - rle_ctx_get_remaining_pdu_length(
	        rle_ctx);
	pdu_size_payload = burst_payload_length - (RLE_CONT_HEADER_SIZE + trailer_size);

	rle_c_e_hdr->ptrs.start = (char *)((char *)rle_ctx->pdu_buf + offset_new_fragment);
	rle_c_e_hdr->ptrs.end =
	        (char *)((char *)rle_ctx->pdu_buf + offset_new_fragment + pdu_size_payload);

	/* update rle context */
	rle_ctx_set_end_address(rle_ctx,
	                        (char *)(&(rle_c_e_hdr->ptrs.end) + 1));

	/* increment queue fragment counter and
	 * nb of fragments for this PDU */
	rle_ctx_incr_frag_counter(rle_ctx);
	rle_ctx_incr_nb_frag_pdu(rle_ctx);

	/* if we are building a END packet,
	 * remaining PDU data size must be equal
	 * to zero */
	new_remaining_val = rle_ctx_get_remaining_pdu_length(rle_ctx) - pdu_size_payload;
	if (((type_rle_frag == RLE_PDU_END_FRAG) && (new_remaining_val > 0)) ||
	    (new_remaining_val < 0)) {
		PRINT("ERROR %s %s:%s:%d: Invalid remaining data size"
		      " while building an RLE END packet [%d]\n",
		      MODULE_NAME, __FILE__, __func__, __LINE__, new_remaining_val);
		return C_ERROR;
	}

	rle_ctx_set_remaining_pdu_length(rle_ctx, new_remaining_val);
	rle_ctx_decr_remaining_alpdu_length(rle_ctx, pdu_size_payload);
	rle_ctx_set_rle_length(rle_ctx,
	                       (burst_payload_length - (RLE_CONT_HEADER_SIZE)), 0);

	/* Copy this fragment to burst payload:
	 * first copy RLE header
	 * second copy PDU region */
	memcpy(burst_payload_buffer, rle_c_e_hdr, sizeof(struct rle_header_cont_end));
	memcpy((void *)((char *)burst_payload_buffer + sizeof(struct rle_header_cont_end)),
	       rle_c_e_hdr->ptrs.start, pdu_size_payload);

	if (type_rle_frag == RLE_PDU_END_FRAG) {
		add_trailer(rle_ctx,
		            rle_conf,
		            ((char *)burst_payload_buffer +
		             sizeof(struct rle_header_cont_end) +
		             pdu_size_payload),
		            burst_payload_length);

		/* Last fragment of a PDU
		 * is being sent so increment status link
		 * successfully sent packet counter */
		rle_ctx_incr_counter_ok(rle_ctx);
	}

	return C_OK;
}

static int get_fragment_type_from_ctx(struct rle_ctx_management *rle_ctx,
                                      size_t burst_payload_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, burst len = %zu\n", MODULE_NAME, __FILE__,
	      __func__, __LINE__, rle_ctx, burst_payload_length);
#endif

	int frag_type = RLE_PDU_START_FRAG;
	size_t remaining_alpdu_len = rle_ctx_get_remaining_alpdu_length(rle_ctx);

	if (rle_ctx_get_is_fragmented(rle_ctx)) {
		/* not all PDU data has been sent, so
		 * it's a CONT or END packet */
		if ((remaining_alpdu_len + RLE_END_HEADER_SIZE) <=
		    burst_payload_length) {
			frag_type = RLE_PDU_END_FRAG;
		} else {
			frag_type = RLE_PDU_CONT_FRAG;
		}
	}

	return frag_type;
}


/*------------------------------------------------------------------------------------------------*/
/*----------------------------------- PUBLIC FUNCTIONS CODE --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_frag_status rle_fragment(struct rle_transmitter *const transmitter, const uint8_t frag_id,
                                  const size_t remaining_burst_size, unsigned char *const ppdu,
                                  size_t *const ppdu_length)
{
	enum rle_frag_status status = RLE_FRAG_ERR; /* Error by default. */

	size_t min_burst_size = 0;
	int ret = 0;
	size_t remaining_pdu = 0;
	size_t remaining_alpdu = 0;
	size_t burst_size = 0;

	*ppdu_length = 0;

	if (transmitter == NULL) {
		status = RLE_FRAG_ERR_NULL_TRMT;
		goto exit_label;
	}

	min_burst_size = RLE_CONT_HEADER_SIZE;

	remaining_pdu = rle_ctx_get_remaining_pdu_length(&transmitter->rle_ctx_man[frag_id]);
	remaining_alpdu = rle_ctx_get_remaining_alpdu_length(&transmitter->rle_ctx_man[frag_id]);
	burst_size = remaining_burst_size <
	                     RLE_MAX_PPDU_PL_SIZE ? remaining_burst_size : RLE_MAX_PPDU_PL_SIZE;

	if (remaining_alpdu == 0) {
		status = RLE_FRAG_ERR_CONTEXT_IS_NULL;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	if (fragmentation_is_needed(&transmitter->rle_ctx_man[frag_id], remaining_burst_size) &&
		!rle_ctx_get_is_fragmented(&transmitter->rle_ctx_man[frag_id])) {
		min_burst_size = RLE_START_MANDATORY_HEADER_SIZE;
	}

	if (burst_size < min_burst_size) {
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		goto exit_label;
	}

	/*
	 * The further statement checks if the remaining burst size is large enough to send SDU,
	 * but not the ALPDU protection octets. If not, there is no framentation, and an error code is
	 * returned. The user of the library must retry the fragmentation with either:
	 * - a smaller burst size, in order to send partially or fully the ALPDU without its
	 *   protection bytes. Those octets could not be split apart and should be sent together in a
	 *   forthcoming burst.
	 * - a bigger burst size, for the same reason as exposed previously.
	 */
	if ((burst_size > RLE_CONT_HEADER_SIZE + remaining_pdu) &&
	    (burst_size < RLE_CONT_HEADER_SIZE + remaining_alpdu)) {
		burst_size = RLE_CONT_HEADER_SIZE + remaining_pdu;
	}

	if ((remaining_alpdu + RLE_CONT_HEADER_SIZE) < burst_size) {
		*ppdu_length = remaining_alpdu + RLE_CONT_HEADER_SIZE;
	} else {
		*ppdu_length = burst_size;
	}

	ret = rle_transmitter_get_packet(transmitter, ppdu, *ppdu_length, frag_id,
	                                 rle_ctx_get_proto_type(&transmitter->rle_ctx_man[frag_id]));

	if (ret == C_ERROR_FRAG_SIZE) {
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		*ppdu_length = 0;
		goto exit_label;
	}

	remaining_alpdu = rle_ctx_get_remaining_alpdu_length(&transmitter->rle_ctx_man[frag_id]);

	if (remaining_alpdu == 0) {
		rle_transmitter_free_context(transmitter, frag_id);
	}

	if (ret == C_OK) {
		status = RLE_FRAG_OK;
	}

exit_label:
	return status;
}

int fragmentation_copy_complete_frag(struct rle_ctx_management *rle_ctx,
                                     struct rle_configuration *rle_conf __attribute__ (
                                             (unused)), void *burst_payload_buffer __attribute__ (
                                             (unused)), size_t burst_payload_length __attribute__ (
                                             (unused)))
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu\n", MODULE_NAME, __FILE__, __func__, __LINE__, rle_ctx, rle_conf,
	      burst_payload_buffer, burst_payload_length);
#endif
	struct zc_rle_header_complete_w_ptype *zc_buf =
	        (struct zc_rle_header_complete_w_ptype *)rle_ctx->buf;
	const size_t size_ppdu_header = RLE_COMPLETE_HEADER_SIZE;
	const size_t pdu_length = rle_ctx_get_pdu_length(rle_ctx);
	const size_t data_length = rle_ctx_get_rle_length(rle_ctx);
	const size_t ptype_length = data_length - pdu_length;
	const size_t size_alpdu_ppdu_header = size_ppdu_header + ptype_length;
	uint8_t proto_type_supp = 0;

	rle_header_all_set_packet_length(&(zc_buf->header.head), ptype_length + pdu_length);

	proto_type_supp = GET_PROTO_TYPE_SUPP(zc_buf->header.head.b.LT_T_FID);
	if (proto_type_supp != RLE_T_PROTO_TYPE_SUPP) {
		struct rle_header_complete_w_ptype *rle_cp_hdr =
		        (struct rle_header_complete_w_ptype *)&zc_buf->header;
		/* copy header region */
		memcpy(burst_payload_buffer, rle_cp_hdr, size_alpdu_ppdu_header);
	} else {
		struct rle_header_complete *rle_c_hdr =
		        (struct rle_header_complete *)&zc_buf->header;
		/* copy header region */
		memcpy(burst_payload_buffer, rle_c_hdr, size_alpdu_ppdu_header);
	}

	/* copy PDU */
	memcpy((void *)((char *)burst_payload_buffer + size_alpdu_ppdu_header),
	       zc_buf->ptrs.start, pdu_length);

	/* update some values in RLE context */
	rle_ctx_set_remaining_pdu_length(rle_ctx, 0);
	rle_ctx_set_remaining_alpdu_length(rle_ctx, 0);
	rle_ctx_set_rle_length(rle_ctx,
	                       (pdu_length + ptype_length), ptype_length);

	/* update status value */
	rle_ctx_incr_counter_ok(rle_ctx);
	rle_ctx_incr_counter_bytes_ok(rle_ctx, ptype_length + size_alpdu_ppdu_header);

	return C_OK;
}

int fragmentation_create_frag(struct rle_ctx_management *rle_ctx,
                              struct rle_configuration *rle_conf, void *burst_payload_buffer,
                              size_t burst_payload_length,
                              int frag_type,
                              uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu, frag type = %d, protocol type = 0x%04x\n", MODULE_NAME, __FILE__, __func__,
	      __LINE__, rle_ctx, rle_conf, burst_payload_buffer, burst_payload_length, frag_type,
	      protocol_type);
#endif

	int ret = C_OK;

	if (frag_type == RLE_PDU_START_FRAG) {
		/* clear old RLE header */
		struct zc_rle_header_complete *rle_hdr =
		        (struct zc_rle_header_complete *)rle_ctx->buf;
		memset((void *)rle_hdr, 0, sizeof(struct zc_rle_header_complete));

	}

	ret = fragmentation_add_header(rle_ctx, rle_conf, burst_payload_buffer, burst_payload_length,
	                               frag_type, protocol_type);

	/* If not OK or just a frag size error, return error. */
	if ((ret != C_OK) && (ret != C_ERROR_FRAG_SIZE)) {
		PRINT("ERROR %s %s:%s:%d: PDU fragmentation process failed\n",
		      MODULE_NAME, __FILE__, __func__, __LINE__);
		ret = C_ERROR;
		return ret;
	}

	return ret;
}

int fragmentation_is_needed(struct rle_ctx_management *rle_ctx, size_t burst_payload_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE length = %d, burst length = %zu\n",
	      MODULE_NAME, __FILE__, __func__, __LINE__, rle_ctx, rle_ctx->remaining_pdu_length,
	      burst_payload_length);
#endif
	size_t total_rle_length = RLE_COMPLETE_HEADER_SIZE +
	                          rle_ctx_get_alpdu_length(rle_ctx);

	if (total_rle_length > burst_payload_length) {
		return C_TRUE;
	}

	return C_FALSE;
}

int fragmentation_fragment_pdu(struct rle_ctx_management *rle_ctx,
                               struct rle_configuration *rle_conf, void *burst_payload_buffer,
                               size_t burst_payload_length,
                               uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu\n", MODULE_NAME, __FILE__, __func__, __LINE__, rle_ctx, rle_conf,
	      burst_payload_buffer, burst_payload_length, protocol_type);
#endif

	int ret = C_ERROR;
	int frag_type = 0;

	if (!rle_ctx) {
		PRINT("ERROR %s %s:%s:%d: RLE context is NULL\n",
		      MODULE_NAME, __FILE__, __func__, __LINE__);
		goto return_ret;
	}

	if (!rle_ctx_get_is_fragmented(rle_ctx)) {
		if (!fragmentation_is_needed(rle_ctx, burst_payload_length)) {
			/* no frag needed, complete PDU is already RLEified
			 * and can be sent as is */
			ret = fragmentation_copy_complete_frag(rle_ctx,
			                                       rle_conf,
			                                       burst_payload_buffer,
			                                       burst_payload_length);
			goto return_ret;
		}
	}

	frag_type = get_fragment_type_from_ctx(rle_ctx, burst_payload_length);

	if ((frag_type == RLE_PDU_START_FRAG) &&
	    (burst_payload_length < RLE_START_MANDATORY_HEADER_SIZE)) {
		PRINT("ERROR %s %s:%s:%d: Burst payload too small for START fragment\n",
		      MODULE_NAME, __FILE__, __func__, __LINE__);
		rle_ctx_set_is_fragmented(rle_ctx, C_FALSE);
		goto return_ret;
	}

	/* RLE fragment creation */
	ret = fragmentation_create_frag(rle_ctx, rle_conf,
	                                burst_payload_buffer,
	                                burst_payload_length, frag_type,
	                                protocol_type);

return_ret:
	/* update link status */
	if (ret == C_OK) {
		rle_ctx_incr_counter_bytes_ok(rle_ctx,
		                              burst_payload_length);
	}

	return ret;
}

int fragmentation_add_header(struct rle_ctx_management *rle_ctx, struct rle_configuration *rle_conf,
                             void *burst_payload_buffer, size_t burst_payload_length,
                             int type_rle_frag,
                             uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE ctx -> 0x%p, RLE conf -> 0x%p, burst buffer -> 0x%p, burst len = "
	      "%zu, type frag = %d, protocol type = 0x%04x\n", MODULE_NAME, __FILE__, __func__,
	      __LINE__, rle_ctx, rle_conf, burst_payload_buffer, burst_payload_length, type_rle_frag,
	      protocol_type);
#endif
	int ret = C_ERROR;

	switch (type_rle_frag) {
	case RLE_PDU_START_FRAG:
		ret = add_start_header(rle_ctx, rle_conf,
		                       burst_payload_buffer,
		                       burst_payload_length, protocol_type);
		break;
	case RLE_PDU_CONT_FRAG:
	case RLE_PDU_END_FRAG:
		ret = add_cont_end_header(rle_ctx, rle_conf,
		                          burst_payload_buffer,
		                          burst_payload_length, type_rle_frag,
		                          protocol_type);
		break;
	default:
		PRINT("ERROR %s %s:%s:%d: RLE fragment type unknown [%d]\n",
		      MODULE_NAME, __FILE__, __func__, __LINE__, type_rle_frag);
		break;
	}

	return ret;
}

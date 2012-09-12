/**
 * @file   fragmentation.c
 * @author Aurelien Castanie
 *
 * @brief  RLE fragmentation functions
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include "fragmentation.h"
#include "constants.h"
#include "rle_ctx.h"
#include "zc_buffer.h"
#include "crc.h"

#define MODULE_NAME "FRAGMENTATION"

static int is_complete_pdu(struct rle_ctx_management *rle_ctx)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	return rle_ctx->is_fragmented;
}

static uint32_t compute_crc32(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
			__FILE__, __func__, __LINE__);
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

	return crc32;
}

static void add_trailer(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer,
		size_t burst_payload_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	/* retrieve address beyond
	 * the last end addr pointer
	 * to map a trailer */
	struct zc_rle_trailer *rle_trl =
		(struct zc_rle_trailer *)rle_ctx_get_end_address(rle_ctx);
	char *buf_last_addr = rle_ctx_get_end_address(rle_ctx);

	if (!rle_ctx->use_crc) {
		/* fill next seq number field */
		rle_trl->trailer.b.seq_no = rle_ctx_get_seq_nb(rle_ctx);
		uint8_t seq_no = rle_ctx_get_seq_nb(rle_ctx);

		rle_ctx_set_end_address(rle_ctx,
			(char *)(buf_last_addr + RLE_SEQ_NO_FIELD_SIZE));

		/* copy trailer to burst payload */
		memcpy(burst_payload_buffer, &seq_no, RLE_SEQ_NO_FIELD_SIZE);
	} else {
		/* crc32 is computed by using protocol type
		 * and the PDU */
		rle_trl->trailer.crc = compute_crc32(rle_ctx, rle_conf);

		rle_ctx_set_end_address(rle_ctx,
			(char *)(buf_last_addr  + RLE_CRC32_FIELD_SIZE));

		/* copy trailer to burst payload */
		memcpy(burst_payload_buffer, &rle_trl->trailer.crc, RLE_CRC32_FIELD_SIZE);
	}

	rle_ctx_incr_seq_nb(rle_ctx);
}

static int add_start_header(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length,
		uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n", MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	size_t size_header = RLE_START_MANDATORY_HEADER_SIZE;

	/* Robustness: test if available burst payload is smaller
	 * than an RLE START packet header */
	if ((burst_payload_length - size_header) <= 0) {
		PRINT("ERROR %s %s:%s:%d: Available burst payload size [%zu]"
				" is not enough to carry data\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__,
				burst_payload_length);
		return C_ERROR;
	}

	size_t ptype_length = 0;
	uint8_t proto_type_supp = RLE_T_PROTO_TYPE_NO_SUPP;

	/* map RLE header to the already allocated buffer */
	struct zc_rle_header_start *rle_s_hdr = rle_ctx->buf;
	rle_s_hdr->ptrs.start = NULL;
	rle_s_hdr->ptrs.end = NULL;

	/* don't fill ptype field if given ptype
	 * is equal to the default one
	 * or if given ptype is for signalling packet */
	if ((protocol_type != rle_conf_get_default_ptype(rle_conf)) &&
			((protocol_type != RLE_PROTO_TYPE_SIGNAL_COMP) ||
			 (protocol_type != RLE_PROTO_TYPE_SIGNAL_UNCOMP))) {
		/* remap a complete header with ptype field */
		struct rle_header_start_w_ptype *rle_sp_hdr =
			(struct rle_header_start_w_ptype *)&rle_s_hdr->header;

		if (rle_conf_get_ptype_compression(rle_conf)) {
			rle_sp_hdr->ptype_c_s.proto_type = (uint8_t)protocol_type;
			ptype_length = RLE_PROTO_TYPE_FIELD_SIZE_COMP;
		} else {
			rle_sp_hdr->ptype_u_s.proto_type = protocol_type;
			ptype_length = RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
		}

		size_header += ptype_length;
	} else {
		/* no protocol type in this packet */
		proto_type_supp = RLE_T_PROTO_TYPE_SUPP;
	}

	/* fill RLE start header */
	rle_s_hdr->header.head.b.start_ind		= 1;
	rle_s_hdr->header.head.b.end_ind		= 0;
	/* RLE packet length is the sum of packet label, protocol type & data length */
	rle_s_hdr->header.head.b.rle_packet_length	=
		(burst_payload_length - RLE_START_MANDATORY_HEADER_SIZE);
	uint8_t frag_id	= rle_ctx_get_frag_id(rle_ctx);
	SET_FRAG_ID(rle_s_hdr->header.head.b.LT_T_FID, frag_id);

	/* RLE total length is the sum of packet label, protocol type & PDU length */
	rle_s_hdr->header.head_start.b.total_length	=
		(rle_ctx_get_pdu_length(rle_ctx) + ptype_length);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: Set total length to %d "
			"ptype %zu size_header %zu proto_type suppressed %d\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			rle_s_hdr->header.head_start.b.total_length,
			ptype_length,
			size_header,
			proto_type_supp);
#endif

	/* fill label_type field accordingly to the
	 * given protocol type (signal or implicit/indicated
	 * by the NCC */
	if ((protocol_type == RLE_PROTO_TYPE_SIGNAL_COMP) ||
			(protocol_type == RLE_PROTO_TYPE_SIGNAL_UNCOMP))
		rle_s_hdr->header.head_start.b.label_type = RLE_LT_PROTO_SIGNAL; /* RCS2 requirement */
	else
		rle_s_hdr->header.head_start.b.label_type = RLE_LT_IMPLICIT_PROTO_TYPE;

	rle_s_hdr->header.head_start.b.proto_type_supp = proto_type_supp;

	/* set start & end PDU data pointers */
	size_t offset_payload = burst_payload_length - size_header;
	rle_s_hdr->ptrs.start = (char *)rle_ctx->pdu_buf;
	rle_s_hdr->ptrs.end = (char *)(rle_ctx->pdu_buf + offset_payload);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: ptrs.start %p ptrs.end %p\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			rle_s_hdr->ptrs.start, rle_s_hdr->ptrs.end);
#endif

	/* update rle context :
	 * zero copy last used address is the sum of
	 * end address + size of 1 end @ pointer */
	rle_ctx_set_end_address(rle_ctx,
		(char *)(&(rle_s_hdr->ptrs.end) + 1));

	rle_ctx_set_is_fragmented(rle_ctx, C_TRUE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, rle_conf_get_crc_check(rle_conf));
	rle_ctx_set_remaining_pdu_length(rle_ctx,
			(rle_ctx_get_pdu_length(rle_ctx) - offset_payload));
	rle_ctx_set_rle_length(rle_ctx,
			(burst_payload_length - ptype_length));

	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO

	/* Copy this fragment to burst payload:
	 * first copy RLE header
	 * second copy PDU region */
	struct rle_header_start *RLE_HEADER = &(rle_s_hdr->header);
	memcpy(burst_payload_buffer, RLE_HEADER, size_header);
	memcpy((void*)(burst_payload_buffer + size_header),
			rle_s_hdr->ptrs.start,
			offset_payload);

	return C_OK;
}

static int add_cont_end_header(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer,
		size_t burst_payload_length,
		int type_rle_frag,
		uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	/* Robustness: test if available burst payload is smaller
	 * than an RLE CONT or END packet header */
	if ((burst_payload_length - RLE_CONT_HEADER_SIZE) <= 0) {
		PRINT("ERROR %s:%s:%d: Available burst payload size [%zu]"
				" is not enough to carry data\n",
				__FILE__, __func__, __LINE__,
				burst_payload_length);
		return C_ERROR;
	}

	/* map RLE header to the already allocated buffer */
	struct zc_rle_header_cont_end *rle_c_e_hdr =
		(struct zc_rle_header_cont_end *)rle_ctx_get_end_address(rle_ctx);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: new fragment start @ %p\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			rle_c_e_hdr);
#endif

	/* fill RLE continuation or end header (same size) */
	rle_c_e_hdr->header.head.b.start_ind = 0;

	if (type_rle_frag == RLE_PDU_END_FRAG)
		rle_c_e_hdr->header.head.b.end_ind = 1;
	else
		rle_c_e_hdr->header.head.b.end_ind = 0;

	size_t trailer_size = 0;

	if (type_rle_frag == RLE_PDU_END_FRAG) {
		if (rle_conf_get_crc_check(rle_conf) == C_TRUE)
			trailer_size += RLE_CRC32_FIELD_SIZE;
		else
			trailer_size += RLE_SEQ_NO_FIELD_SIZE;
	}

	rle_c_e_hdr->header.head.b.rle_packet_length =
		(burst_payload_length - (RLE_CONT_HEADER_SIZE + trailer_size));
	uint8_t frag_id	= rle_ctx_get_frag_id(rle_ctx);
	SET_FRAG_ID(rle_c_e_hdr->header.head.b.LT_T_FID, frag_id);

	/* set start & end PDU data pointers to new fragment data region */
	size_t offset_new_fragment =
		rle_ctx_get_pdu_length(rle_ctx) - rle_ctx_get_remaining_pdu_length(rle_ctx);
	size_t pdu_size_payload = burst_payload_length - (RLE_CONT_HEADER_SIZE + trailer_size);

	rle_c_e_hdr->ptrs.start = (char *)(rle_ctx->pdu_buf + offset_new_fragment);
	rle_c_e_hdr->ptrs.end = (char *)(rle_ctx->pdu_buf + offset_new_fragment + pdu_size_payload);

	/* update rle context */
	rle_ctx_set_end_address(rle_ctx,
		(char *)(&(rle_c_e_hdr->ptrs.end) + 1));

	/* increment fragment counter */
	rle_ctx_incr_frag_counter(rle_ctx);

	/* if we are building a END packet,
	 * remaining PDU data size must be equal
	 * to zero */
	int new_remaining_val = 0;
	new_remaining_val =
		rle_ctx_get_remaining_pdu_length(rle_ctx) - pdu_size_payload;
	if ((type_rle_frag == RLE_PDU_END_FRAG) && (new_remaining_val > 0)) {
		PRINT("ERROR %s %s:%s:%d: Invalid remaining data size"
			       " while building an RLE END packet [%d]\n",
			       MODULE_NAME,
				__FILE__, __func__, __LINE__,
				new_remaining_val);
		return C_ERROR;
	}

	if (new_remaining_val < 0)
		new_remaining_val = 0;

	rle_ctx_set_remaining_pdu_length(rle_ctx, new_remaining_val);
	rle_ctx_set_rle_length(rle_ctx,
			(burst_payload_length - (RLE_CONT_HEADER_SIZE + trailer_size)));

	/* Copy this fragment to burst payload:
	 * first copy RLE header
	 * second copy PDU region */
	memcpy(burst_payload_buffer, rle_c_e_hdr, sizeof(struct rle_header_cont_end));
	memcpy((burst_payload_buffer + sizeof(struct rle_header_cont_end)),
			rle_c_e_hdr->ptrs.start, pdu_size_payload);

	if (type_rle_frag == RLE_PDU_END_FRAG) {
		add_trailer(rle_ctx,
			rle_conf,
			(burst_payload_buffer +
			 sizeof(struct rle_header_cont_end) +
			 pdu_size_payload),
			burst_payload_length);
	}


	return C_OK;
}

static int get_fragment_type(struct rle_ctx_management *rle_ctx, size_t burst_payload_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int frag_type = RLE_PDU_START_FRAG;
	uint32_t remaining_pdu_len = rle_ctx_get_remaining_pdu_length(rle_ctx);

	if (is_complete_pdu(rle_ctx)) {
		size_t trailer_size =
			(rle_ctx_get_use_crc(rle_ctx) == C_FALSE) ? RLE_SEQ_NO_FIELD_SIZE : RLE_CRC32_FIELD_SIZE;
		/* not all PDU data has been sent, so
		 * it's a CONT or END packet */
		if ((remaining_pdu_len + RLE_CONT_HEADER_SIZE) > burst_payload_length)
			frag_type = RLE_PDU_CONT_FRAG;
		else if ((remaining_pdu_len + RLE_CONT_HEADER_SIZE + trailer_size) <= burst_payload_length)
			frag_type = RLE_PDU_END_FRAG;
	}

	return frag_type;
}

int fragmentation_create_frag(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length,
		int frag_type, uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int ret = C_OK;

	if (frag_type == RLE_PDU_START_FRAG) {
		/* clear old RLE header */
		struct zc_rle_header_complete *rle_hdr = (struct zc_rle_header_complete *)rle_ctx->buf;
		memset((void *)rle_hdr, 0, sizeof(struct zc_rle_header_complete));
	}

	if (fragmentation_add_header(rle_ctx, rle_conf,
				burst_payload_buffer, burst_payload_length,
				frag_type, protocol_type) != C_OK) {
			PRINT("ERROR %s %s:%s:%d: PDU fragmentation process failed\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__);
			ret = C_ERROR;
			return ret;
	}

	return ret;
}

int fragmentation_is_needed(struct rle_ctx_management *rle_ctx, size_t burst_payload_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE length [%d] burst length [%zu]\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			rle_ctx->remaining_pdu_length,
			burst_payload_length);
#endif

	if (rle_ctx->remaining_pdu_length > burst_payload_length)
		return C_TRUE;

	return C_FALSE;
}

int fragmentation_fragment_pdu(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length,
		uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int ret = C_ERROR;

	if (!rle_ctx) {
		PRINT("ERROR %s %s:%s:%d: RLE context is NULL\n",
				MODULE_NAME,
				 __FILE__, __func__, __LINE__);
		goto return_ret;
	}

	if (!rle_ctx_get_is_fragmented(rle_ctx))
		if (!fragmentation_is_needed(rle_ctx, burst_payload_length)) {
			/* no frag needed, complete PDU is already RLEified
			 * and can be sent as is */
			ret = C_OK;
			goto return_ret;
		}

	int frag_type = get_fragment_type(rle_ctx, burst_payload_length);

	/* RLE fragment creation */
	ret = fragmentation_create_frag(rle_ctx, rle_conf,
			burst_payload_buffer,
			burst_payload_length, frag_type,
			protocol_type);

return_ret:
	return ret;
}

int fragmentation_add_header(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *burst_payload_buffer, size_t burst_payload_length,
		int type_rle_frag, uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
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
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					type_rle_frag);
			break;
	}

	return ret;
}

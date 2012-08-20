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

static int is_complete_pdu(struct rle_ctx_management *rle_ctx)
{
	return rle_ctx->is_fragmented;
}

static int add_start_header(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t burst_payload_length)
{
	/* Robustness: test if available burst payload is smaller
	 * than an RLE START packet header */
	if ((burst_payload_length - RLE_START_HEADER_SIZE) <= 0) {
		PRINT("ERROR %s:%s:%d: Available burst payload size [%zu]"
				" is not enough to carry data\n",
				__FILE__, __func__, __LINE__,
				burst_payload_length);
		return C_ERROR;
	}

	/* map RLE header to the already allocated buffer */
	struct zc_rle_header_start *rle_s_hdr = rle_ctx->buf;
	rle_s_hdr->ptrs.start = NULL;
	rle_s_hdr->ptrs.end = NULL;

	/* fill RLE start header */
	rle_s_hdr->header.head.b.start_ind = 1;
	rle_s_hdr->header.head.b.end_ind = 0;
	/* RLE packet length is the sum of packet label, protocol type & data length */
	rle_s_hdr->header.head.b.rle_packet_length =
		(burst_payload_length - RLE_START_MANDATORY_HEADER_SIZE);
	rle_s_hdr->header.head.b.frag_id = rle_ctx_get_frag_id(rle_ctx);
	rle_s_hdr->header.proto_type = rle_ctx_get_proto_type(rle_ctx);
	/* RLE total length is the sum of packet label, protocol type & PDU length */
	rle_s_hdr->header.head_start.b.total_length =
		(rle_ctx_get_pdu_length(rle_ctx) + RLE_PROTO_TYPE_FIELD_SIZE);
	rle_s_hdr->header.head_start.b.label_type = rle_ctx_get_label_type(rle_ctx);
	rle_s_hdr->header.head_start.b.proto_type_supp = RLE_T_PROTO_TYPE_NO_SUPP;

	/* set start & end PDU data pointers */
	rle_s_hdr->ptrs.start = (int *)data_buffer;
	rle_s_hdr->ptrs.end = (int *)(data_buffer +
			(burst_payload_length - RLE_START_MANDATORY_HEADER_SIZE));

	/* update rle context */
	int *buf_last_addr = rle_ctx_get_end_address(rle_ctx);
	rle_ctx_set_end_address(rle_ctx,
		(int *)(buf_last_addr  + sizeof(struct zc_rle_header_start)));
	rle_ctx_set_is_fragmented(rle_ctx, C_TRUE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, C_FALSE); // TODO  set the good trailer type to use (given by user)
	rle_ctx_set_remaining_pdu_length(rle_ctx,
			(rle_ctx_get_pdu_length(rle_ctx) -
			(burst_payload_length - RLE_START_HEADER_SIZE)));
	rle_ctx_set_rle_length(rle_ctx,
			(burst_payload_length - RLE_PROTO_TYPE_FIELD_SIZE));
	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO

	return C_OK;
}

static int add_cont_end_header(struct rle_ctx_management *rle_ctx,
		void *data_buffer,
		size_t burst_payload_length,
		int type_rle_frag)
{
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

	/* fill RLE continuation or end header (same size) */
	rle_c_e_hdr->header.head.b.start_ind = 0;
	rle_c_e_hdr->header.head.b.end_ind = 0;
	rle_c_e_hdr->header.head.b.rle_packet_length =
		(burst_payload_length - RLE_CONT_HEADER_SIZE);
	rle_c_e_hdr->header.head.b.frag_id = rle_ctx_get_frag_id(rle_ctx);

	/* set start & end PDU data pointers to new fragment data region */
	uint32_t offset_new_fragment =
		rle_ctx_get_pdu_length(rle_ctx) - rle_ctx_get_remaining_pdu_length(rle_ctx);
	rle_c_e_hdr->ptrs.start = (int *)data_buffer + offset_new_fragment;
	rle_c_e_hdr->ptrs.end = (int *)(rle_c_e_hdr->ptrs.start +
		(burst_payload_length - RLE_CONT_HEADER_SIZE));

	/* update rle context */
	int *buf_last_addr = rle_ctx_get_end_address(rle_ctx);
	rle_ctx_set_end_address(rle_ctx,
		(int *)(buf_last_addr  + sizeof(struct zc_rle_header_cont_end)));
	/* increment fragment counter */
	rle_ctx_incr_frag_counter(rle_ctx);

	/* if we are building a END packet,
	 * remaining PDU data size must be equal
	 * to zero */
	int new_remaining_val = 0;
	new_remaining_val =
		rle_ctx_get_remaining_pdu_length(rle_ctx) - (burst_payload_length - RLE_CONT_HEADER_SIZE);
	if ((type_rle_frag == RLE_END_PACKET) && (new_remaining_val != 0)) {
		PRINT("ERROR %s:%s:%d: Invalid remaining data size"
			       " while building an RLE END packet [%d]\n",
				__FILE__, __func__, __LINE__,
				new_remaining_val);
		return C_ERROR;
	}

	rle_ctx_set_remaining_pdu_length(rle_ctx, new_remaining_val);
	rle_ctx_set_rle_length(rle_ctx,
			(burst_payload_length - RLE_CONT_HEADER_SIZE));

	return C_OK;
}

static uint32_t compute_crc32(struct rle_ctx_management *rle_ctx,
		void *data_buffer)
{
	uint32_t crc32 = 0;
	uint16_t field_value = 0;
	size_t length = 0;

	/* first compute proto_type CRC */
	length = RLE_PROTO_TYPE_FIELD_SIZE;
	field_value = (rle_ctx_get_proto_type(rle_ctx));
	crc32 = compute_crc((unsigned char *)&field_value, length, RLE_CRC_INIT);

	/* then compute PDU CRC */
	length = rle_ctx_get_pdu_length(rle_ctx);
	crc32 = compute_crc((unsigned char *)data_buffer, length, crc32);

	return crc32;
}

static void add_trailer(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t burst_payload_length)
{
	/* retrieve address beyond
	 * the last end addr pointer
	 * to map a trailer */
	struct zc_rle_trailer *rle_trl =
		(struct zc_rle_trailer *)rle_ctx_get_end_address(rle_ctx);
	int *buf_last_addr = rle_ctx_get_end_address(rle_ctx);

	if (!rle_ctx->use_crc) {
		/* fill next seq number field */
		rle_ctx_incr_seq_nb(rle_ctx);
		rle_trl->trailer.seq_no = rle_ctx_get_seq_nb(rle_ctx);

		rle_ctx_set_end_address(rle_ctx,
			(int *)(buf_last_addr  + sizeof(unsigned char)));
	} else {
		/* crc32 is computed by using protocol type
		 * and the PDU */
		rle_trl->trailer.crc = compute_crc32(rle_ctx, data_buffer);

		rle_ctx_set_end_address(rle_ctx,
			(int *)(buf_last_addr  + sizeof(uint32_t)));
	}
}

static int get_fragment_type(struct rle_ctx_management *rle_ctx, size_t burst_payload_length)
{
	int frag_type = RLE_START_PACKET;
	uint32_t remaining_pdu_len = rle_ctx_get_remaining_pdu_length(rle_ctx);

	if (is_complete_pdu(rle_ctx)) {
		/* not all PDU data has been sent, so
		 * it's a CONT or END packet */
		if (remaining_pdu_len > burst_payload_length)
			frag_type = RLE_CONT_PACKET;
		else
			frag_type = RLE_END_PACKET;
	}

	return frag_type;
}

int fragmentation_create_frag(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t burst_payload_length, int frag_type)
{
	int ret = C_OK;

	if (frag_type == RLE_START_PACKET) {
		/* clear old RLE header */
		struct zc_rle_header_start *rle_hdr = (struct zc_rle_header_start *)rle_ctx->buf;
		memset((void *)rle_hdr, 0, sizeof(struct zc_rle_header_start));
	}

	if (fragmentation_add_header(rle_ctx, data_buffer, burst_payload_length, frag_type) !=
			C_OK) {
			PRINT("ERROR %s:%s:%d: PDU fragmentation process failed\n",
					__FILE__, __func__, __LINE__);
			ret = C_ERROR;
			return ret;
	}

	if (frag_type == RLE_END_PACKET)
		add_trailer(rle_ctx, data_buffer, burst_payload_length);

	return ret;
}

int fragmentation_is_needed(struct rle_ctx_management *rle_ctx, size_t burst_payload_length)
{
	if (rle_ctx->rle_length > burst_payload_length)
		return C_TRUE;

	return C_FALSE;
}

int fragmentation_fragment_pdu(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t burst_payload_length)
{
	int ret = C_ERROR;

	if (!rle_ctx) {
		PRINT("ERROR %s:%s:%d: RLE context is NULL\n",
				 __FILE__, __func__, __LINE__);
		goto return_ret;
	}

	if (!fragmentation_is_needed(rle_ctx, burst_payload_length)) {
		/* no frag needed, complete PDU is already RLEified
		 * and can be sent as is */
		ret = C_OK;
		goto return_ret;
	}

	int frag_type = get_fragment_type(rle_ctx, burst_payload_length);

	/* RLE fragment creation */
	ret = fragmentation_create_frag(rle_ctx, data_buffer, burst_payload_length, frag_type);

return_ret:
	return ret;
}

int fragmentation_add_header(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t burst_payload_length,
		int type_rle_frag)
{
	int ret = C_ERROR;

	switch (type_rle_frag) {
		case RLE_PDU_START_FRAG:
			ret = add_start_header(rle_ctx, data_buffer, burst_payload_length);
			break;
		case RLE_PDU_CONT_FRAG:
		case RLE_PDU_END_FRAG:
			ret = add_cont_end_header(rle_ctx, data_buffer, burst_payload_length, type_rle_frag);
			break;
		default:
			PRINT("ERROR %s:%s:%d: RLE fragment type unknown [%d]\n",
					__FILE__, __func__, __LINE__, type_rle_frag);
			break;
	}

	return ret;
}

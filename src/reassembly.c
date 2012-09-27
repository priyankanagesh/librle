/**
 * @file   reassembly.c
 * @author Aurelien Castanie
 *
 * @brief  RLE reassembly functions
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include "reassembly.h"
#include "constants.h"
#include "rle_ctx.h"
#include "header.h"
#include "trailer.h"
#include "crc.h"

#define MODULE_NAME "REASSEMBLY"

static int check_complete_length(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length, size_t header_size)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	/* map the complete packet header */
	union rle_header_all *head = (union rle_header_all *)data_buffer;
	/* rle packet length is the sum of proto_type and payload size */
	size_t recv_packet_length = (data_length - header_size);

	if (head->b.rle_packet_length != recv_packet_length) {
		PRINT("ERROR %s %s:%s:%d: invalid packet length,"
				" received size [%d] computed size [%zu] header [%zu]\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__,
				head->b.rle_packet_length,
				recv_packet_length,
				header_size);
		rle_ctx_incr_counter_dropped(rle_ctx);
		return C_ERROR_DROP;
	}

	return C_OK;
}

static int check_fragmented_length(struct rle_ctx_management *rle_ctx,
		size_t data_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int ret = C_OK;
	/* data_length contains header and also trailer length which
	 * must not be taken into account while computing
	 * PDU total length */
	size_t trailer_size = 0;

	if (rle_ctx_get_use_crc(rle_ctx) == C_TRUE)
		trailer_size += RLE_CRC32_FIELD_SIZE;
	else
		trailer_size += RLE_SEQ_NO_FIELD_SIZE;

	size_t recv_pkt_length = (data_length -
			(sizeof(struct rle_header_cont_end) + trailer_size));

	/* for each fragment received, remaining data size is updated,
	 * so if everything is okay remaining size must be equal
	 * to the last rle_packet_length value */
	uint32_t remaining_size = rle_ctx_get_remaining_pdu_length(rle_ctx);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE trailer_size %zu recv_pkt_length %zu remaining_size %d\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			trailer_size, recv_pkt_length,
			remaining_size);
#endif

	if (remaining_size != recv_pkt_length) {
		PRINT("ERROR %s %s:%s:%d: invalid packet length,"
				"total received size [%zu] PDU received size [%zu] awaited PDU size [%d]\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__,
				data_length,
				recv_pkt_length, remaining_size);
		rle_ctx_incr_counter_dropped(rle_ctx);
		ret = C_ERROR_DROP;
	}

	return ret;
}

static int check_fragmented_sequence(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	/* awaited sequence nb must be equal
	 * to the received one.
	 * Trailer addr is buffer addr + offset
	 * offset is equal to the length of received data
	 * - size of seq_no field */
	struct rle_trailer *trl = (struct rle_trailer *)(data_buffer +
			(data_length - RLE_SEQ_NO_FIELD_SIZE));

	if (trl->b.seq_no != rle_ctx->next_seq_nb) {
		PRINT("ERROR %s %s:%s:%d: sequence number inconsistency,"
			       " received [%d] expected [%d]\n",
			       MODULE_NAME,
			       __FILE__, __func__, __LINE__,
			       trl->b.seq_no, rle_ctx->next_seq_nb);
		/* update sequence with received one
		 * and increment it to resynchronize
		 * with sender sequence */
		rle_ctx_set_seq_nb(rle_ctx, trl->b.seq_no);
		rle_ctx_incr_seq_nb(rle_ctx);
		/* we must update lost & dropped packet
		 * counter and */
		rle_ctx_incr_counter_lost(rle_ctx);
		rle_ctx_incr_counter_dropped(rle_ctx);

		return C_ERROR_DROP;
	}

	rle_ctx_incr_seq_nb(rle_ctx);

	return C_OK;
}

static uint32_t compute_crc32(struct rle_ctx_management *rle_ctx)
{
	uint32_t crc32 = 0;
	uint16_t field_value = 0;
	size_t length = 0;

	/* first compute CRC of the header field p_type
	 * whatever it's compressed or suppressed, we must
	 * use the original two bytes ptype */
	field_value = (rle_ctx_get_proto_type(rle_ctx));
	crc32 = compute_crc((unsigned char *)&field_value,
			RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP, RLE_CRC_INIT);

	/* compute PDU CRC */
	length = rle_ctx_get_pdu_length(rle_ctx);
	crc32 = compute_crc((unsigned char *)rle_ctx->buf, length, crc32);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: with PDU length %zu & protocol type 0x%x CRC %x\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			length, field_value, crc32);
#endif

	return crc32;
}

static int check_fragmented_crc(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	/* We must compute CRC using all PDU data
	 * and the compare it to the received CRC32 value */
	struct rle_trailer *trl = (struct rle_trailer *)(data_buffer +
			(data_length - RLE_CRC32_FIELD_SIZE));

	uint32_t crc = compute_crc32(rle_ctx);

	if (trl->crc != crc) {
		PRINT("ERROR %s %s:%s:%d: CRC error,"
			       " received [%0x] expected [%0x]\n",
			       MODULE_NAME,
			       __FILE__, __func__, __LINE__,
			       trl->crc, crc);
		rle_ctx_incr_counter_dropped(rle_ctx);
		return C_ERROR_DROP;
	}

	return C_OK;
}

static int check_fragmented_consistency(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int ret = check_fragmented_length(rle_ctx, data_length);

	if (ret == C_OK) {
		/* it's OK, no more data remaining
		 * for this PDU */
		rle_ctx_set_remaining_pdu_length(rle_ctx, 0);
		if(!rle_ctx_get_use_crc(rle_ctx)) {
			ret = check_fragmented_sequence(rle_ctx,
					data_buffer, data_length);
		} else {
			ret = check_fragmented_crc(rle_ctx,
					data_buffer, data_length);
		}
	}

	return ret;
}

static size_t get_header_size(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer,
		int frag_type)
{
	size_t header_size = 0;

	switch (frag_type) {
		case RLE_PDU_COMPLETE:
			header_size = RLE_COMPLETE_HEADER_SIZE;
			break;
		case RLE_PDU_START_FRAG:
			header_size = RLE_START_MANDATORY_HEADER_SIZE;
			break;
		case RLE_PDU_CONT_FRAG:
		case RLE_PDU_END_FRAG:
			header_size = RLE_CONT_HEADER_SIZE;
			goto return_hdr_size;
			break;
		default:
			/* it cannot happen */
			goto return_hdr_size;
			break;
	}

	/* get ptype compression status from NCC and
	 * protocol type suppressed field value */
	int is_compressed = rle_conf_get_ptype_compression(rle_conf);
	int is_suppressed = 0xff;

	if (frag_type == RLE_PDU_COMPLETE) {
		struct rle_header_complete *hdr =
		(struct rle_header_complete *)data_buffer;

		is_suppressed = GET_PROTO_TYPE_SUPP(hdr->head.b.LT_T_FID);
	} else {
		struct rle_header_start *hdr =
		(struct rle_header_start *)data_buffer;

		is_suppressed = hdr->head_start.b.proto_type_supp;
	}

	if (is_suppressed != RLE_T_PROTO_TYPE_SUPP) {
		if (is_compressed)
			header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
		else
			header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
	}

return_hdr_size:
	return header_size;
}

static void update_ctx_complete(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer, size_t data_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	struct rle_header_complete *hdr = (struct rle_header_complete *)data_buffer;
	uint16_t protocol_type = 0;
	size_t header_size = RLE_COMPLETE_HEADER_SIZE;
	/* get ptype compression status from NCC */
	int is_compressed = rle_conf_get_ptype_compression(rle_conf);
	uint8_t proto_type_supp = GET_PROTO_TYPE_SUPP(hdr->head.b.LT_T_FID);
	uint8_t label_type = GET_LABEL_TYPE(hdr->head.b.LT_T_FID);

	if ((proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
			(label_type == RLE_LT_IMPLICIT_PROTO_TYPE)) {
		protocol_type = rle_conf_get_default_ptype(rle_conf);
	} else if (label_type == RLE_LT_PROTO_SIGNAL) {
		protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
	}

	if (proto_type_supp != RLE_T_PROTO_TYPE_SUPP) {
		struct rle_header_complete_w_ptype *hdr_pt =
		(struct rle_header_complete_w_ptype *)data_buffer;
		if (is_compressed) {
			protocol_type = hdr_pt->ptype_c_s.proto_type;
			header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
		} else {
			protocol_type = hdr_pt->ptype_u_s.proto_type;
			header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
		}
	}

	rle_ctx_set_is_fragmented(rle_ctx, C_FALSE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_nb_frag_pdu(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, C_FALSE);
	/* set real size of PDU */
	rle_ctx_set_pdu_length(rle_ctx, (data_length - header_size));
	/* it's a RLE complete packet, so there is no data remaining */
	rle_ctx_set_remaining_pdu_length(rle_ctx, 0);
	/* RLE packet length is the sum of packet label, protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
	rle_ctx_set_proto_type(rle_ctx, protocol_type);
	rle_ctx_set_label_type(rle_ctx, label_type);

	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO
}

static void update_ctx_start(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	struct rle_header_start *hdr = (struct rle_header_start *)data_buffer;
	/* real size of PDU,
	 * total length = PDU length + proto_type field */
	uint16_t protocol_type = 0;
	size_t header_size = 0;
	size_t trailer_size = 0;

	/* get ptype compression status from NCC
	 * and CRC usage from user */
	int is_compressed = rle_conf_get_ptype_compression(rle_conf);
	int is_crc_used = rle_conf_get_crc_check(rle_conf);

	if ((hdr->head_start.b.proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
			(hdr->head_start.b.label_type == RLE_LT_IMPLICIT_PROTO_TYPE)) {
		protocol_type = rle_conf_get_default_ptype(rle_conf);
	} else if (hdr->head_start.b.label_type == RLE_LT_PROTO_SIGNAL) {
		protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
	}

	if (hdr->head_start.b.proto_type_supp != RLE_T_PROTO_TYPE_SUPP) {
		struct rle_header_start_w_ptype *hdr_pt =
		(struct rle_header_start_w_ptype *)data_buffer;
		if (is_compressed) {
			protocol_type = hdr_pt->ptype_c_s.proto_type;
			header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
		} else {
			protocol_type = hdr_pt->ptype_u_s.proto_type;
			header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
		}
	}

	if (is_crc_used)
		trailer_size += RLE_CRC32_FIELD_SIZE;
	else
		trailer_size += RLE_SEQ_NO_FIELD_SIZE;

	size_t pdu_length = (hdr->head_start.b.total_length -
			header_size);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE head_start.b.total_length %d PDU length %zu"
			" label_type 0x%x proto_type_supp 0x%x\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			hdr->head_start.b.total_length,
			pdu_length,
			hdr->head_start.b.label_type,
			hdr->head_start.b.proto_type_supp);
#endif

	rle_ctx_set_pdu_length(rle_ctx, pdu_length);
	rle_ctx_set_remaining_pdu_length(rle_ctx, (hdr->head_start.b.total_length -
				hdr->head.b.rle_packet_length));
	rle_ctx_set_is_fragmented(rle_ctx, C_TRUE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_nb_frag_pdu(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, is_crc_used);
	/* set real size of PDU */
	rle_ctx_set_pdu_length(rle_ctx, pdu_length);
	/* it's a RLE start packet, so there is some data remaining
	 * we can deduce from total length and this packet length the
	 * remaining length to receive */

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE START remaining_pdu %d total length %d rle length %d\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			rle_ctx_get_remaining_pdu_length(rle_ctx),
			hdr->head_start.b.total_length, hdr->head.b.rle_packet_length);
	PRINT("------ RECV START PACKET ------------\n");
	PRINT("| SE |  RLEPL |  ID |  TL   |  LT  |  T  |  PTYPE  |\n");
	PRINT("| %d%d |   %d   | 0x%0x |  %d  |  0x%0x | 0x%0x | 0x%0x    |\n",
			hdr->head.b.start_ind,
			hdr->head.b.end_ind,
			hdr->head.b.rle_packet_length,
			hdr->head.b.LT_T_FID,
			hdr->head_start.b.total_length,
			hdr->head_start.b.label_type,
			hdr->head_start.b.proto_type_supp,
			protocol_type);
#endif

	/* RLE packet length is the sum of packet label, protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
	rle_ctx_set_proto_type(rle_ctx, protocol_type);
	rle_ctx_set_label_type(rle_ctx, hdr->head_start.b.label_type);

	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO
}

static void update_ctx_cont(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	struct rle_header_cont_end *hdr = (struct rle_header_cont_end *)data_buffer;
	/* get PDU length (total_length - p_type_length) */
	size_t remaining_pdu_length = rle_ctx_get_remaining_pdu_length(rle_ctx);

	rle_ctx_incr_frag_counter(rle_ctx);
	rle_ctx_incr_nb_frag_pdu(rle_ctx);

	/* it's a RLE continuation packet, so there is some data remaining
	 * we can deduce from total length and previous packets length the
	 * remaining length to receive */
	rle_ctx_set_remaining_pdu_length(rle_ctx,
			(remaining_pdu_length - hdr->head.b.rle_packet_length));
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
}

static void update_ctx_end(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	struct rle_header_cont_end *hdr = (struct rle_header_cont_end *)data_buffer;

	rle_ctx_incr_frag_counter(rle_ctx);
	rle_ctx_incr_nb_frag_pdu(rle_ctx);
	/* RLE packet length is the sum of packet label, protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
}

static void update_ctx_fragmented(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer, int frag_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	switch (frag_type) {
		case RLE_PDU_START_FRAG:
			update_ctx_start(rle_ctx,
					rle_conf,
					data_buffer);
			break;
		case RLE_PDU_CONT_FRAG:
			update_ctx_cont(rle_ctx,
				       rle_conf,
			       	       data_buffer);
			break;
		case RLE_PDU_END_FRAG:
			update_ctx_end(rle_ctx,
				       rle_conf,
			       	       data_buffer);
			break;
		default:
			PRINT("ERROR %s %s:%s:%d: invalid fragment type [%d]\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					frag_type);
			break;
	}
}

int reassembly_get_pdu(struct rle_ctx_management *rle_ctx,
		void *pdu_buffer,
		int *pdu_proto_type,
		uint32_t *pdu_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int ret = C_OK;

	if ((pdu_buffer == NULL) || (pdu_proto_type == NULL)) {
		PRINT("ERROR %s %s:%s:%d: invalid parameter,"
			       " cannot get reassembled PDU\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__);
		ret = C_ERROR_BUF;
		goto return_ret;
	}

	memcpy(pdu_buffer, (const void *)rle_ctx->buf,
			rle_ctx->pdu_length);

	*pdu_proto_type = rle_ctx_get_proto_type(rle_ctx);
	*pdu_length = rle_ctx_get_pdu_length(rle_ctx);

	/* update rle pointer to data end address */
	rle_ctx_set_end_address(rle_ctx, (char *)(rle_ctx->buf));
	rle_ctx_set_remaining_pdu_length(rle_ctx, 0);

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: Copy PDU %d Bytes\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			rle_ctx->pdu_length);
#endif

return_ret:
	return ret;
}

int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer, size_t data_length, int frag_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	size_t hdr_offset = 0;
	int ret = C_ERROR;

	/* retrieve header length to strip it during memory copy */
	switch (frag_type) {
		case RLE_PDU_COMPLETE:
		case RLE_PDU_START_FRAG:
		case RLE_PDU_CONT_FRAG:
		case RLE_PDU_END_FRAG:
			hdr_offset = get_header_size(rle_ctx,
					rle_conf,
					data_buffer,
					frag_type);
			break;
		default:
			PRINT("ERROR %s %s:%s:%d: invalid fragment type [%d] to reassemble\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					frag_type);
			goto ret_val;
			break;
	}

	/* check if the complete PDU is not fragmented
	 * into more than 256 fragments, if not it's OK we continue,
	 * otherwise drop fragment and all data of this frag_id */
	if (rle_ctx_get_nb_frag_pdu(rle_ctx) > RLE_MAX_SEQ_NO) {
		PRINT("ERROR %s %s:%s:%d: waited too much fragments to reassemble packet\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__);
		ret = C_ERROR_TOO_MUCH_FRAG;
		goto ret_val;
	}

	/* the copy begins from the buffer end address
	 * and the copied data are from a received RLE packet
	 * plus RLE header length to get the payload only */
	memcpy((void *)(rle_ctx->end_address),
		(const void *)(data_buffer + hdr_offset),
		(data_length - hdr_offset));

	if (frag_type != RLE_PDU_COMPLETE) {
		/* fragmentation case */
		update_ctx_fragmented(rle_ctx, rle_conf,
				data_buffer, frag_type);

		if (frag_type == RLE_PDU_END_FRAG) {
			/* in case of end packet,
			 * length must be checked
			 * and sequence number or CRC
			 * must be checked too */
			ret = check_fragmented_consistency(rle_ctx, data_buffer, data_length);
			if(ret != C_OK)
				goto error_frag;

			/* Tell user that
			 * reassembly is complete */
			rle_ctx_incr_counter_ok(rle_ctx);
			ret = C_REASSEMBLY_OK;
		} else {
			ret = C_OK;
		}
	} else {
		/* no fragmentation case */
		ret = check_complete_length(rle_ctx, data_buffer, data_length, hdr_offset);
		if (ret == C_OK) {
			/* update ctx status structure if length checking is OK */
			update_ctx_complete(rle_ctx, rle_conf,
					data_buffer, data_length);
			rle_ctx_incr_counter_ok(rle_ctx);

			/* update link status */
			rle_ctx_incr_counter_bytes(rle_ctx,
					data_length);

			goto ret_val;
		} else {
			goto error_frag;
		}
	}

	/* update rle pointer to data end address */
	rle_ctx_set_end_address(rle_ctx, (char *)(rle_ctx->end_address +
				(data_length - hdr_offset)));

	/* update link status */
	rle_ctx_incr_counter_bytes(rle_ctx,
			data_length);

	goto ret_val;

error_frag:
	/* discard all data */
	memset((void *)(rle_ctx->end_address),
			0, (data_length - hdr_offset));

	/* TODO call a callback which must be
	 * specific to each protocol type supported
	 * and give it the final reassembled packet */

ret_val:
	return ret;
}

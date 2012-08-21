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

static int check_complete_length(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length)
{
	/* map the complete packet header */
	union rle_header_all *head = (union rle_header_all *)data_buffer;
	/* rle packet length is the sum of proto_type and payload size */
	size_t recv_packet_length = (data_length - sizeof(union rle_header_all));

	if (head->b.rle_packet_length != recv_packet_length) {
		PRINT("ERROR %s:%s:%d: invalid packet length,"
			       " received size [%d] computed size [%zu]\n",
				__FILE__, __func__, __LINE__,
				head->b.rle_packet_length,
				recv_packet_length);
		return C_ERROR_DROP;
	}

	return C_OK;
}

static int check_fragmented_length(struct rle_ctx_management *rle_ctx,
		size_t data_length)
{
	/* data_length contains header and also trailer length which
	 * must not be taken into account while computing
	 * PDU total length */
	size_t trailer_size = 0;

	if (rle_ctx_get_use_crc(rle_ctx) == C_TRUE)
		trailer_size = RLE_CRC32_FIELD_SIZE;
	else
		trailer_size = RLE_SEQ_NO_FIELD_SIZE;

	size_t recv_pkt_length = (data_length -
			(sizeof(union rle_header_all) + trailer_size));

	/* for each fragment received, remaining data size is updated,
	 * so if everything is okay remaining size must be equal
	 * to the last rle_packet_length value */
	size_t remaining_size = rle_ctx_get_remaining_pdu_length(rle_ctx);

	if (remaining_size != recv_pkt_length) {
		PRINT("ERROR %s:%s:%d: invalid packet length,"
			       " received size [%zu] awaited size [%zu]\n",
				__FILE__, __func__, __LINE__,
				recv_pkt_length, remaining_size);
		return C_ERROR_DROP;
	}

	return C_OK;
}

static int check_fragmented_sequence(struct rle_ctx_management *rle_ctx,
		void * data_buffer, size_t data_length)
{
	/* awaited sequence nb must be equal
	 * to the received one.
	 * Trailer addr is buffer addr + offset
	 * offset is equal to the length of received data
	 * - size of seq_no field */
	struct rle_trailer *trl = (struct rle_trailer *)(data_buffer +
			(data_length - RLE_SEQ_NO_FIELD_SIZE));

	if (trl->seq_no != rle_ctx->next_seq_nb) {
		PRINT("ERROR %s:%s:%d: sequence number inconsistency,"
			       " received [%d] expected [%d]\n",
			       __FILE__, __func__, __LINE__,
			       trl->seq_no, rle_ctx->next_seq_nb);
		return C_ERROR_DROP;
	}

	return C_OK;
}

static uint32_t compute_crc32(struct rle_ctx_management *rle_ctx)
{
	uint32_t crc32 = 0;
	uint16_t field_value = 0;
	size_t length = 0;

	/* first compute CRC of the header field p_type */
	length = RLE_PROTO_TYPE_FIELD_SIZE;
	field_value = (rle_ctx_get_proto_type(rle_ctx));
	crc32 = compute_crc((unsigned char *)&field_value, length, RLE_CRC_INIT);

	/* compute PDU CRC */
	length = rle_ctx_get_pdu_length(rle_ctx);
	crc32 = compute_crc((unsigned char *)(rle_ctx->buf), length, crc32);

	return crc32;
}

static int check_fragmented_crc(struct rle_ctx_management *rle_ctx,
		void * data_buffer, size_t data_length)
{
	/* We must compute CRC using all PDU data
	 * and the compare it to the received CRC32 value */
	struct rle_trailer *trl = (struct rle_trailer *)(data_buffer +
			(data_length - RLE_CRC32_FIELD_SIZE));

	uint32_t crc = compute_crc32(rle_ctx);

	if (trl->crc != crc) {
		PRINT("ERROR %s:%s:%d: CRC error,"
			       " received [%0x] expected [%0x]\n",
			       __FILE__, __func__, __LINE__,
			       trl->crc, crc);
		return C_ERROR_DROP;
	}

	return C_OK;
}

static int check_fragmented_consistency(struct rle_ctx_management *rle_ctx,
		void * data_buffer, size_t data_length)
{
	int ret = C_ERROR;

	if (check_fragmented_length(data_buffer, data_length)) {
		if(!rle_ctx_get_use_crc(rle_ctx))
			ret = check_fragmented_sequence(rle_ctx,
					data_buffer, data_length);
		else
			ret = check_fragmented_crc(rle_ctx,
					data_buffer, data_length);
	}

	return ret;
}

static void update_ctx_complete(struct rle_ctx_management *rle_ctx,
		void * data_buffer, size_t data_length)
{
	struct rle_header_complete *hdr = (struct rle_header_complete *)data_buffer;

	rle_ctx_set_is_fragmented(rle_ctx, C_FALSE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_nb_frag_pdu(rle_ctx, 0);
	rle_ctx_set_use_crc(rle_ctx, C_FALSE);
	/* set real size of PDU */
	rle_ctx_set_pdu_length(rle_ctx, (data_length - sizeof(struct rle_header_complete)));
	/* it's a RLE complete packet, so there is no data remaining */
	rle_ctx_set_remaining_pdu_length(rle_ctx, 0);
	/* RLE packet length is the sum of packet label, protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
	rle_ctx_set_proto_type(rle_ctx, hdr->proto_type); // TODO
	rle_ctx_set_label_type(rle_ctx, hdr->head.b.label_type); // TODO
	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO
}

static void update_ctx_start(struct rle_ctx_management *rle_ctx,
		void *data_buffer)
{
	struct rle_header_start *hdr = (struct rle_header_start *)data_buffer;
	/* real size of PDU,
	 * total length = PDU length + proto_type field */
	size_t pdu_length = (hdr->head_start.b.total_length - RLE_PROTO_TYPE_FIELD_SIZE);

	rle_ctx_set_is_fragmented(rle_ctx, C_TRUE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_nb_frag_pdu(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, C_FALSE); /* TODO */
	/* set real size of PDU */
	rle_ctx_set_pdu_length(rle_ctx, pdu_length);
	/* it's a RLE start packet, so there is some data remaining
	 * we can deduce from total length and this packet length the
	 * remaining length to receive */
	rle_ctx_set_remaining_pdu_length(rle_ctx,
			(hdr->head_start.b.total_length - hdr->head.b.rle_packet_length));
	/* RLE packet length is the sum of packet label, protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
	rle_ctx_set_proto_type(rle_ctx, hdr->proto_type); // TODO
	rle_ctx_set_label_type(rle_ctx, hdr->head.b.label_type); // TODO
	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO
}

static void update_ctx_cont(struct rle_ctx_management *rle_ctx,
		void *data_buffer)
{
	struct rle_header_cont_end *hdr = (struct rle_header_cont_end *)data_buffer;
	/* get PDU length (total_length - p_type_length) */
	size_t pdu_length = rle_ctx_get_pdu_length(rle_ctx);

	rle_ctx_incr_frag_counter(rle_ctx);
	rle_ctx_incr_nb_frag_pdu(rle_ctx);

	/* it's a RLE continuation packet, so there is some data remaining
	 * we can deduce from total length and previous packets length the
	 * remaining length to receive */
	rle_ctx_set_remaining_pdu_length(rle_ctx,
			(pdu_length - hdr->head.b.rle_packet_length));
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
}

static void update_ctx_end(struct rle_ctx_management *rle_ctx,
		void *data_buffer)
{
	struct rle_header_cont_end *hdr = (struct rle_header_cont_end *)data_buffer;

	rle_ctx_incr_frag_counter(rle_ctx);
	rle_ctx_incr_nb_frag_pdu(rle_ctx);

	/* it's a RLE end packet, so there is no data remaining */
	rle_ctx_set_remaining_pdu_length(rle_ctx, 0);
	/* RLE packet length is the sum of packet label, protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx, hdr->head.b.rle_packet_length);
}

static void update_ctx_fragmented(struct rle_ctx_management *rle_ctx,
		void *data_buffer, int frag_type)
{
	switch (frag_type) {
		case RLE_PDU_START_FRAG:
			update_ctx_start(rle_ctx, data_buffer);
			break;
		case RLE_PDU_CONT_FRAG:
			update_ctx_cont(rle_ctx, data_buffer);
			break;
		case RLE_PDU_END_FRAG:
			update_ctx_end(rle_ctx, data_buffer);
			break;
		default:
			PRINT("ERROR %s:%s:%d: invalid fragment type [%d]\n",
					__FILE__, __func__, __LINE__, frag_type);
			break;
	}
}

int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length, int frag_type)
{
	size_t hdr_offset = 0;
	int ret = C_ERROR;

	/* retrieve header length to strip it during memory copy */
	switch (frag_type) {
		case RLE_PDU_COMPLETE:
			hdr_offset = sizeof(struct rle_header_complete);
			break;
		case RLE_PDU_START_FRAG:
			hdr_offset = sizeof(struct rle_header_start);
			break;
		case RLE_PDU_CONT_FRAG:
		case RLE_PDU_END_FRAG:
			hdr_offset = sizeof(struct rle_header_cont_end);
			break;
		default:
			PRINT("ERROR %s:%s:%d: invalid fragment type [%d]\n",
					__FILE__, __func__, __LINE__, frag_type);
			goto ret_val;
			break;
	}

	/* check if the complete PDU is not fragmented
	 * into more than 256 fragments, if not it's OK we continue,
	 * otherwise drop fragment and all data of this frag_id */
	if (rle_ctx_get_nb_frag_pdu(rle_ctx) >= RLE_MAX_SEQ_NO) {
		PRINT("ERROR %s:%s:%d: waited too much fragments to reassemble packet\n",
				__FILE__, __func__, __LINE__);
		ret = C_ERROR_DROP;
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
		if (frag_type == RLE_PDU_END_FRAG) {
			/* in case of end packet,
			 * length must be checked
			 * and sequence number or CRC
			 * must be checked too */
			if(!check_fragmented_consistency(rle_ctx, data_buffer, data_length)) {
				ret = C_ERROR_DROP;
				goto error_frag;
			}
		}
		update_ctx_fragmented(rle_ctx, data_buffer, frag_type);
	} else {
		/* no fragmentation case */
		ret = check_complete_length(rle_ctx, data_buffer, data_length);
		if (ret == C_OK)
			/* update ctx status structure if length checking is OK */
			update_ctx_complete(rle_ctx, data_buffer, data_length);
		else
			goto error_frag;
	}

	/* update rle pointer to data end address */
	rle_ctx_set_end_address(rle_ctx, (int *)(rle_ctx->end_address +
				(data_length - hdr_offset)));

	ret = C_OK;
	goto ret_val;

error_frag:
	/* discard all data */
	memset((void *)(rle_ctx->end_address),
			0, (data_length - hdr_offset));
ret_val:
	return ret;
}

/**
 * @file   rle_ctx.c
 * @brief  RLE transmitter functions
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#else

#include <linux/stddef.h>
#include <linux/string.h>

#endif

#include "rle_ctx.h"
#include "constants.h"
#include "zc_buffer.h"

#define MODULE_NAME "RLE CTX"

#ifdef __KERNEL__
#define strerror(errno) "1"
#endif

/************************************************************************
*									*
* Prototypes private functions						*
*									*
************************************************************************/
/**
 *  @brief	Flush all data and pointer of a RLE context structure
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
static void flush(struct rle_ctx_management *_this);

/************************************************************************
*									*
* Private functions							*
*									*
************************************************************************/
static void flush(struct rle_ctx_management *_this)
{
	_this->frag_id = 0xff;
	_this->next_seq_nb = 0xff;
	_this->is_fragmented = C_FALSE;
	_this->frag_counter = 0;
	_this->nb_frag_pdu = 0;
	_this->qos_tag = 0xffffffff;
	_this->use_crc = C_FALSE;
	_this->pdu_length = 0;
	_this->remaining_pdu_length = 0;
	_this->rle_length = 0;
	_this->proto_type = 0xffff;
	_this->label_type = 0xff;
	_this->pdu_buf = NULL;
	_this->end_address = NULL;
	rle_ctx_reset_counters(_this);

	return;
}

/************************************************************************
*									*
* Public functions							*
*									*
************************************************************************/
int rle_ctx_init(struct rle_ctx_management *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	if (!_this) {
		PRINT("ERROR %s:%s:%d: RLE context is NULL\n",
		      __FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	_this->buf = NULL;

	/* set to zero or invalid values
	 * all variables */
	flush(_this);

	/* allocate enough memory space
	 * for the worst case of fragmentation */
	_this->buf = MALLOC(ZC_BUFFER_MAX_SIZE);
	if (!_this->buf) {
		PRINT("ERROR %s %s:%s:%d: allocating ZC buffer failed [%s]\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__,
		      strerror(errno));
		return C_ERROR;
	}

	/* set useful data end address pointing
	 * to the buffer start address */
	_this->end_address = (char *)_this->buf;

	/* set all buffer memory to zero */
	memset(_this->buf, 0, ZC_BUFFER_MAX_SIZE);

	return C_OK;
}

int rle_ctx_destroy(struct rle_ctx_management *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	if (!_this) {
		PRINT("ERROR %s %s:%s:%d: RLE context is NULL\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return C_ERROR;
	}

	flush(_this);

	if (_this->buf != NULL) {
		FREE(_this->buf);
		_this->buf = NULL;
	}

	return C_OK;
}

void rle_ctx_flush_buffer(struct rle_ctx_management *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__);
#endif

	/* set all buffer memory to zero
	 * and reset buffer end addr */
	memset(_this->buf, 0, ZC_BUFFER_MAX_SIZE);
	_this->end_address = (char *)_this->buf;
}

void rle_ctx_invalid_ctx(struct rle_ctx_management *_this)
{
	_this->is_fragmented = C_FALSE;
	_this->frag_counter = 0;
	_this->nb_frag_pdu = 0;
	_this->qos_tag = 0xffffffff;
	_this->use_crc = C_FALSE;
	_this->pdu_length = 0;
	_this->remaining_pdu_length = 0;
	_this->rle_length = 0;
	_this->alpdu_size = 0;
	_this->remaining_alpdu_size = 0;
	_this->proto_type = 0xffff;
	_this->label_type = 0xff;
	_this->pdu_buf = NULL;
	_this->end_address = NULL;
}

void rle_ctx_set_frag_id(struct rle_ctx_management *_this, uint8_t val)
{
	if (val > RLE_MAX_FRAG_ID) {
		PRINT("ERROR %s %s:%s:%d: Invalid fragment id [%d]\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__, val);
		return;
	}

	_this->frag_id = val;
}

uint8_t rle_ctx_get_frag_id(struct rle_ctx_management *_this)
{
	return _this->frag_id;
}

void rle_ctx_set_seq_nb(struct rle_ctx_management *_this, uint8_t val)
{
	_this->next_seq_nb = val;
}

uint8_t rle_ctx_get_seq_nb(struct rle_ctx_management *_this)
{
	return _this->next_seq_nb;
}

void rle_ctx_incr_seq_nb(struct rle_ctx_management *_this)
{
	_this->next_seq_nb++;
}

void rle_ctx_set_is_fragmented(struct rle_ctx_management *_this, int val)
{
	_this->is_fragmented = val;
}

int rle_ctx_get_is_fragmented(struct rle_ctx_management *_this)
{
	return _this->is_fragmented;
}

void rle_ctx_set_frag_counter(struct rle_ctx_management *_this, uint8_t val)
{
	_this->frag_counter = val;
}

void rle_ctx_incr_frag_counter(struct rle_ctx_management *_this)
{
	_this->frag_counter++;
}

void rle_ctx_set_nb_frag_pdu(struct rle_ctx_management *_this, int val)
{
	_this->nb_frag_pdu = val;
}

void rle_ctx_incr_nb_frag_pdu(struct rle_ctx_management *_this)
{
	_this->nb_frag_pdu++;
}

int rle_ctx_get_nb_frag_pdu(struct rle_ctx_management *_this)
{
	return _this->nb_frag_pdu;
}

void rle_ctx_set_qos_tag(struct rle_ctx_management *_this, uint32_t val)
{
	_this->qos_tag = val;
}

void rle_ctx_set_use_crc(struct rle_ctx_management *_this, int val)
{
	_this->use_crc = val;
}

int rle_ctx_get_use_crc(struct rle_ctx_management *_this)
{
	return _this->use_crc;
}

void rle_ctx_set_pdu_length(struct rle_ctx_management *_this, uint32_t val)
{
	if (val > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s:%s:%d: Invalid PDU length [%d]\n",
		      __FILE__, __func__, __LINE__, val);
		return;
	}

	_this->pdu_length = val;
}

uint32_t rle_ctx_get_pdu_length(struct rle_ctx_management *_this)
{
	return _this->pdu_length;
}

void rle_ctx_set_remaining_pdu_length(struct rle_ctx_management *_this, uint32_t val)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d val = %d\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__, val);
#endif

	if (val > RLE_MAX_PDU_SIZE) {
		PRINT("WARNING %s:%s:%d: Invalid remaining PDU length [%d]\n",
		      __FILE__, __func__, __LINE__, val);
		return;
	}

	_this->remaining_pdu_length = val;
}

uint32_t rle_ctx_get_remaining_pdu_length(struct rle_ctx_management *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d val = %u\n",
	      MODULE_NAME,
	      __FILE__, __func__, __LINE__,
	      _this->remaining_pdu_length);
#endif

	return _this->remaining_pdu_length;
}

void rle_ctx_set_rle_length(struct rle_ctx_management *_this, uint32_t val,
                            const size_t header_size)
{
	if (val > (RLE_MAX_PDU_SIZE + header_size)) {
		PRINT("ERROR %s %s:%s:%d: Invalid RLE length [%d]\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__,
		      val);
		return;
	}

	_this->rle_length = val;
}

void rle_ctx_set_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val)
{
	_this->alpdu_size = val;
	return;
}

void rle_ctx_incr_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val)
{
	_this->alpdu_size += val;
	return;
}

uint32_t rle_ctx_get_alpdu_length(const struct rle_ctx_management *const _this)
{
	return _this->alpdu_size;
}

void rle_ctx_set_remaining_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val)
{
	_this->remaining_alpdu_size = val;
	return;
}

void rle_ctx_decr_remaining_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val)
{
	if (val > _this->remaining_alpdu_size) {
		PRINT("ERROR %s %s:%s:%d: Invalid decr value for remaining ALPDU length [%d]\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__,
		      val);
	} else {
		_this->remaining_alpdu_size -= val;
	}
	return;
}

uint32_t rle_ctx_get_remaining_alpdu_length(const struct rle_ctx_management *const _this)
{
	return _this->remaining_alpdu_size;
}

uint32_t rle_ctx_get_rle_length(struct rle_ctx_management *_this)
{
	return _this->rle_length;
}

void rle_ctx_set_proto_type(struct rle_ctx_management *_this, uint16_t val)
{
	_this->proto_type = val;
}

uint16_t rle_ctx_get_proto_type(struct rle_ctx_management *_this)
{
	return _this->proto_type;
}

void rle_ctx_set_label_type(struct rle_ctx_management *_this, uint8_t val)
{
	switch (val) {
	case RLE_LT_IMPLICIT_PROTO_TYPE:
	case RLE_LT_PROTO_SIGNAL:
	case RLE_T_PROTO_TYPE_SUPP:
	case RLE_T_PROTO_TYPE_NO_SUPP:
		break;
	default:
		PRINT("ERROR %s %s:%s:%d: Invalid Label_type value [%d]\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__,
		      val);
		return;
	}

	_this->label_type = val;
}

void rle_ctx_set_end_address(struct rle_ctx_management *_this, char *addr)
{
	if (!addr) {
		PRINT("ERROR %s %s:%s:%d: Useful data end address NULL\n",
		      MODULE_NAME,
		      __FILE__, __func__, __LINE__);
		return;
	}

	_this->end_address = (char *)addr;
}

char *rle_ctx_get_end_address(struct rle_ctx_management *_this)
{
	return _this->end_address;
}

void rle_ctx_dump_alpdu(const uint16_t protocol_type, const struct rle_ctx_management *const _this,
                        struct rle_configuration *const rle_conf, unsigned char alpdu_buffer[],
                        const size_t alpdu_buffer_size,
                        size_t *const alpdu_length)
{
	struct zc_rle_header_complete_w_ptype *rle_hdr =
	        (struct zc_rle_header_complete_w_ptype *)_this->buf;

	*alpdu_length = (size_t)(rle_hdr->ptrs.end - rle_hdr->ptrs.start);

	if (*alpdu_length > alpdu_buffer_size) {
		PRINT("ERROR %s:l.%d - ALPDU length (%zu) too big for buffer size (%zu).\n",
		      __func__, __LINE__, *alpdu_length,
		      alpdu_buffer_size);
	} else {
		size_t rle_header_size = 0;

		if (!ptype_is_omissible(protocol_type, rle_conf)) {
			struct rle_header_complete_w_ptype *rle_c_hdr =
			        (struct rle_header_complete_w_ptype *)&rle_hdr->header;

			if (rle_conf_get_ptype_compression(rle_conf)) {
				rle_header_size = RLE_PROTO_TYPE_FIELD_SIZE_COMP;
				if (rle_header_ptype_is_compressible(protocol_type) == C_OK) {
					alpdu_buffer[0] = rle_c_hdr->ptype_c_s.c.proto_type;
				} else {
					unsigned char *p_uint16 =
					        (unsigned char *)&(rle_c_hdr->ptype_c_s.e.
					                           proto_type_uncompressed);
					rle_header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
					alpdu_buffer[0] = rle_c_hdr->ptype_c_s.e.proto_type;
					alpdu_buffer[1] = p_uint16[1];
					alpdu_buffer[2] = p_uint16[0];
				}
			} else {
				unsigned char *p_uint16 =
				        (unsigned char *)&(rle_c_hdr->ptype_u_s.proto_type);
				rle_header_size = RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
				alpdu_buffer[0] = p_uint16[1];
				alpdu_buffer[1] = p_uint16[0];
			}
		}

		memcpy((void *)(alpdu_buffer + (size_t)rle_header_size),
		       (const void *)rle_hdr->ptrs.start,
		       *alpdu_length);
		*alpdu_length += rle_header_size;
	}

	/*
	 * {
	 *      size_t iterator = 0;
	 *
	 *      for (iterator = 0; iterator < *alpdu_length; ++iterator) {
	 *              PRINT("0x%02x ", alpdu_buffer[iterator]);
	 *      }
	 *      PRINT("\n");
	 * }
	 */

	return;
}


enum check_frag_status check_frag_transition(const enum frag_states current_state,
                                             const enum frag_states next_state)
{
	enum check_frag_status status = FRAG_STATUS_KO; /* KO states explicitly pass silently */

	/*
	 * Possible transitions:
	 *
	 *   +-------------------------------+
	 *   |                               |
	 *   |                               v
	 * Start -------> Continue -------> End
	 *                ^      |
	 *                |      |
	 *                +------+
	 */

	switch (current_state) {
	case FRAG_STATE_START:
	case FRAG_STATE_CONT:
		switch (next_state) {
		case FRAG_STATE_CONT:
		case FRAG_STATE_END:
			status = FRAG_STATUS_OK;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return status;
}

enum frag_states get_fragment_type(const unsigned char *const buffer)
{
	enum frag_states fragment_type = RLE_PDU_COMPLETE;

	union rle_header_all *head = (union rle_header_all *)((void *)buffer);

	if (head->b.start_ind == 0x0) {
		if (head->b.end_ind == 0x0) {
			fragment_type = FRAG_STATE_CONT;
		} else {
			fragment_type = FRAG_STATE_END;
		}
	} else {
		if (head->b.end_ind == 0x0) {
			fragment_type = FRAG_STATE_START;
		} else {
			fragment_type = FRAG_STATE_COMP;
		}
	}

	return fragment_type;
}

size_t get_fragment_length(const unsigned char *const buffer)
{
	size_t fragment_length = 0;
	enum frag_states fragment_type = RLE_PDU_COMPLETE;
	union rle_header_all *head = (union rle_header_all *)((void *)buffer);


	fragment_type = get_fragment_type(buffer);

	switch (fragment_type) {
	case FRAG_STATE_CONT:
	case FRAG_STATE_COMP:
	case FRAG_STATE_END:
		fragment_length += (size_t)RLE_CONT_HEADER_SIZE;
		break;
	case FRAG_STATE_START:
		fragment_length += (size_t)RLE_START_MANDATORY_HEADER_SIZE;
		break;
	default:
		break;
	}

	fragment_length += rle_header_all_get_packet_length(*head);

	return fragment_length;
}

enum check_frag_status rle_ctx_check_frag_integrity(const struct rle_ctx_management *const _this)
{
	enum check_frag_status status = FRAG_STATUS_KO;
	enum check_frag_status transition_status = FRAG_STATUS_KO;

	unsigned char *buffer = _this->buf;
	enum frag_states current_state = get_fragment_type(buffer);
	enum frag_states previous_state = FRAG_STATE_START;
	size_t sdu_size = 0;

	struct zc_rle_header_cont_end *rle_hdr = NULL;

	PRINT("CHECK_FRAG\n");

	switch (current_state) {
	case FRAG_STATE_START:
		break;
	case FRAG_STATE_COMP:
		status = FRAG_STATUS_OK;
	/* Not a fragmented context */
	default:
		/* Not a start fragment. */
		goto exit_label;
	}

	/*
	 * Reminder :
	 *      Possible transitions:
	 *
	 *   +-------------------------------+
	 *   |                               |
	 *   |                               v
	 * Start -------> Continue -------> End
	 *                ^      |
	 *                |      |
	 *                +------+
	 */

	/* START Fragment */
	{
		/* Temporary scope for rle_hdr */
		const int supp =
		        ((struct rle_header_start *)((void *)buffer))->head_start.b.proto_type_supp;

		if (supp != RLE_T_PROTO_TYPE_SUPP) {
			struct zc_rle_header_start_w_ptype *rle_hdr_start =
			        (struct zc_rle_header_start_w_ptype *)((void *)buffer);
			sdu_size += rle_hdr_start->ptrs.end - rle_hdr_start->ptrs.start;
		} else {
			struct zc_rle_header_start *rle_hdr_start =
			        (struct zc_rle_header_start *)((void *)buffer);
			sdu_size += rle_hdr_start->ptrs.end - rle_hdr_start->ptrs.start;
		}
		buffer += sizeof(struct zc_rle_header_start_w_ptype);
	}


	/* CONTINUATION Fragments */
	rle_hdr = (struct zc_rle_header_cont_end *)((void *)(buffer));

	previous_state = current_state;
	current_state = get_fragment_type(buffer);
	transition_status = check_frag_transition(previous_state, current_state);

	if (transition_status != FRAG_STATUS_OK) {
		PRINT("ERROR: Bad transition in integrity check\n");
		goto exit_label;
	}

	while (current_state != FRAG_STATE_END) {
		if (rle_hdr->ptrs.start == NULL) {
			PRINT("ERROR: NOT FULLY FRAGMENTED\n");
			goto exit_label;
		}

		sdu_size += rle_hdr->ptrs.end - rle_hdr->ptrs.start;

		buffer += sizeof(struct zc_rle_header_cont_end);
		rle_hdr = (struct zc_rle_header_cont_end *)((void *)buffer);

		previous_state = current_state;
		current_state = get_fragment_type(buffer);
		transition_status = check_frag_transition(previous_state, current_state);

		if (transition_status != FRAG_STATUS_OK) {
			PRINT("ERROR: Bad transition in integrity check\n");
			goto exit_label;
		}
	}

	/* END Fragment */
	if (current_state == FRAG_STATE_END) {
		sdu_size += rle_hdr->ptrs.end - rle_hdr->ptrs.start;

		status = FRAG_STATUS_OK;

		buffer += sizeof(struct zc_rle_header_cont_end);
	}

exit_label:

	return status;
}

void rle_header_all_set_packet_length(union rle_header_all *const header, const size_t length)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	(*header).b.rle_packet_length_1 = (uint8_t)((((uint16_t)(length) & 0x7ff) >> 5) & 0x3f);
	(*header).b.rle_packet_length_2 = (uint8_t)(((uint16_t)(length) & 0x7ff) & 0x1f);
#elif __BYTE_ORDER == __BIG_ENDIAN
	(*header).b.rle_packet_length = length;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return;
}

size_t rle_header_all_get_packet_length(const union rle_header_all header)
{
	size_t length = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	length = ((uint16_t)((header.b.rle_packet_length_1 & 0x3f)) << 5) & 0x7ff;
	length |= (header.b.rle_packet_length_2 & 0x1f);
#elif __BYTE_ORDER == __BIG_ENDIAN
	length = header.b.rle_packet_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return length;
}

void rle_header_start_set_packet_length(union rle_header_start_packet *const header,
                                        const size_t length)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	(*header).b.total_length_1 = (uint8_t)((((uint16_t)(length) & 0xfff) >> 5) & 0x7f);
	(*header).b.total_length_2 = (uint8_t)(((uint16_t)(length) & 0xfff) & 0x1f);
#elif __BYTE_ORDER == __BIG_ENDIAN
	(*header).b.rle_packet_length = length;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return;
}

size_t rle_header_start_get_packet_length(const union rle_header_start_packet header)
{
	size_t length = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	length = ((uint16_t)((header.b.total_length_1 & 0x7f)) << 5) & 0xfff;
	length |= (header.b.total_length_2 & 0x1f);
#elif __BYTE_ORDER == __BIG_ENDIAN
	length = header.b.rle_packet_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return length;
}

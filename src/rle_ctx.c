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
	_this->lk_status.counter_in = 0L;
	_this->lk_status.counter_ok = 0L;
	_this->lk_status.counter_dropped = 0L;
	_this->lk_status.counter_lost = 0L;
	_this->lk_status.counter_bytes_in = 0L;
	_this->lk_status.counter_bytes_ok = 0L;
	_this->lk_status.counter_bytes_dropped = 0L;
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

uint8_t rle_ctx_get_label_type(struct rle_ctx_management *_this)
{
	return _this->label_type;
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

/*********************************
* Link status getters & setters *
*********************************/
void rle_ctx_set_counter_in(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_in = val;
}

void rle_ctx_incr_counter_in(struct rle_ctx_management *_this)
{
	_this->lk_status.counter_in++;
}

uint64_t rle_ctx_get_counter_in(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_in = 0L;

	ctr_packets_in = _this->lk_status.counter_in;

	return ctr_packets_in;
}

void rle_ctx_set_counter_ok(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_ok = val;
}

void rle_ctx_incr_counter_ok(struct rle_ctx_management *_this)
{
	_this->lk_status.counter_ok++;
}

uint64_t rle_ctx_get_counter_ok(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_ok = 0L;

	ctr_packets_ok = _this->lk_status.counter_ok;

	return ctr_packets_ok;
}

void rle_ctx_set_counter_dropped(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_dropped = val;
}

void rle_ctx_incr_counter_dropped(struct rle_ctx_management *_this)
{
	_this->lk_status.counter_dropped++;
}

uint64_t rle_ctx_get_counter_dropped(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_dropped = 0L;

	ctr_packets_dropped = _this->lk_status.counter_dropped;

	return ctr_packets_dropped;
}

void rle_ctx_set_counter_lost(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_lost = val;
}

void rle_ctx_incr_counter_lost(struct rle_ctx_management *_this, uint32_t val)
{
	_this->lk_status.counter_lost += val;
}

uint64_t rle_ctx_get_counter_lost(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_lost = 0L;

	ctr_packets_lost = _this->lk_status.counter_lost;

	return ctr_packets_lost;
}

void rle_ctx_set_counter_bytes_in(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_bytes_in = val;
}

void rle_ctx_incr_counter_bytes_in(struct rle_ctx_management *_this, uint32_t val)
{
	_this->lk_status.counter_bytes_in += val;
}

uint64_t rle_ctx_get_counter_bytes_in(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_bytes_in = 0L;

	ctr_packets_bytes_in = _this->lk_status.counter_bytes_in;

	return ctr_packets_bytes_in;
}

void rle_ctx_set_counter_bytes_ok(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_bytes_ok = val;
}

void rle_ctx_incr_counter_bytes_ok(struct rle_ctx_management *_this, uint32_t val)
{
	_this->lk_status.counter_bytes_ok += val;
}

uint64_t rle_ctx_get_counter_bytes_ok(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_bytes_ok = 0L;

	ctr_packets_bytes_ok = _this->lk_status.counter_bytes_ok;

	return ctr_packets_bytes_ok;
}

void rle_ctx_set_counter_bytes_dropped(struct rle_ctx_management *_this, uint64_t val)
{
	_this->lk_status.counter_bytes_dropped = val;
}

void rle_ctx_incr_counter_bytes_dropped(struct rle_ctx_management *_this, uint32_t val)
{
	_this->lk_status.counter_bytes_dropped += val;
}

uint64_t rle_ctx_get_counter_bytes_dropped(struct rle_ctx_management *_this)
{
	uint64_t ctr_packets_bytes_dropped = 0L;

	ctr_packets_bytes_dropped = _this->lk_status.counter_bytes_dropped;

	return ctr_packets_bytes_dropped;
}

static uint8_t check_ip_version(const void *const data_buffer)
{
	uint16_t ip_version = 0x0000;

	ip_version = ntohs(*((uint16_t *)(data_buffer)));
	ip_version >>= 12;

	return (uint8_t)ip_version;
}

void rle_ctx_dump(struct rle_ctx_management *_this, struct rle_configuration *rle_conf)
{
	/* get ptype compression status from NCC */
	int is_compressed = rle_conf_get_ptype_compression(rle_conf);
	int protocol_type = 0;
	char *i_ptr = NULL;

	/* just get the first bits of RLE packet */
	union rle_header_all *header = _this->buf;

	int i = 0;
	int j = 0;
	uint8_t data = 0;

	PRINT("\n-------------------DUMP RLE CTX-------------------\n");
	PRINT("\tfrag_id		\t\t= [0x%0x]\n", _this->frag_id);
	PRINT("\tnext_seq_nb		\t= [0x%0x]\n", _this->next_seq_nb);
	PRINT("\tis_fragmented		\t= [%d]\n", _this->is_fragmented);
	PRINT("\tfrag_counter		\t= [%d]\n", _this->frag_counter);
	PRINT("\tqos_tag		\t\t= [%d]\n", _this->qos_tag);
	PRINT("\tuse_crc		\t\t= [%d]\n", _this->use_crc);
	PRINT("\tpdu_length		\t= [%d] Bytes\n", _this->pdu_length);
	PRINT("\tremaining_pdu_length	\t= [%d] Bytes\n", _this->remaining_pdu_length);
	PRINT("\tlast rle_length	\t\t= [%d] Bytes\n", _this->rle_length);
	PRINT("\tproto_type		\t= [0x%0x]\n", _this->proto_type);
	PRINT("\tlabel_type		\t= [0x%0x]\n", _this->label_type);
	PRINT("\tend address		\t= [%p]\n", _this->end_address);
	PRINT("\tLink Status:\n");
	PRINT("\tPackets sent/received	\t= [%lu]\n", (long unsigned int)_this->lk_status.counter_ok);
	PRINT("\tPackets lost		\t= [%lu]\n", (long unsigned int)_this->lk_status.counter_lost);
	PRINT("\tPackets dropped	\t\t= [%lu]\n",
	      (long unsigned int)_this->lk_status.counter_dropped);
	PRINT("\tBytes sent/received	\t= [%lu]\n",
	      (long unsigned int)_this->lk_status.counter_bytes_ok);

	if (_this->frag_counter == 0) {
		PRINT("\n--------------------------------------------------\n");
		return;
	}

	if ((header->b.start_ind == 1) && (header->b.end_ind == 1)) {
		/* COMPLETE RLE packet */
		struct zc_rle_header_complete *zc_buf = (struct zc_rle_header_complete *)_this->buf;
		struct rle_header_complete *hdr = &zc_buf->header;
		size_t header_size = RLE_COMPLETE_HEADER_SIZE;
		uint8_t proto_type_supp = GET_PROTO_TYPE_SUPP(hdr->head.b.LT_T_FID);
		uint8_t label_type = GET_LABEL_TYPE(hdr->head.b.LT_T_FID);

		if ((proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
		    (label_type == RLE_LT_IMPLICIT_PROTO_TYPE)) {
			const uint8_t default_ptype = rle_conf_get_default_ptype(rle_conf);
			if (default_ptype == RLE_PROTO_TYPE_IP_COMP) {
				const uint8_t ip_version = check_ip_version(hdr + 1);
				if (ip_version == 4) {
					protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP;
				} else if (ip_version == 6) {
					protocol_type = RLE_PROTO_TYPE_IPV6_UNCOMP;
				}
			} else {
				protocol_type = rle_header_ptype_decompression(default_ptype);
			}
		} else if (label_type == RLE_LT_PROTO_SIGNAL) {
			protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
		}

		if (proto_type_supp != RLE_T_PROTO_TYPE_SUPP) {
			struct rle_header_complete_w_ptype *hdr_pt =
			        (struct rle_header_complete_w_ptype *)&zc_buf->header;
			if (is_compressed) {
				protocol_type = hdr_pt->ptype_c_s.c.proto_type;
				header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
			} else {
				protocol_type = ntohs(hdr_pt->ptype_u_s.proto_type);
				header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
			}
		}

		PRINT("--------- COMPLETE PACKET ------------\n");
		PRINT("| SE |  RLEPL   |  LT |  T  |  PTYPE  |\n");
		PRINT("| %d%d |   %zu   | 0x%0x | 0x%0x |  0x%04x |\n",
		      zc_buf->header.head.b.start_ind,
		      zc_buf->header.head.b.end_ind,
		      rle_header_all_get_packet_length(zc_buf->header.head),
		      label_type,
		      proto_type_supp,
		      protocol_type);

		if (header_size <= RLE_COMPLETE_HEADER_SIZE) {
			i_ptr = (char *)zc_buf->ptrs.start;
		} else {
			struct zc_rle_header_complete_w_ptype *zc_buf_tmp =
			        (struct zc_rle_header_complete_w_ptype *)_this->buf;
			i_ptr = (char *)zc_buf_tmp->ptrs.start;
		}

		PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
		for (i = 0; (char *)(i_ptr + i) < zc_buf->ptrs.end; i++) {
			data = (*(i_ptr + i));

			PRINT(" %02x ", data);
			if (j == 3) {
				PRINT("\n");
				j = 0;
			} else {
				j++;
			}
		}

		if (j != 0) {
			PRINT("\n");
		}
	} else {
		int start_bit = header->b.start_ind;
		int end_bit = header->b.end_ind;
		int use_crc = rle_conf_get_crc_check(rle_conf);

		/* to avoid seg fault while dumping
		 * erroneous fragments, we must
		 * compare each new last fragment address
		 * with ZC buffer end address */
		void *end_buffer_pointer =
		        (unsigned char *)((unsigned char *)_this->buf + ZC_BUFFER_MAX_SIZE);

		if ((start_bit == 0x1) && (end_bit == 0x0)) {
			/* dump START packet */
			struct zc_rle_header_start *zc_buf =
			        (struct zc_rle_header_start *)_this->buf;
			struct rle_header_start *hdr = &zc_buf->header;
			size_t header_size = RLE_START_MANDATORY_HEADER_SIZE;

			int m = 0;
			int n = 0;
			uint8_t data_mn = 0;

			void *ptr_to_next_frag = NULL;

			if ((hdr->head_start.b.proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
			    (hdr->head_start.b.label_type == RLE_LT_IMPLICIT_PROTO_TYPE)) {
				const uint8_t default_ptype = rle_conf_get_default_ptype(rle_conf);
				if (default_ptype == RLE_PROTO_TYPE_IP_COMP) {
					protocol_type = check_ip_version(hdr + 1);
				} else if (default_ptype ==
				           RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
					const uint8_t ip_version = check_ip_version(hdr + 1);
					if (ip_version == 4) {
						protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP;
					} else if (ip_version == 6) {
						protocol_type = RLE_PROTO_TYPE_IPV6_UNCOMP;
					}
				} else {
					protocol_type = rle_header_ptype_decompression(
					        default_ptype);
				}
			} else if (hdr->head_start.b.label_type == RLE_LT_PROTO_SIGNAL) {
				protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
			}

			if (hdr->head_start.b.proto_type_supp != RLE_T_PROTO_TYPE_SUPP) {
				struct rle_header_start_w_ptype *hdr_pt =
				        (struct rle_header_start_w_ptype *)&zc_buf->header;
				if (is_compressed) {
					protocol_type = hdr_pt->ptype_c_s.c.proto_type;
					header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
				} else {
					protocol_type = ntohs(hdr_pt->ptype_u_s.proto_type);
					header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
				}
			}

			if (header_size == RLE_START_MANDATORY_HEADER_SIZE) {
				i_ptr = (char *)zc_buf->ptrs.start;
#ifdef DEBUG
				PRINT("DEBUG ptrs start %p end %p i_ptr %p\n",
				      zc_buf->ptrs.start,
				      zc_buf->ptrs.end,
				      i_ptr);
#endif
			} else {
				struct zc_rle_header_start_w_ptype *zc_buf_tmp =
				        (struct zc_rle_header_start_w_ptype *)_this->buf;
				i_ptr = (char *)zc_buf_tmp->ptrs.start;
#ifdef DEBUG
				PRINT("DEBUG w_ptype ptrs start %p end %p i_ptr %p\n",
				      zc_buf_tmp->ptrs.start,
				      zc_buf_tmp->ptrs.end,
				      i_ptr);
#endif
			}

			PRINT("----------- START PACKET ------------\n");
			PRINT("| SE |  RLEPL |  ID |  TL   |  LT  |  T  |  PTYPE  |\n");
			PRINT("| %d%d |   %zu   | 0x%0x |  %zu  |  0x%0x | 0x%0x | 0x%04x  |\n",
			      zc_buf->header.head.b.start_ind,
			      zc_buf->header.head.b.end_ind,
			      rle_header_all_get_packet_length(zc_buf->header.head),
			      zc_buf->header.head.b.LT_T_FID,
			      rle_header_start_get_packet_length(zc_buf->header.head_start),
			      zc_buf->header.head_start.b.label_type,
			      zc_buf->header.head_start.b.proto_type_supp,
			      protocol_type);

			PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
			for (m = 0; (char *)(i_ptr + m) < zc_buf->ptrs.end; m++) {
				data_mn = (*(i_ptr + m));
				PRINT(" %02x ", data_mn);

				if (n == 3) {
					PRINT("\n");
					n = 0;
				} else {
					n++;
				}
			}

			if (n != 0) {
				PRINT("\n");
			}
#ifdef DEBUG
			/* DEBUG */

			PRINT("zc_buf->ptrs.end %p \n", zc_buf->ptrs.end);
#endif

			ptr_to_next_frag = &(zc_buf->ptrs.end);

			/* START packet is dumped,
			 * dump all others fragments */
			while ((end_bit != 1)) {
				/* update current address in RLE zc buffer */
				struct zc_rle_header_cont_end *zc_ce_buf =
				        (struct zc_rle_header_cont_end *)((void *)((unsigned char *)
				                                                   ptr_to_next_frag
				                                                   + 8));
				struct rle_header_cont_end *hdr_ce = NULL;

				int k = 0;
				int l = 0;
				uint8_t _data = 0;

				ptr_to_next_frag = &(zc_ce_buf->ptrs.end);

				/* We must stop dumping now cause
				 * we are going to dump
				 * beyond the buffer address space */
				if (ptr_to_next_frag >= end_buffer_pointer) {
					break;
				}

				hdr_ce = &zc_ce_buf->header;

				/* then dump CONTINUATION & END packet */
				if (hdr_ce->head.b.end_ind == 0x1) {
					PRINT("----------- END PACKET ------------\n");
				} else {
					PRINT("----------- CONT PACKET ------------\n");
				}
				PRINT("| SE |  RLEPL   |  ID  |\n");
				PRINT("| %d%d |   %zu     | 0x%0x  |\n",
				      zc_ce_buf->header.head.b.start_ind,
				      zc_ce_buf->header.head.b.end_ind,
				      rle_header_all_get_packet_length(zc_ce_buf->header.head),
				      zc_ce_buf->header.head.b.LT_T_FID);

				i_ptr = (char *)zc_ce_buf->ptrs.start;
#ifdef DEBUG
				PRINT("DEBUG ptrs start %p end %p i_ptr %p\n",
				      zc_ce_buf->ptrs.start,
				      zc_ce_buf->ptrs.end,
				      i_ptr);
#endif

				PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
				for (k = 0; (char *)(i_ptr + k) < zc_ce_buf->ptrs.end; k++) {
					_data = (*(i_ptr + k));

					PRINT(" %02x ", _data);

					if (l == 3) {
						PRINT("\n");
						l = 0;
					} else {
						l++;
					}
				}

				if (l != 0) {
					PRINT("\n");
				}

				if (hdr_ce->head.b.end_ind == 0x1) {
					struct rle_trailer *trl = NULL;

					/* print trailer */
					PRINT("----------- END TRAILER ------------\n");
					i_ptr = (char *)(&(zc_ce_buf->ptrs.end) + 1);
					trl = (struct rle_trailer *)i_ptr;

					if (!use_crc) {
						PRINT("\t SeqNo 0x%0x\n", trl->b.seq_no);
					} else {
						PRINT("\t CRC32 0x%0x\n", trl->crc);
					}
					PRINT("------------------------------------\n");
				}

				start_bit = hdr_ce->head.b.start_ind;
				end_bit = hdr_ce->head.b.end_ind;
#ifdef DEBUG
				PRINT("DEBUG start_bit %d end_bit %d start_ind %d end_ind %d\n",
				      start_bit, end_bit,
				      hdr_ce->head.b.start_ind, hdr_ce->head.b.end_ind);
#endif
			}
		}
	}

	PRINT("\n--------------------------------------------------\n");
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

uint8_t get_fragment_frag_id(const unsigned char *const buffer)
{
	uint8_t frag_id = 0;
	union rle_header_all *head = (union rle_header_all *)((void *)buffer);

	frag_id = (uint8_t)head->b.LT_T_FID;

	return frag_id;
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

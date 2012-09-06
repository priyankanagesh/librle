/**
 * @file   rle_ctx.c
 * @author Aurelien Castanie
 *
 * @brief  RLE transmitter functions
 *
 *
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rle_ctx.h"
#include "constants.h"
#include "zc_buffer.h"

#define MODULE_NAME "RLE_CTX"

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
	_this->frag_id			= 0xff;
	_this->next_seq_nb		= 0xff;
	_this->is_fragmented		= C_FALSE;
	_this->frag_counter		= 0;
	_this->nb_frag_pdu		= 0;
	_this->qos_tag			= 0xffffffff;
	_this->use_crc			= C_FALSE;
	_this->pdu_length		= 0;
	_this->remaining_pdu_length	= 0;
	_this->rle_length		= 0;
	_this->proto_type		= 0xffff;
	_this->label_type		= 0xff;
	_this->error_nb			= 0;
	_this->error_type		= 0;
	_this->pdu_buf			= NULL;
	_this->end_address		= NULL;
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
	/* TODO see for receiver buffer size */
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

	if (_this->buf) {
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

	/* set all buffer memory to zero */
	memset(_this->buf, 0, ZC_BUFFER_MAX_SIZE);
}

void rle_ctx_invalid_ctx(struct rle_ctx_management *_this)
{
	_this->is_fragmented		= C_FALSE;
	_this->frag_counter		= 0;
	_this->nb_frag_pdu		= 0;
	_this->qos_tag			= 0xffffffff;
	_this->use_crc			= C_FALSE;
	_this->pdu_length		= 0;
	_this->remaining_pdu_length	= 0;
	_this->rle_length		= 0;
	_this->proto_type		= 0xffff;
	_this->label_type		= 0xff;
	_this->error_nb			= 0;
	_this->error_type		= 0;
	_this->pdu_buf			= NULL;
	_this->end_address		= NULL;
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
	return(_this->frag_id);
}

void rle_ctx_set_seq_nb(struct rle_ctx_management *_this, uint8_t val)
{
	_this->next_seq_nb = val;
}

uint8_t rle_ctx_get_seq_nb(struct rle_ctx_management *_this)
{
	return(_this->next_seq_nb);
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
	return(_this->is_fragmented);
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
	return(_this->nb_frag_pdu);
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
	return(_this->use_crc);
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
	return(_this->pdu_length);
}

void rle_ctx_set_remaining_pdu_length(struct rle_ctx_management *_this, uint32_t val)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d val = %u\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__, val);
#endif

	if (val > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s:%s:%d: Invalid remaining RLE length [%d]\n",
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

	return(_this->remaining_pdu_length);
}

void rle_ctx_set_rle_length(struct rle_ctx_management *_this, uint32_t val)
{
	if (val > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s %s:%s:%d: Invalid RLE length [%d]\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__,
				val);
		return;
	}

	_this->rle_length = val;
}

void rle_ctx_set_proto_type(struct rle_ctx_management *_this, uint16_t val)
{
	_this->proto_type = val;
}

uint16_t rle_ctx_get_proto_type(struct rle_ctx_management *_this)
{
	return(_this->proto_type);
}


void rle_ctx_set_label_type(struct rle_ctx_management *_this, uint8_t val)
{
	if ((val != RLE_LT_IMPLICIT_PROTO_TYPE) && (val != RLE_LT_PROTO_SIGNAL)) {
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
	return(_this->label_type);
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
	return(_this->end_address);
}

union print_bytes {
	uint32_t all;
	struct {
		uint32_t B3:8;
		uint32_t B2:8;
		uint32_t B1:8;
		uint32_t B0:8;
	} B;
};

void rle_ctx_dump(struct rle_ctx_management *_this,
		struct rle_configuration *rle_conf)
{
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
	PRINT("\terror_nb		\t= [%d]\n", _this->error_nb);
	PRINT("\terror_type		\t= [%d]\n", _this->error_type);
	PRINT("\tend address		\t= [%p]\n", _this->end_address);

	/* RLE packet dump TODO CONT & END + TRL */

	/* get ptype compression status from NCC */
	int is_compressed = rle_conf_get_ptype_compression(rle_conf);
	int protocol_type = 0;
	int *i_ptr = NULL;

	if (!_this->is_fragmented) {
		/* COMPLETE RLE packet */
		struct zc_rle_header_complete *zc_buf = (struct zc_rle_header_complete *)_this->buf;
		struct rle_header_complete *hdr = &zc_buf->header;
		size_t header_size = RLE_COMPLETE_HEADER_SIZE;
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
				(struct rle_header_complete_w_ptype *)&zc_buf->header;
			if (is_compressed) {
				protocol_type = hdr_pt->ptype_c_s.proto_type;
				header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
			} else {
				protocol_type = ntohs(hdr_pt->ptype_u_s.proto_type);
				header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
			}
		}

		PRINT("| SE |  RLEPL  |  LT |  T  |  PTYPE |\n");
		PRINT("| %d%d |   %d   | 0x%0x | 0x%0x |  0x%0x  |\n",
				zc_buf->header.head.b.start_ind,
				zc_buf->header.head.b.end_ind,
				zc_buf->header.head.b.rle_packet_length,
				label_type,
				proto_type_supp,
				protocol_type);

		if (header_size <= RLE_COMPLETE_HEADER_SIZE) {
			i_ptr = (int *)zc_buf->ptrs.start;
		} else {
			struct zc_rle_header_complete_w_ptype *zc_buf_tmp =
				(struct zc_rle_header_complete_w_ptype *)_this->buf;
			i_ptr = (int *)zc_buf_tmp->ptrs.start;
		}

		int i = 0;
		union print_bytes data;

		PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
		for (i = 0; (char *)(i_ptr + i) < zc_buf->ptrs.end; i++) {
			data.all = ntohl(*(i_ptr +  i));
			PRINT("@ %p = %02x %02x %02x %02x \n", (uint32_t *)(i_ptr + i),
					data.B.B0, data.B.B1,
					data.B.B2, data.B.B3);
		}
	} else {
		union rle_header_all *header = _this->buf;
		int start_bit = header->b.start_ind;
		int end_bit = header->b.end_ind;
		int use_crc = rle_conf_get_crc_check(rle_conf);

		if ((start_bit == 0x1) && (end_bit == 0x0)) {
			/* dump START packet */
			struct zc_rle_header_start *zc_buf = (struct zc_rle_header_start *)_this->buf;
			struct rle_header_start *hdr = &zc_buf->header;
			size_t header_size = RLE_START_MANDATORY_HEADER_SIZE;

			if ((hdr->head_start.b.proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
					(hdr->head_start.b.label_type == RLE_LT_IMPLICIT_PROTO_TYPE)) {
				protocol_type = rle_conf_get_default_ptype(rle_conf);
			} else if (hdr->head_start.b.label_type == RLE_LT_PROTO_SIGNAL) {
				protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
			}

			if (hdr->head_start.b.proto_type_supp != RLE_T_PROTO_TYPE_SUPP) {
				struct rle_header_start_w_ptype *hdr_pt =
					(struct rle_header_start_w_ptype *)&zc_buf->header;
				if (is_compressed) {
					protocol_type = hdr_pt->ptype_c_s.proto_type;
					header_size += RLE_PROTO_TYPE_FIELD_SIZE_COMP;
				} else {
					protocol_type = ntohs(hdr_pt->ptype_u_s.proto_type);
					header_size += RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
				}
			}

			if (header_size == RLE_START_MANDATORY_HEADER_SIZE) {
				i_ptr = (int *)zc_buf->ptrs.start;
#ifdef DEBUG
				PRINT("DEBUG ptrs start %p end %p i_ptr %p\n",
						zc_buf->ptrs.start,
						zc_buf->ptrs.end,
						i_ptr);
#endif
			} else {
				struct zc_rle_header_start_w_ptype *zc_buf_tmp =
					(struct zc_rle_header_start_w_ptype *)_this->buf;
				i_ptr = (int *)zc_buf_tmp->ptrs.start;
#ifdef DEBUG
				PRINT("DEBUG w_ptype ptrs start %p end %p i_ptr %p\n",
						zc_buf_tmp->ptrs.start,
						zc_buf_tmp->ptrs.end,
						i_ptr);
#endif
			}


			PRINT("----------- START PACKET ------------\n");
			PRINT("| SE |  RLEPL |  ID |  TL   |  LT  |  T  |  PTYPE  |\n");
			PRINT("| %d%d |   %d   | 0x%0x |  %d  |  0x%0x | 0x%0x | 0x%0x    |\n",
					zc_buf->header.head.b.start_ind,
					zc_buf->header.head.b.end_ind,
					zc_buf->header.head.b.rle_packet_length,
					zc_buf->header.head.b.LT_T_FID,
					zc_buf->header.head_start.b.total_length,
					zc_buf->header.head_start.b.label_type,
					zc_buf->header.head_start.b.proto_type_supp,
					protocol_type);
			int i = 0;
			union print_bytes data;
			PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
			for (i = 0; (char *)(i_ptr + i) < zc_buf->ptrs.end; i++) {
				data.all = ntohl(*(i_ptr +  i));
				PRINT("@ %p = %02x %02x %02x %02x \n", (uint32_t *)(i_ptr + i),
						data.B.B0, data.B.B1,
						data.B.B2, data.B.B3);
			}

			void *ptr_to_next_frag = &(zc_buf->ptrs.end);

			/* START packet is dumped,
			 * dump all others fragments */
			while ((end_bit != 1)) {
				/* update current address in RLE zc buffer */
				struct zc_rle_header_cont_end *zc_ce_buf =
					(struct zc_rle_header_cont_end *)(ptr_to_next_frag + 8);

				ptr_to_next_frag = &(zc_ce_buf->ptrs.end);

				struct rle_header_cont_end *hdr = &zc_ce_buf->header;


				/* then dump CONTINUATION & END packet */
				if (hdr->head.b.end_ind == 0x1) {
					PRINT("----------- END PACKET ------------\n");
				} else {

					PRINT("----------- CONT PACKET ------------\n");
				}
				PRINT("| SE |  RLEPL   |  ID  |\n");
				PRINT("| %d%d |   %d     | 0x%0x  |\n",
						zc_ce_buf->header.head.b.start_ind,
						zc_ce_buf->header.head.b.end_ind,
						zc_ce_buf->header.head.b.rle_packet_length,
						zc_ce_buf->header.head.b.LT_T_FID);

				int i = 0;
				i_ptr = (int *)zc_ce_buf->ptrs.start;
				union print_bytes data;
#ifdef DEBUG
				PRINT("DEBUG ptrs start %p end %p i_ptr %p\n",
						zc_ce_buf->ptrs.start,
						zc_ce_buf->ptrs.end,
						i_ptr);
#endif


				PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
				for (i = 0; (char *)(i_ptr + i) < zc_ce_buf->ptrs.end; i++) {
					data.all = ntohl(*(i_ptr +  i));
					PRINT("@ %p = %02x %02x %02x %02x \n", (uint32_t *)(i_ptr + i),
							data.B.B0, data.B.B1,
							data.B.B2, data.B.B3);
				}

				if (hdr->head.b.end_ind == 0x1) {
					/* print trailer */
					PRINT("----------- END TRAILER ------------\n");
					i_ptr = (int *)(&(zc_ce_buf->ptrs.end) + SIZEOF_PTR);
					struct rle_trailer *trl = (struct rle_trailer *)i_ptr;

					if (!use_crc) {
						PRINT("\t SeqNo 0x%0x\n", trl->seq_no);
					} else {
						PRINT("\t CRC32 0x%0x\n", trl->crc);
					}
				}

				start_bit = hdr->head.b.start_ind;
				end_bit = hdr->head.b.end_ind;
#ifdef DEBUG
				PRINT("DEBUG start_bit %d end_bit %d start_ind %d end_ind %d\n",
						start_bit, end_bit,
						hdr->head.b.start_ind, hdr->head.b.end_ind);
#endif
			}
		}
	}

	PRINT("\n--------------------------------------------------\n");
}

#ifdef __KERNEL__
EXPORT_SYMBOL(rle_ctx_init);
EXPORT_SYMBOL(rle_ctx_destroy);
#endif

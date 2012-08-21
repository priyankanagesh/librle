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
	_this->end_address		= NULL;
}

/************************************************************************
 *									*
 * Public functions							*
 *									*
 ************************************************************************/
int rle_ctx_init(struct rle_ctx_management *_this)
{
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
		PRINT("ERROR %s:%s:%d: allocating ZC buffer failed [%s]\n",
				 __FILE__, __func__, __LINE__,
				strerror(errno));
		return C_ERROR;
	}

	/* set useful data end address pointing
	 * to the buffer start address */
	_this->end_address = (int *)_this->buf;

	/* set all buffer memory to zero */
	memset(_this->buf, 0, ZC_BUFFER_MAX_SIZE);

	return C_OK;
}

int rle_ctx_destroy(struct rle_ctx_management *_this)
{
	if (!_this) {
		PRINT("ERROR %s:%s:%d: RLE context is NULL\n",
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
	_this->end_address		= NULL;
}

void rle_ctx_set_frag_id(struct rle_ctx_management *_this, uint8_t val)
{
	if (val > RLE_MAX_FRAG_ID) {
		PRINT("ERROR %s:%s:%d: Invalid fragment id [%d]\n",
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
	if (val > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s:%s:%d: Invalid remaining RLE length [%d]\n",
				__FILE__, __func__, __LINE__, val);
		return;
	}

	_this->remaining_pdu_length = val;
}

uint32_t rle_ctx_get_remaining_pdu_length(struct rle_ctx_management *_this)
{
	return(_this->remaining_pdu_length);
}

void rle_ctx_set_rle_length(struct rle_ctx_management *_this, uint32_t val)
{
	if (val > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s:%s:%d: Invalid RLE length [%d]\n",
				__FILE__, __func__, __LINE__, val);
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
		PRINT("ERROR %s:%s:%d: Invalid Label_type value [%d]\n",
				__FILE__, __func__, __LINE__, val);
		return;
	}

	_this->label_type = val;
}

uint8_t rle_ctx_get_label_type(struct rle_ctx_management *_this)
{
	return(_this->label_type);
}

void rle_ctx_set_end_address(struct rle_ctx_management *_this, int *addr)
{
	if (!addr) {
		PRINT("ERROR %s:%s:%d: Useful data end address NULL\n",
				__FILE__, __func__, __LINE__);
		return;
	}

	_this->end_address = (int *)addr;
}

int *rle_ctx_get_end_address(struct rle_ctx_management *_this)
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

void rle_ctx_dump(struct rle_ctx_management *_this)
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
	struct zc_rle_header_complete *hdr = _this->buf;
	PRINT("| SE |  RLEPL  |  LT |  T  |  PTYPE |\n");
	PRINT("| %d%d |   %d   | 0x%0x | 0x%0x |  0x%0x  |\n",
			hdr->header.head.b.start_ind,
			hdr->header.head.b.end_ind,
			hdr->header.head.b.rle_packet_length,
			hdr->header.head.b.label_type,
			hdr->header.head.b.proto_type_supp,
			hdr->header.proto_type);
	int i = 0;
	int *i_ptr = hdr->ptrs.start;
	union print_bytes data;

	PRINT("|  \t\t  PAYLOAD  \t\t  |\n");
	for (i = 0; (i_ptr + i) < hdr->ptrs.end; i++) {
		data.all = ntohl(*(i_ptr +  i));
		PRINT("@ %p = %02x %02x %02x %02x \n", (uint32_t *)(i_ptr + i),
				data.B.B0, data.B.B1,
				data.B.B2, data.B.B3);
	}

	PRINT("\n@ start %p\n", hdr->ptrs.start);
	PRINT("@ end %p\n", hdr->ptrs.end);

	PRINT("\n--------------------------------------------------\n");
}

#ifdef __KERNEL__
EXPORT_SYMBOL(rle_ctx_init);
EXPORT_SYMBOL(rle_ctx_destroy);
#endif

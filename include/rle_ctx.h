/**
 * @file   rle_ctx.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE context and status structure, functions and variables
 *
 *
 */

#ifndef _RLE_CTX_H
#define _RLE_CTX_H

#include <stdint.h>

struct rle_ctx_management {
	/** specify fragment id the structure belongs to */
	uint8_t frag_id;
	/** next sequence number for frag_id */
	uint8_t next_seq_nb;
	/** PDU fragmentation status */
	int is_fragmented;
	/** current number of fragments present in queue */
	uint8_t frag_counter;
	/** specify PDU QoS tag */
	uint32_t qos_tag;
	/** CRC32 trailer usage status */
	int use_crc;
	/** size of received PDU or PDU to send */
	uint32_t pdu_length;
	/** size of remaining data to send or to receive */
	uint32_t remaining_pdu_length;
	/** size of last RLE packet/fragment received/sent */
	uint32_t rle_length;
	/** PDU protocol type */
	uint16_t proto_type;
	/** PDU Label type */
	uint8_t label_type;
	/** Buffer containing PDU refs and
	 * headers/trailer */
	void *buf;
	/** End address of last fragment
	 * constructed in buffer */
	int *end_address;
	/** number of errors drop PDU or fragments */
	int error_nb;
	/** specify error */
	int error_type;
};

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
int rle_ctx_init(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
int rle_ctx_destroy(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_invalid_ctx(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_frag_id(struct rle_ctx_management *_this, uint8_t val);

uint8_t rle_ctx_get_frag_id(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_seq_nb(struct rle_ctx_management *_this, uint8_t val);

uint8_t rle_ctx_get_seq_nb(struct rle_ctx_management *_this);

void rle_ctx_incr_seq_nb(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_is_fragmented(struct rle_ctx_management *_this, int val);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_frag_counter(struct rle_ctx_management *_this, uint8_t val);

void rle_ctx_incr_frag_counter(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_qos_tag(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_use_crc(struct rle_ctx_management *_this, int val);

int rle_ctx_get_use_crc(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_pdu_length(struct rle_ctx_management *_this, uint32_t val);

uint32_t rle_ctx_get_pdu_length(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_remaining_pdu_length(struct rle_ctx_management *_this, uint32_t val);

uint32_t rle_ctx_get_remaining_pdu_length(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_rle_length(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_proto_type(struct rle_ctx_management *_this, uint16_t val);

uint16_t rle_ctx_get_proto_type(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_label_type(struct rle_ctx_management *_this, uint8_t val);

uint8_t rle_ctx_get_label_type(struct rle_ctx_management *_this);

/**
 *  @brief
 *
 *  @warning
 *
 *  @param
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_end_address(struct rle_ctx_management *_this, int *addr);

int *rle_ctx_get_end_address(struct rle_ctx_management *_this);

void rle_ctx_dump(struct rle_ctx_management *_this);

#endif /* _RLE_CTX_H */

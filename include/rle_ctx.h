/**
 * @file   rle_ctx.h
 * @author Aurelien Castanie
 * @date   Mon Aug  6 09:27:35 CEST 2012
 *
 * @brief  Definition of RLE context and status structure, functions and variables
 *
 *
 */

#ifndef _RLE_CTX_H
#define _RLE_CTX_H

struct rle_ctx_management {
	/** specify fragment id the structure belongs to */
	uint8_t frag_id;
	/** next sequence number for frag_id */
	uint8_t next_seq_nb;
	/** PDU fragmentation status */
	bool is_fragmented;
	/** current number of fragments present in queue */
	uint8_t frag_counter;
	/** specify PDU QoS tag */
	uint32_t qos_tag;
	/** CRC32 trailer usage status */
	bool use_crc;
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
void rle_ctx_set_frag_id(struct rle_ctx_management *_this, uint8_t val);

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
void rle_ctx_set_is_fragmented(struct rle_ctx_management *_this, bool val);

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
void rle_ctx_set_use_crc(struct rle_ctx_management *_this, bool val);

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

#endif /* _RLE_CTX_H */

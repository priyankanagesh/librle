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

struct rle_buf_management {
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

#endif /* _RLE_CTX_H */

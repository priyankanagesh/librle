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
#include "rle_conf.h"

/** RLE context management structure */
struct rle_ctx_management {
	/** specify fragment id the structure belongs to */
	uint8_t frag_id;
	/** next sequence number for frag_id */
	uint8_t next_seq_nb;
	/** PDU fragmentation status */
	int is_fragmented;
	/** current number of fragments present in queue */
	uint8_t frag_counter;
	/** Fragment counter from the first START
	 * frag of a fragmented PDU */
	int nb_frag_pdu;
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
	/** Pointer to PDU buffer */
	void *pdu_buf;
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
 *  @brief	Initialize RLE context structure
 *
 *  @warning
 *
 *  @param	_this	Pointer to the RLE context structure
 *
 *  @return	C_ERROR	If initilization went wrong
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
int rle_ctx_init(struct rle_ctx_management *_this);

/**
 *  @brief	Destroy RLE context structure and free memory
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	C_ERROR If destruction went wrong
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
int rle_ctx_destroy(struct rle_ctx_management *_this);

/**
 *  @brief	Set all buffered data to zero
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_flush_buffer(struct rle_ctx_management *_this);

/**
 *  @brief	Set RLE context variables to invalid values
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_invalid_ctx(struct rle_ctx_management *_this);

/**
 *  @brief	Set fragment id
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New fragment id value
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_frag_id(struct rle_ctx_management *_this, uint8_t val);

/**
 *  @brief	Get current fragment id
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Fragment id
 *
 *  @ingroup
 */
uint8_t rle_ctx_get_frag_id(struct rle_ctx_management *_this);

/**
 *  @brief	Set sequence number
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New sequence number value
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_seq_nb(struct rle_ctx_management *_this, uint8_t val);

/**
 *  @brief	Get current sequence number
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Sequence number
 *
 *  @ingroup
 */
uint8_t rle_ctx_get_seq_nb(struct rle_ctx_management *_this);

/**
 *  @brief	Increment current sequence number
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_incr_seq_nb(struct rle_ctx_management *_this);

/**
 *  @brief	Set fragmentation status flag
 *
 *  @warning
 *
 *  @param	_this	Pointer to the RLE context structure
 *  @param	val	Boolean representing fragmentation status
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_is_fragmented(struct rle_ctx_management *_this, int val);

/**
 *  @brief	Get fragmentation status flag
 *
 *  @warning
 *
 *  @param	_this	Pointer to the RLE context structure
 *
 *  @return	Current fragmentation status flag
 *
 *  @ingroup
 */
int rle_ctx_get_is_fragmented(struct rle_ctx_management *_this);

/**
 *  @brief	Set fragment number counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New fragment number counter value
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_frag_counter(struct rle_ctx_management *_this, uint8_t val);

/**
 *  @brief	Increment current fragment counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_incr_frag_counter(struct rle_ctx_management *_this);

/**
 *  @brief	Set new PDU fragment counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New value of PDU fragment counter
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_nb_frag_pdu(struct rle_ctx_management *_this, int val);

/**
 *  @brief	Increment current PDU fragment counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_incr_nb_frag_pdu(struct rle_ctx_management *_this);

/**
 *  @brief	Get current PDU fragment counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current PDU fragment counter value
 *
 *  @ingroup
 */
int rle_ctx_get_nb_frag_pdu(struct rle_ctx_management *_this);

/**
 *  @brief	Set QoS tag for a specific RLE context
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New QoS tag value
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_qos_tag(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief	Set CRC usage flag for a specific RLE context
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New boolean value representing CRC usage
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_use_crc(struct rle_ctx_management *_this, int val);

/**
 *  @brief	Get current CRC usage flag
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	CRC usage boolean
 *
 *  @ingroup
 */
int rle_ctx_get_use_crc(struct rle_ctx_management *_this);

/**
 *  @brief	Set PDU length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New PDU length
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_pdu_length(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief	Get current PDU length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current PDU length
 *
 *  @ingroup
 */
uint32_t rle_ctx_get_pdu_length(struct rle_ctx_management *_this);

/**
 *  @brief	Set remaining PDU length to send or receive
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New remaining PDU length
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_remaining_pdu_length(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief	Get current remaining PDU length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current remaining PDU length
 *
 *  @ingroup
 */
uint32_t rle_ctx_get_remaining_pdu_length(struct rle_ctx_management *_this);

/**
 *  @brief	Set RLE packet length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val     New RLE packet length
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_rle_length(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief	Set Protocol Type value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New Protocol Type value
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_proto_type(struct rle_ctx_management *_this, uint16_t val);

/**
 *  @brief	Get Protocol Type value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current Protocol Type value
 *
 *  @ingroup
 */
uint16_t rle_ctx_get_proto_type(struct rle_ctx_management *_this);

/**
 *  @brief	Set Label Type value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *		val	New Label Type value
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_label_type(struct rle_ctx_management *_this, uint8_t val);

/**
 *  @brief	Get current Label Type value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current Label Type value
 *
 *  @ingroup
 */
uint8_t rle_ctx_get_label_type(struct rle_ctx_management *_this);

/**
 *  @brief	Set buffer useful data end address
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	addr	Pointer to the last data added in buffer
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_set_end_address(struct rle_ctx_management *_this, int *addr);

/**
 *  @brief	Get current buffer useful data end address
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Pointer to the last data added in buffer
 *
 *  @ingroup
 */
int *rle_ctx_get_end_address(struct rle_ctx_management *_this);

/**
 *  @brief	Dump & print to stdout the content of a specific RLE context
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return
 *
 *  @ingroup
 */
void rle_ctx_dump(struct rle_ctx_management *_this,
		struct rle_configuration *rle_conf);

#endif /* _RLE_CTX_H */

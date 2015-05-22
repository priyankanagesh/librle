/**
 * @file   rle_ctx.h
 * @brief  Definition of RLE context and status structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __RLE_CTX_H__
#define __RLE_CTX_H__

#include <stdint.h>
#include <pthread.h>
#include "rle_conf.h"

/** RLE link status counters
 * and associated mutexes */
struct link_status {
	/** Number of packets sent/received
	 * successfully */
	uint64_t counter_ok;
	pthread_mutex_t ctr_ok_mutex;
	/** Number of dropped packets */
	uint64_t counter_dropped;
	pthread_mutex_t ctr_dropped_mutex;
	/** Number of lost packets */
	uint64_t counter_lost;
	pthread_mutex_t ctr_lost_mutex;
	/** Number of bytes sent/received */
	uint64_t counter_bytes;
	pthread_mutex_t ctr_bytes_mutex;
};

/** RLE context management structure */
struct rle_ctx_management {
	/** specify fragment id the structure belongs to */
	uint8_t frag_id;
	/** next sequence number for frag_id */
	uint8_t next_seq_nb;
	/** PDU fragmentation status */
	int is_fragmented;
	/** current number of fragments present in queue */
	uint16_t frag_counter;
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
	/** size of the ALPDU fragmented/to fragment */
	uint32_t alpdu_size;
	/** remaining ALPDU size to send/receive */
	uint32_t remaining_alpdu_size;
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
	char *end_address;
	/** Type of link TX or RX */
	int lk_type;
	/** Fragmentation context status */
	struct link_status lk_status;
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
 *  @brief	Increment by one current sequence number
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
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
 *  @ingroup
 */
void rle_ctx_set_frag_counter(struct rle_ctx_management *_this, uint8_t val);

/**
 *  @brief	Increment by one current fragment counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
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
 *  @ingroup
 */
void rle_ctx_set_nb_frag_pdu(struct rle_ctx_management *_this, int val);

/**
 *  @brief	Increment by one current PDU fragment counter
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
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
 *  @param	_this       Pointer to the RLE context structure
 *  @param	val         New RLE packet length
 *  @param	header_size The RLE Header size
 *
 *  @ingroup
 */
void rle_ctx_set_rle_length(struct rle_ctx_management *_this, uint32_t val,
                            const size_t header_size);

/**
 *  @brief	Get RLE packet length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current RLE packet length
 *
 *  @ingroup
 */
uint32_t rle_ctx_get_rle_length(struct rle_ctx_management *_this);

/**
 *  @brief	Set ALPDU length
 *
 *  @warning
 *
 *  @param	_this       Pointer to the RLE context structure
 *  @param	val         New ALPDU length
 *
 *  @ingroup
 */
void rle_ctx_set_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val);

/**
 *  @brief	increment ALPDU length
 *
 *  @warning
 *
 *  @param	_this       Pointer to the RLE context structure
 *  @param	val         ALPDU length incremented of val
 *
 *  @ingroup
 */
void rle_ctx_incr_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val);

/**
 *  @brief	Get ALPDU length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current ALPDU length
 *
 *  @ingroup
 */
uint32_t rle_ctx_get_alpdu_length(const struct rle_ctx_management *const _this);


/**
 *  @brief	Set remaining ALPDU length
 *
 *  @warning
 *
 *  @param	_this       Pointer to the RLE context structure
 *  @param	val         New remaining ALPDU length
 *
 *  @ingroup
 */
void rle_ctx_set_remaining_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val);

/**
 *  @brief	decrement remaining ALPDU length
 *
 *  @warning
 *
 *  @param	_this       Pointer to the RLE context structure
 *  @param	val         remaining ALPDU length decremented of val
 *
 *  @ingroup
 */
void rle_ctx_decr_remaining_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val);

/**
 *  @brief	Get remaining ALPDU length
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Current remaining ALPDU length
 *
 *  @ingroup
 */
uint32_t rle_ctx_get_remaining_alpdu_length(const struct rle_ctx_management *const _this);

/**
 *  @brief	Set Protocol Type value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New Protocol Type value
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
 *  @ingroup
 */
void rle_ctx_set_end_address(struct rle_ctx_management *_this, char *addr);

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
char *rle_ctx_get_end_address(struct rle_ctx_management *_this);

/**
 *  @brief	Set PDU successfully transmitted/received counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New counter value
 *
 *  @ingroup
 */
void rle_ctx_set_counter_ok(struct rle_ctx_management *_this, uint64_t val);

/**
 *  @brief	Increment by one number of PDU successfully transmitted/received
 *		counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @ingroup
 */
void rle_ctx_incr_counter_ok(struct rle_ctx_management *_this);

/**
 *  @brief	Get current counter value for PDU successfully transmitted/received
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	PDU successfully transmitted/received counter value
 *
 *  @ingroup
 */
uint64_t rle_ctx_get_counter_ok(struct rle_ctx_management *_this);

/**
 *  @brief	Set dropped PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New counter value
 *
 *  @ingroup
 */
void rle_ctx_set_counter_dropped(struct rle_ctx_management *_this, uint64_t val);

/**
 *  @brief	Increment by one dropped PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @ingroup
 */
void rle_ctx_incr_counter_dropped(struct rle_ctx_management *_this);

/**
 *  @brief	Get current dropped PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Dropped PDU counter value
 *
 *  @ingroup
 */
uint64_t rle_ctx_get_counter_dropped(struct rle_ctx_management *_this);

/**
 *  @brief	Set lost PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New counter value
 *
 *  @ingroup
 */
void rle_ctx_set_counter_lost(struct rle_ctx_management *_this, uint64_t val);

/**
 *  @brief	Increment by one lost PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @ingroup
 */
void rle_ctx_incr_counter_lost(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief	Get current lost PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Lost PDU counter value
 *
 *  @ingroup
 */
uint64_t rle_ctx_get_counter_lost(struct rle_ctx_management *_this);

/**
 *  @brief	Set successfully sent/received number of Bytes
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	New counter value
 *
 *  @ingroup
 */
void rle_ctx_set_counter_bytes(struct rle_ctx_management *_this, uint64_t val);

/**
 *  @brief	Increment by given value lost PDU counter value
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *  @param	val	Number of Bytes to add to the current Bytes counter
 *
 *  @ingroup
 */
void rle_ctx_incr_counter_bytes(struct rle_ctx_management *_this, uint32_t val);

/**
 *  @brief	Get current number of sent/received Bytes
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @return	Number of sent/received Bytes
 *
 *  @ingroup
 */
uint64_t rle_ctx_get_counter_bytes(struct rle_ctx_management *_this);

/**
 *  @brief	Dump & print to stdout the content of a specific RLE context
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE context structure
 *
 *  @ingroup
 */
void rle_ctx_dump(struct rle_ctx_management *_this, struct rle_configuration *rle_conf);

/**
 *  @brief         Dump an ALPDU from a context in a buffer.
 *
 *                 This is intended to help testing encapsulation only. Please don't use this after
 *                 fragmentation and take care if you want to use it in another way.
 *
 *  @param[in]     protocol_type       The theorical protocol_type in the context.
 *                                     (You can use rle_ctx_get_proto_type)
 *                                     For now, this param is useful, but it can evolve in the
 *                                     future.
 *  @param[in]     _this               The RLE context
 *  @param[in]     rle_conf            The RLE configuration
 *  @param[in,out] alpdu_buffer        A preallocated buffer that will contain the ALPDU.
 *  @param[in]     alpdu_buffer_size   The size of the preallocated buffer
 *  @param[out]    alpdu_length        The size of the ALPDU
 */
void rle_ctx_dump_alpdu(const uint16_t protocol_type, const struct rle_ctx_management *const _this,
                        struct rle_configuration *const rle_conf, unsigned char alpdu_buffer[],
                        const size_t alpdu_buffer_size,
                        size_t *const alpdu_length);

/** Status for the fragmentation checking */
enum check_frag_status {
	FRAG_STATUS_OK, /**< Fragementation is ok. */
	FRAG_STATUS_KO  /**< Error case.           */
};


/** States of fragmentation */
enum frag_states {
	FRAG_STATE_START, /**< Fragementation is in starting state   */
	FRAG_STATE_CONT,  /**< Fragementation is in continuing state */
	FRAG_STATE_END,   /**< Fragementation is in ending state     */
	FRAG_STATE_COMP   /**< No fragmentation */
};

/**
 *  @brief         Check if a fragmentation transition is OK.
 *
 *  @param[in]     current_state       The current state.
 *  @param[in]     next_state          The future state.
 *
 *  @return        FRAG_STATUS_OK if legal transition, else FRAG_STATUS_KO.
 */
enum check_frag_status check_frag_transition(const enum frag_states current_state,
                                             const enum frag_states next_state);

/**
 *  @brief         Check the fragmentation integrity
 *
 *  @param[in]     _this               The context with the buffer to check.
 *
 *  @return        FRAG_STATUS_OK if fragmentation in OK, else FRAG_STATUS_KO.
 */
enum check_frag_status rle_ctx_check_frag_integrity(const struct rle_ctx_management *const _this);

/**
 *  @brief         Get the type of the fragment in the buffer
 *
 *  @param[in]     buffer              The buffer
 *
 *  @return        the fragment type @see enum frag_states
 */
enum frag_states get_fragment_type(const unsigned char *const buffer);

/**
 *  @brief         Get the length of the fragment in the buffer
 *
 *  @param[in]     buffer              The buffer
 *
 *  @return        the fragment type @see enum frag_states
 */
size_t get_fragment_length(const unsigned char *const buffer);

/**
 *  @brief         Get the fragment id of the fragment in the buffer
 *
 *  @param[in]     buffer              The buffer
 *
 *  @return        the fragment id of the fragment
 */
uint8_t get_fragment_frag_id(const unsigned char *const buffer);

/**
 *  @brief         Set the packet length of a given RLE Header for CONT, END or COMP.
 *
 *  @param[in,out] header              The RLE header
 *  @param[in]     length              The packet length
 */
void rle_header_all_set_packet_length(union rle_header_all *const header, const size_t length);

/**
 *  @brief         Get the packet length of a given RLE Header for CONT, END or COMP.
 *
 *  @param[in]     header              The RLE header
 *
 *  @return        the packet length
 */
size_t rle_header_all_get_packet_length(const union rle_header_all header);

/**
 *  @brief         Set the packet length of a given RLE Header for START.
 *
 *  @param[in,out] header              The RLE header
 *  @param[in]     length              The packet length
 */
void rle_header_start_set_packet_length(union rle_header_start_packet *const header,
                                        const size_t length);

/**
 *  @brief         Get the packet length of a given RLE Header for START.
 *
 *  @param[in]     header              The RLE header
 *
 *  @return        the packet length
 */
size_t rle_header_start_get_packet_length(const union rle_header_start_packet header);

#endif /* __RLE_CTX_H__ */

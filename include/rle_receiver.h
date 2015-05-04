/**
 * @file   rle_receiver.h
 * @brief  Definition of RLE receiver context and status structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __RLE_RECEIVER_H__
#define __RLE_RECEIVER_H__

#include <stddef.h>
#include <pthread.h>
#include "rle_ctx.h"
#include "header.h"

/**
 * RLE receiver module used
 * for reassembly & deencapsulation.
 * Provides a context structure for each
 * fragment_id.
 */
struct rle_receiver {
	struct rle_ctx_management rle_ctx_man[RLE_MAX_FRAG_NUMBER];
	struct rle_configuration *rle_conf[RLE_MAX_FRAG_NUMBER];
	pthread_mutex_t ctx_mutex;
	uint8_t free_ctx;
};

/**
 *  @brief Create a RLE receiver module
 *
 *  @warning
 *
 *  @return Pointer to the receiver module
 *
 *  @ingroup
 */
struct rle_receiver *rle_receiver_module_new(void);

/**
 *  @brief Initialize a RLE receiver module
 *
 *  @warning
 *
 *  @param _this	The receiver module to initialize
 *
 *  @ingroup
 */
void rle_receiver_module_init(struct rle_receiver *_this);

/**
 *  @brief Destroy a RLE receiver module
 *
 *  @warning
 *
 *  @param _this	The receiver module to destroy
 *
 *  @ingroup
 */
void rle_receiver_module_destroy(struct rle_receiver *_this);

/**
 *  @brief Deencapsulate RLE fragment from a buffer
 *		and bufferize/reassemble it while waiting for remaining data
 *		to be received
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param data_buffer	Data buffer's address to deencapsulate
 *  @param data_length	Data length to deencapsulate
 *  @param index_ctx		The index of the context
 *
 *  @return	C_ERROR		if error occured while reassembling PDU
 *		C_ERROR_TOO_MUCH_FRAG	if the PDU was too fragmented (> 256 fragments)
 *		C_REASSEMBLY_OK	if PDU is completely reassembled
 *		C_OK		if deencapsulation and reassembly is successfull
 *
 *  @ingroup
 */
int rle_receiver_deencap_data(struct rle_receiver *_this, void *data_buffer, size_t data_length, int * index_ctx);

/**
 *  @brief Retrieve reassembled PDU data and copy it
 *		to a buffer
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param fragment_id	Fragmentation context to use to get the PDU
 *  @param pdu_buffer	Destination of reassembled PDU
 *  @param pdu_proto_type	Reassembled PDU protocol type
 *  @param pdu_length	Reassembled PDU length
 *
 *  @return	C_ERROR		if error occured while retrieving PDU
 *		C_ERROR_BUF	if given buffer (PDU, protocol type or PDU length) is invalid
 *		C_OK		otherwise
 *
 *  @ingroup
 */
int rle_receiver_get_packet(struct rle_receiver *_this, uint8_t fragment_id, void *pdu_buffer,
                            int *pdu_proto_type,
                            uint32_t *pdu_length);
/**
 *  @brief Set to idle the fragment context
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param fragment_id	Fragmentation context to use to get the PDU
 *
 *  @ingroup
 */
void rle_receiver_free_context(struct rle_receiver *_this, uint8_t fragment_id);

/**
 *  @brief Get total number of successfully
 *  sent/received packets
 *
 *  @warning
 *
 *  @param _this		The receiver module
 *
 *  @return	Number of packets sent/received successfully
 *
 *  @ingroup
 */
uint64_t rle_receiver_get_counter_ok(struct rle_receiver *_this);

/**
 *  @brief Get total number of dropped packets
 *
 *  @warning
 *
 *  @param _this		The receiver module
 *
 *  @return	Number of dropped packets
 *
 *  @ingroup
 */
uint64_t rle_receiver_get_counter_dropped(struct rle_receiver *_this);

/**
 *  @brief Get total number of lost packets
 *
 *  @warning
 *
 *  @param _this		The receiver module
 *
 *  @return	Number of lost packets
 *
 *  @ingroup
 */
uint64_t rle_receiver_get_counter_lost(struct rle_receiver *_this);

/**
 *  @brief Get total number of sent/received Bytes
 *
 *  @warning
 *
 *  @param _this		The receiver module
 *
 *  @return	Number of Bytes sent/received
 *
 *  @ingroup
 */
uint64_t rle_receiver_get_counter_bytes(struct rle_receiver *_this);

/**
 *  @brief Dump an RLE receiver
 *
 *  @warning
 *
 *  @param _this		The receiver module
 *
 *  @ingroup
 */
void rle_receiver_dump(struct rle_receiver *_this);

/**
 *  @brief Get the length of the ALPDU protection mechanism, knowing the receiver and a buffer.
 *
 * The buffer must be an end PPDU, but this function  will also work on cont and comp PPDU. The
 * buffer is needed to get the fragment id, in order to extract the current configuration.
 *
 *  @warning
 *
 *  @param _this     The receiver module
 *  @param buffer    The buffer, an End PPDU
 *
 *  @return	Number of octets in the ALPDU protection mechanism.
 *
 *  @ingroup
 */
size_t rle_receiver_get_alpdu_protection_length(const struct rle_receiver *const _this,
                                                const unsigned char *const buffer);

#endif /* __RLE_RECEIVER_H__ */

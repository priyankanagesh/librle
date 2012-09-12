/**
 * @file   rle_receiver.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE receiver context and status structure, functions and variables
 *
 *
 */

#ifndef _RLE_RECEIVER_H
#define _RLE_RECEIVER_H

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
struct receiver_module {
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
 *  @param
 *
 *  @return Pointer to the receiver module
 *
 *  @ingroup
 */
struct receiver_module *rle_receiver_new(void);

/**
 *  @brief Initialize a RLE receiver module
 *
 *  @warning
 *
 *  @param _this	The receiver module to initialize
 *
 *  @return
 *
 *  @ingroup
 */
void rle_receiver_init(struct receiver_module *_this);

/**
 *  @brief Destroy a RLE receiver module
 *
 *  @warning
 *
 *  @param _this	The receiver module to destroy
 *
 *  @return
 *
 *  @ingroup
 */
void rle_receiver_destroy(struct receiver_module *_this);

/**
 *  @brief Deencapsulate data from an RLE packet
 *
 *  @warning
 *
 *  @param _this	The receiver module to use for deencapsulation
 *  @param data_buffer	Data buffer's address to deencapsulate
 *  @param data_length	Data length to deencapsulate
 *
 *  @return
 *
 *  @ingroup
 */
int rle_receiver_get_packet(struct receiver_module *_this,
			uint8_t fragment_id,
			void *pdu_buffer,
			int *pdu_proto_type,
			uint32_t *pdu_length);


void rle_receiver_dump(struct receiver_module *_this);

#endif /* _RLE_RECEIVER_H */

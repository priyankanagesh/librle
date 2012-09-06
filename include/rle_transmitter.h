/**
 * @file   rle_transmitter.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE transmitter context and status structure, functions and variables
 *
 *
 */

#ifndef _RLE_TRANSMITTER_H
#define _RLE_TRANSMITTER_H

#include <stddef.h>
#include <pthread.h>
#include "rle_ctx.h"
#include "header.h"

/**
 * RLE transmitter module used
 * for encapsulation & fragmentation.
 * Provides a context structure for each
 * fragment_id, with a list of contexts
 * free to use and with a configuration
 * structure.
 * A mutex is used for synchronize
 * access to free contexts.
 *
 */
struct transmitter_module {
	struct rle_ctx_management rle_ctx_man[RLE_MAX_FRAG_NUMBER];
	struct rle_configuration *rle_conf;
	pthread_mutex_t ctx_mutex;
	uint8_t free_ctx;
};

/**
 *  @brief Create a RLE transmitter module
 *
 *  @warning
 *
 *  @param
 *
 *  @return Pointer to the transmitter module
 *
 *  @ingroup
 */
struct transmitter_module *rle_transmitter_new(void);

/**
 *  @brief Initialize a RLE transmitter module
 *
 *  @warning
 *
 *  @param _this	The transmitter module to initialize
 *
 *  @return
 *
 *  @ingroup
 */
void rle_transmitter_init(struct transmitter_module *_this);

/**
 *  @brief Destroy a RLE transmitter module
 *
 *  @warning
 *
 *  @param _this	The transmitter module to destroy
 *
 *  @return
 *
 *  @ingroup
 */
void rle_transmitter_destroy(struct transmitter_module *_this);

/**
 *  @brief Encapsulate data into an RLE packet
 *
 *  @warning
 *
 *  @param _this	The transmitter module to use for encapsulation
 *  @param data_buffer	Data buffer's address to encapsulate
 *  @param data_length	Data length to encapsulate
 *
 *  @return
 *
 *  @ingroup
 */
int rle_transmitter_encap_data(struct transmitter_module *_this,
				void *data_buffer, size_t data_length,
				uint16_t protocol_type);

/**
 *  @brief Fill burst payload with an RLE packet
 *
 *  @warning
 *
 *  @param _this		The transmitter module to use for encapsulation
 *  @param burst_buffer		Burst buffer's address to fill
 *  @param burst_length		Burst length available
 *  @param fragment_id		Fragment id to use
 *  @param protocol_type	Protocol type to use in proto_type field
 *
 *  @return
 *
 *  @ingroup
 */
int rle_transmitter_get_packet(struct transmitter_module *_this,
		void *burst_buffer,
		size_t burst_length,
		uint8_t fragment_id,
		uint16_t protocol_type);

/**
 *  @brief Get a queue (frag_id) state, filled or empty
 *
 *  @warning
 *
 *  @param _this		The transmitter module
 *  @param fragment_id		Fragment id to use
 *
 *  @return	C_TRUE if the queue is empty
 *		C_FALSE if the queue is full or has remaining PDU data
 *
 *  @ingroup
 */
int rle_transmitter_get_queue_state(struct transmitter_module *_this,
		uint8_t fragment_id);

/**
 *  @brief Get occupied size of a queue (frag_id)
 *
 *  @warning
 *
 *  @param _this		The transmitter module
 *  @param fragment_id		Fragment id to use
 *
 *  @return	Number of Bytes present in a queue
 *
 *  @ingroup
 */
uint32_t rle_transmitter_get_queue_size(struct transmitter_module *_this,
		uint8_t fragment_id);

/**
 *  @brief Dump all frag_id contents
 *
 *  @warning
 *
 *  @param _this		The transmitter module
 *
 *  @ingroup
 */
void rle_transmitter_dump(struct transmitter_module *_this);

#endif /* _RLE_TRANSMITTER_H */

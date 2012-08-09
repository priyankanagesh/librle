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

#include "rle_ctx.h"

/**
 * RLE transmitter module used
 * for encapsulation & fragmentation.
 * Provides a context structure for each
 * fragment_id.
 */
struct transmitter_module {
	struct rle_ctx_management rle_ctx_man[RLE_MAX_FRAG_NUMBER];
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
void rle_transmitter_encap_data(struct transmitter_module *_this,
				void *data_buffer, size_t data_length);

#endif /* _RLE_TRANSMITTER_H */

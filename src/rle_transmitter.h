/**
 * @file   rle_transmitter.h
 * @brief  Definition of RLE transmitter context and status structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __RLE_TRANSMITTER_H__
#define __RLE_TRANSMITTER_H__

#ifndef __KERNEL__

#include <stddef.h>

#else

#include <linux/stddef.h>

#endif

#include "rle_ctx.h"
#include "header.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** RLE transmitter link status
 * holds the sum of all statistics
 * of each fragment_id */
struct transmitter_link_status {
	/** Total number of packets sent/received
	 * successfully */
	uint64_t counter_ok;
	/** Total number of dropped packets */
	uint64_t counter_dropped;
	/** Total number of lost packets */
	uint64_t counter_lost;
	/** Total number of bytes sent/received */
	uint64_t counter_bytes;
};

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
struct rle_transmitter {
	struct rle_ctx_management rle_ctx_man[RLE_MAX_FRAG_NUMBER];
	struct rle_configuration *rle_conf;
	uint8_t free_ctx;
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief Encapsulate data into an RLE packet.
 *
 * @param[in,out] _this    The transmitter module to use for encapsulation.
 * @param[in]     sdu      The SDU to encapsulate.
 * @param[in]     frag_id  The fragment ID.
 *
 * @return  C_ERROR enable_crc_check is an invalid flag
 *          C_OK    Otherwise
 *
 * @ingroup
 */
int rle_transmitter_encap_data(struct rle_transmitter *_this, const struct rle_sdu *const sdu,
                               uint8_t frag_id);

/**
 * @brief Set to idle the fragment context
 *
 * @param[in,out] _this        The transmitter module to use for deencapsulation
 * @param[in]     fragment_id  Fragmentation context to use to get the PDU
 *
 * @ingroup
 */
void rle_transmitter_free_context(struct rle_transmitter *const _this, const uint8_t fragment_id);


#endif /* __RLE_TRANSMITTER_H__ */

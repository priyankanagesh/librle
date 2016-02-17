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

#ifndef __KERNEL__

#include <stdint.h>
#include <stdbool.h>

#else

#include <linux/types.h>

#endif

#include "rle_conf.h"
#include "constants.h"
#include "fragmentation_buffer.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC MACROS AND CONSTANTS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Status for the fragmentation checking */
enum check_frag_status {
	FRAG_STATUS_OK, /**< Fragementation is ok. */
	FRAG_STATUS_KO  /**< Error case.           */
};

/** States of fragmentation */
enum frag_states {
	FRAG_STATE_UNINIT, /**< Fragmentation not started */
	FRAG_STATE_START,  /**< Fragmentation is in starting state   */
	FRAG_STATE_CONT,   /**< Fragmentation is in continuing state */
	FRAG_STATE_END,    /**< Fragmentation is in ending state     */
	FRAG_STATE_COMP    /**< No fragmentation */
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** RLE link status counters */
struct link_status {
	/** Number of SDUs received (partially received) for transmission (reception) */
	uint64_t counter_in;
	/** Number of SDUs sent/received successfully */
	uint64_t counter_ok;
	/** Number of dropped SDUs */
	uint64_t counter_dropped;
	/** Number of lost SDUs */
	uint64_t counter_lost;
	/** Number of bytes received (partially received) for transmission (reception) */
	uint64_t counter_bytes_in;
	/** Number of bytes of transmitted/received SDUs */
	uint64_t counter_bytes_ok;
	/** Number of bytes dropped */
	uint64_t counter_bytes_dropped;
};

/** RLE context management structure */
struct rle_ctx_management {
	/** specify fragment id the structure belongs to */
	uint8_t frag_id;
	/** next sequence number for frag_id */
	uint8_t next_seq_nb;
	/** CRC32 trailer usage status */
	int use_crc;
	/** Fragmentation/Reassembly buffer. */
	void *buff;
	/** Current octets counter. */
	size_t current_counter;
	/** Type of link TX or RX */
	int lk_type;
	/** Fragmentation context status */
	struct link_status lk_status;
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief  Initialize RLE context structure with fragmentation buffers.
 *
 * @param[out]    _this  Pointer to the RLE context structure
 *
 * @return  C_ERROR  If initilization went wrong
 *          C_OK     Otherwise
 *
 * @ingroup RLE context
 */
int rle_ctx_init_f_buff(struct rle_ctx_management *_this);

/**
 * @brief  Initialize RLE context structure with reassembly buffers.
 *
 * @param[out]    _this  Pointer to the RLE context structure
 *
 * @return  C_ERROR  If initilization went wrong
 *          C_OK     Otherwise
 *
 * @ingroup RLE context
 */
int rle_ctx_init_r_buff(struct rle_ctx_management *_this);

/**
 * @brief  Destroy RLE context with fragmentation buffers structure and free memory
 *
 * @param[out]   _this  Pointer to the RLE context structure
 *
 * @return  C_ERROR  If destruction went wrong
 *          C_OK     Otherwise
 *
 * @ingroup RLE context
 */
int rle_ctx_destroy_f_buff(struct rle_ctx_management *_this);

/**
 * @brief  Destroy RLE context with reassembly buffers structure and free memory
 *
 * @param[out]   _this  Pointer to the RLE context structure
 *
 * @return  C_ERROR  If destruction went wrong
 *          C_OK     Otherwise
 *
 * @ingroup RLE context
 */
int rle_ctx_destroy_r_buff(struct rle_ctx_management *_this);

/**
 * @brief  Set fragment id
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val     New fragment id value
 *
 * @ingroup RLE context
 */
void rle_ctx_set_frag_id(struct rle_ctx_management *const _this, const uint8_t val);

/**
 * @brief  Set sequence number
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val     New sequence number value
 *
 * @ingroup RLE context
 */
void rle_ctx_set_seq_nb(struct rle_ctx_management *const _this, const uint8_t val);

/**
 * @brief  Get current sequence number
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Sequence number
 *
 * @ingroup RLE context
 */
uint8_t rle_ctx_get_seq_nb(const struct rle_ctx_management *const _this);

/**
 * @brief  Increment by one current sequence number
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
void rle_ctx_incr_seq_nb(struct rle_ctx_management *const _this);

/**
 * @brief  Set CRC usage flag for a specific RLE context
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val     New boolean value representing CRC usage
 *
 * @ingroup RLE context
 */
void rle_ctx_set_use_crc(struct rle_ctx_management *const _this, const int val);

/**
 * @brief  Get current CRC usage flag
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  CRC usage boolean
 *
 * @ingroup RLE context
 */
int rle_ctx_get_use_crc(const struct rle_ctx_management *const _this);

/**
 * @brief  Get RLE packet length
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Current RLE packet length
 *
 * @ingroup RLE context
 */
uint32_t rle_ctx_get_rle_length(struct rle_ctx_management *const _this);

/**
 * @brief  increment ALPDU length
 *
 * @param[in,out] _this       Pointer to the RLE context structure
 * @param[in]     val         ALPDU length incremented of val
 *
 * @ingroup RLE context
 */
void rle_ctx_incr_alpdu_length(struct rle_ctx_management *const _this, const uint32_t val);

/**
 * @brief  Get ALPDU length
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Current ALPDU length
 *
 * @ingroup RLE context
 */
uint32_t rle_ctx_get_alpdu_length(const struct rle_ctx_management *const _this);

/**
 * @brief  decrement remaining ALPDU length
 *
 * @param[in,out] _this       Pointer to the RLE context structure
 * @param[in]     val         remaining ALPDU length decremented of val
 *
 * @ingroup RLE context
 */
void rle_ctx_decr_remaining_alpdu_length(struct rle_ctx_management *const _this,
                                         const uint32_t val);

/**
 * @brief  Get remaining ALPDU length
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Current remaining ALPDU length
 *
 * @ingroup RLE context
 */
uint32_t rle_ctx_get_remaining_alpdu_length(const struct rle_ctx_management *const _this);

/**
 * @brief  Get Protocol Type value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Current Protocol Type value
 *
 * @ingroup RLE context
 */
uint16_t rle_ctx_get_proto_type(struct rle_ctx_management *const _this);

/**
 * @brief  Set Label Type value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * 	val    New Label Type value
 *
 * @ingroup RLE context
 */

/**
 * @brief  Set the number of SDUs received (partially received) for transmission (reception)
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_in(struct rle_ctx_management *const _this,
                                          const uint64_t val)
{
	_this->lk_status.counter_in = val;

	return;
}


/**
 * @brief  Reset the number of SDUs received (partially received) for transmission (reception)
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_in(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_in(_this, 0L);

	return;
}


/**
 * @brief  Increment by one number of SDUs received (partially received) for transmission
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_in(struct rle_ctx_management *const _this)
{
	_this->lk_status.counter_in++;

	return;
}


/**
 * @brief  Get current counter value for SDU to be transmitted/received
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  SDU to be transmitted/received counter value
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_in(const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_in;
}


/**
 * @brief  Set SDU successfully transmitted/received counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_ok(struct rle_ctx_management *const _this,
                                          const uint64_t val)
{
	_this->lk_status.counter_ok = val;

	return;
}


/**
 * @brief  Reset SDU successfully transmitted/received counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_ok(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_ok(_this, 0L);

	return;
}


/**
 * @brief  Increment by one number of SDU successfully transmitted/received
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_ok(struct rle_ctx_management *const _this)
{
	_this->lk_status.counter_ok++;

	return;
}


/**
 * @brief  Get current counter value for SDU successfully transmitted/received
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  SDU successfully transmitted/received counter value
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_ok(const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_ok;
}


/**
 * @brief  Set dropped SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_dropped(struct rle_ctx_management *const _this,
                                               const uint64_t val)
{
	_this->lk_status.counter_dropped = val;

	return;
}


/**
 * @brief  Reset dropped SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_dropped(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_dropped(_this, 0L);

	return;
}


/**
 * @brief  Increment by one dropped SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_dropped(struct rle_ctx_management *const _this)
{
	_this->lk_status.counter_dropped++;

	return;
}


/**
 * @brief  Get current dropped SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Dropped SDU counter value
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_dropped(const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_dropped;
}


/**
 * @brief  Set lost SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_lost(struct rle_ctx_management *const _this,
                                            const uint64_t val)
{
	_this->lk_status.counter_lost = val;

	return;
}


/**
 * @brief  Reset lost SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_lost(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_lost(_this, 0L);

	return;
}


/**
 * @brief  Increment by one lost SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_lost(struct rle_ctx_management *const _this,
                                             const uint64_t val)
{
	_this->lk_status.counter_lost += val;

	return;
}


/**
 * @brief  Get current lost SDU counter value
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Lost SDU counter value
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_lost(const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_lost;
}


/**
 * @brief  Set to be sent/partially received SDUs bytes
 *
 * @param[in,out] _this  Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_bytes_in(struct rle_ctx_management *const _this,
                                                const uint64_t val)
{
	_this->lk_status.counter_bytes_in = val;

	return;
}


/**
 * @brief  Reset to be sent/partially received SDUs bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_bytes_in(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_bytes_in(_this, 0L);

	return;
}


/**
 * @brief  Increment by given value to be sent/partially received SDUs bytes
 *
 * @param[in,out] _this  Pointer to the RLE context structure
 * @param[in]     val    Number of bytes to add to the to be sent/partially received SDUs bytes
 *                       counter
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_bytes_in(struct rle_ctx_management *const _this,
                                                 const uint64_t val)
{
	_this->lk_status.counter_bytes_in += val;

	return;
}


/**
 * @brief  Get current number of to be sent/partially received SDUs bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Number of to be sent/partilly received SDUs Bytes
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_bytes_in(const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_bytes_in;
}


/**
 * @brief  Set successfully sent/received number of bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_bytes_ok(struct rle_ctx_management *const _this,
                                                const uint64_t val)
{
	_this->lk_status.counter_bytes_ok = val;

	return;
}


/**
 * @brief  Reset successfully sent/received number of bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_bytes_ok(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_bytes_ok(_this, 0L);

	return;
}


/**
 * @brief  Increment by given value sent/received bytes
 *
 * @param[in,out] _this  Pointer to the RLE context structure
 * @param[in]     val    Number of Bytes to add to the current bytes counter
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_bytes_ok(struct rle_ctx_management *const _this,
                                                 const uint64_t val)
{
	_this->lk_status.counter_bytes_ok += val;

	return;
}


/**
 * @brief  Get current number of sent/partially received SDUs bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Number of sent/partilly received SDUs Bytes
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_bytes_ok(const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_bytes_ok;
}


/**
 * @brief  Set successfully sent/received number of Bytes
 *
 * @param[in,out] _this  Pointer to the RLE context structure
 * @param[in]     val    New counter value
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_set_counter_bytes_dropped(struct rle_ctx_management *const _this,
                                                     const uint64_t val)
{
	_this->lk_status.counter_bytes_dropped = val;

	return;
}


/**
 * @brief  Reset successfully sent/received number of Bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counter_bytes_dropped(struct rle_ctx_management *const _this)
{
	rle_ctx_set_counter_bytes_dropped(_this, 0L);

	return;
}


/**
 * @brief  Increment by given value dropped bytes counter
 *
 * @param[in,out] _this  Pointer to the RLE context structure
 * @param[in]     val    Number of bytes to add to the current dropped bytes counter
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_incr_counter_bytes_dropped(struct rle_ctx_management *const _this,
                                                      const uint64_t val)
{
	_this->lk_status.counter_bytes_dropped += val;

	return;
}


/**
 * @brief  Get current number of dropped SDUs bytes
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @return  Number of to be dropped SDUs Bytes
 *
 * @ingroup RLE context
 */
static inline uint64_t rle_ctx_get_counter_bytes_dropped(
        const struct rle_ctx_management *const _this)
{
	return _this->lk_status.counter_bytes_dropped;
}


/**
 * @brief  Reset all counters
 *
 * @param[in,out] _this   Pointer to the RLE context structure
 *
 * @ingroup RLE context
 */
static inline void rle_ctx_reset_counters(struct rle_ctx_management *const _this)
{
	rle_ctx_reset_counter_in(_this);
	rle_ctx_reset_counter_ok(_this);
	rle_ctx_reset_counter_dropped(_this);
	rle_ctx_reset_counter_lost(_this);
	rle_ctx_reset_counter_bytes_in(_this);
	rle_ctx_reset_counter_bytes_ok(_this);
	rle_ctx_reset_counter_bytes_dropped(_this);

	return;
}

/**
 * @brief         Get the length of the fragment in the buffer
 *
 * @param[in]     buffer              The buffer
 *
 * @return        the fragment type @see enum frag_states
 */
size_t get_fragment_length(const unsigned char *const buffer);

/**
 * @brief         Get the state of the frag_id-nth context.
 *
 * @param[in]     contexts              The contexts
 * @param[in]     frag_id               The frag_id of the context checked
 *
 * @return        false if the context is in use, else true if free.
 */
static inline int rle_ctx_is_free(uint8_t contexts, const size_t frag_id)
{
	int context_is_free = false;

	if (((contexts >> frag_id) & 0x1) == 0) {
		context_is_free = true;
	}

	return context_is_free;
}

/**
 * @brief         Set the state of the frag_id-nth context to NON FREE.
 *
 * @param[in]     contexts              The contexts
 * @param[in]     frag_id               The frag_id of the context to be set
 */
static inline void rle_ctx_set_nonfree(uint8_t *const contexts, const size_t frag_id)
{
	*contexts |= (1 << frag_id);

	return;
}

/**
 * @brief         Set the state of the frag_id-nth context to FREE.
 *
 * @param[in]     contexts              The contexts
 * @param[in]     frag_id               The frag_id of the context to be set
 */
static inline void rle_ctx_set_free(uint8_t *const contexts, const size_t frag_id)
{
	*contexts &= ~(1 << frag_id);

	return;
}

#endif /* __RLE_CTX_H__ */

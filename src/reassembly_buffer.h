/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file   reassembly_buffer.h
 * @brief  Definition of the reassembly buffer.
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __REASSEMBLY_BUFFER_H__
#define __REASSEMBLY_BUFFER_H__

#include "rle.h"

#include "constants.h"

#ifndef __KERNEL__
#	include <assert.h>
#endif



/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Maximum size for a reassembly buffer. */
#define RLE_R_BUFF_LEN ((2 << 12) - 1)
#define MODULE_ID RLE_MOD_ID_REASSEMBLY_BUFFER


/*------------------------------------------------------------------------------------------------*/
/*------------------------------- PROTECTED STRUCTS AND TYPEDEFS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * Reassembly buffer pointers.
 * Used to delimitate a portion of the reassembly buffer.
 *
 * ··· +-+-+-+-+ ···
 *     | | | | |
 * ··· +-+-+-+-+ ···
 *      ^     ^
 *      |     |
 *    start  end
 */
struct reassembly_buffer_ptrs;

/** Reassembly buffer pointers definition. */
typedef struct reassembly_buffer_ptrs rasm_buf_ptrs_t;

/**
 * Reassembly buffer.
 * Used to stock received SDU fragments it a full SDU.
 * The buffer itself is given by the library caller, by the decapsulation function.
 *
 * Init:
 *
 *                     MAX
 *                     SDU
 *  <--------------------------------->
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *  ^
 *  |
 *  ptrs
 *
 * In use:
 *
 * +-+-+···+-+-+-+···+-+-+-+···+-+-+-+···+-+-+
 * |r|r|   |r|f|f|   |f|/|/|   |/|X|X|   |X|X|
 * +-+-+···+-+-+-+···+-+-+-+···+-+-+-+···+-+-+
 *  ^         ^         ^         ^
 *  |         |         |         |
 * start   cur frag  cur frag    end
 *  ptr    start ptr  end ptr    ptr
 *
 */
struct rle_reassembly_buffer;

/** Reassembly buffer definition. */
typedef struct rle_reassembly_buffer rle_rasm_buf_t;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Reassembly buffer pointers implementation. */
struct reassembly_buffer_ptrs {
	rle_rasm_buf_t *rasm_buf; /** Pointed reassembly buffer. */
	unsigned char *start; /** Start pointer.             */
	unsigned char *end;   /** End pointer.               */
};

/** Reassembly buffer implementation. */
struct rle_reassembly_buffer {
	unsigned char *buffer;                /** Buffer. Given by the library caller.               */
	struct rle_sdu sdu_info;              /** RLE SDU struct used without buffer to store infos. */
	uint8_t comp_protocol_type;           /**< The compressed protocol type found in ALPDU */
	rasm_buf_ptrs_t sdu;                    /** SDU after copying it.                              */
	rasm_buf_ptrs_t sdu_frag;               /** Current SDU fragment.                              */
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief         Set the start and end pointers of a reassembly buffer pointers to an arbitraly
 *                choosen value (bound in the reassembly buffer).
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *          ^
 *          | <-----X
 *          |     ptr start
 *          | <---------------X
 *       address           ptr end
 *
 * @param[in,out] ptrs                     The reassembly buffer pointers.
 * @param[in]     address                  The arbitraly choosen address.
 *
 * @ingroup       RLE Reassembly buffer pointers.
 */
static void rasm_buf_ptrs_set(rasm_buf_ptrs_t *const ptrs, unsigned char *const address);

/**
 * @brief         Increment the end pointer in the reassembly buffer.
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *        ^                   ^
 *        |         X-------> |
 *     ptr start           ptr end
 *
 * @param[in,out] ptrs                     The reassembly buffer pointers.
 * @param[in]     size                     The size to put.
 *
 * @ingroup       RLE Reassembly buffer pointers.
 */
static void rasm_buf_ptrs_put(rasm_buf_ptrs_t *const ptrs, const size_t size);

/**
 * @brief         Put the SDU pointers.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 * @param[in]     size                     The size to put.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline void rasm_buf_sdu_put(rle_rasm_buf_t *const rasm_buf, const size_t size);

/**
 * @brief         Put the SDU fragment pointers. Automatically used by the copying function.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 * @param[in]     size                     The size to put.
 *
 * @ingroup       RLE Reassembly buffer.
 */
void rasm_buf_sdu_frag_put(rle_rasm_buf_t *const rasm_buf, const size_t size);

/**
 * @brief         Create a new reassembly buffer.
 *
 * @return        The reassembly buffer if OK, else NULL.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline rle_rasm_buf_t *rasm_buf_new(void);

/**
 * @brief         Destroy a reassembly buffer.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer to destroy.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline void rasm_buf_del(rle_rasm_buf_t **const rasm_buf);

/**
 * @brief         Initialize (eventually reinitialize) a reassembly buffer.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer to (re)initialize.
 * @param[in,out] sdu                      the SDU structure, containing the buffer that will be
 *                                         used to store the reassembled SDU.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline void rasm_buf_init(rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Check if the reassembly buffer is in use.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer to check.
 *
 * @return        0 if not in use, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int rasm_buf_in_use(const rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Copy a fragment of SDU in a reassembly buffer.
 *
 * @param[in,out] rasm_buf  The reassembly buffer
 * @param[in]     sdu_frag  The SDU to copy
 *
 * @ingroup       RLE Reassembly buffer.
 */
void rasm_buf_cpy_sdu_frag(rle_rasm_buf_t *const rasm_buf,
                           const unsigned char sdu_frag[]);

/**
 * @brief         Get the length of the SDU in the reassembly buffer (reassembled or not).
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 *
 * @return        The total length of the SDU.
 *
 * @ingroup       RLE Reassembly buffer.
 */
size_t rasm_buf_get_sdu_length(const rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Get the length of SDU currently reassembled.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 *
 * @return        The currently reassembled SDU length.
 *
 * @ingroup       RLE Reassembly buffer.
 */
size_t rasm_buf_get_reassembled_sdu_length(const rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Dump memory from the reassembly buffer.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 * @param[in]     start                    The start of the dump.
 * @param[in]     end                      The end of the dump.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int rasm_buf_dump_mem(const rle_rasm_buf_t *const rasm_buf,
                                    const unsigned char *const start,
                                    const unsigned char *const end);

/**
 * @brief         Dump the SDU from the reassembly buffer.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int rasm_buf_dump_sdu(const rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Dump the currently reassembled SDU from the reassembly buffer.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int rasm_buf_dump_reassembled_sdu(const rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Dump the reassembly buffer fully.
 *
 * @param[in,out] rasm_buf                   The reassembly buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int rasm_buf_dump_full_rasm_buf(const rle_rasm_buf_t *const rasm_buf);

/**
 * @brief         Check if the reassembly buffer is fully reassembled.
 *
 * @param[in]     rasm_buf                   The reassembly buffer.
 *
 * @return        0 if not reassembled, 1 if reassembled.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int rasm_buf_is_reassembled(const rle_rasm_buf_t *const rasm_buf);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static void rasm_buf_ptrs_set(rasm_buf_ptrs_t *const ptrs, unsigned char *const address)
{
	assert(address >= ptrs->rasm_buf->buffer &&
	       address < (ptrs->rasm_buf->buffer + RLE_R_BUFF_LEN));

	ptrs->start = ptrs->end = address;

}

static void rasm_buf_ptrs_put(rasm_buf_ptrs_t *const ptrs, const size_t size)
{
	const ptrdiff_t offset = (ptrs->rasm_buf->buffer + RLE_R_BUFF_LEN) - ptrs->end;

	assert(size <= (size_t)offset);

	ptrs->end += size;
}

static inline void rasm_buf_sdu_put(rle_rasm_buf_t *const rasm_buf, const size_t size)
{
	rasm_buf_ptrs_put(&rasm_buf->sdu, size);
}

static inline void rasm_buf_init_sdu_frag(rle_rasm_buf_t *const rasm_buf)
{
	rasm_buf_ptrs_set(&rasm_buf->sdu_frag, rasm_buf->sdu_frag.end);
}

static inline rle_rasm_buf_t *rasm_buf_new(void)
{
	rle_rasm_buf_t *rasm_buf = (rle_rasm_buf_t *)MALLOC(sizeof(rle_rasm_buf_t));

	if (!rasm_buf) {
		PRINT_RLE_ERROR("reassembly buffer not allocated.");
		goto error;
	}

	rasm_buf->buffer = (unsigned char *)MALLOC(RLE_R_BUFF_LEN);
	if (!rasm_buf->buffer) {
		PRINT_RLE_ERROR("reassembly buffer not allocated (2)");
		goto free_rasm_buf;
	}
	rasm_buf->sdu_info.buffer = rasm_buf->buffer;
	rasm_buf->sdu.rasm_buf = rasm_buf;
	rasm_buf->sdu_frag.rasm_buf = rasm_buf;

	return rasm_buf;

free_rasm_buf:
	FREE(rasm_buf);
error:
	return NULL;
}

static inline void rasm_buf_del(rle_rasm_buf_t **const rasm_buf)
{
	assert(rasm_buf != NULL);
	assert((*rasm_buf) != NULL);

	if ((*rasm_buf)->sdu_info.buffer) {
		FREE((*rasm_buf)->sdu_info.buffer);
		(*rasm_buf)->sdu_info.buffer = NULL;
	}

	FREE(*rasm_buf);
	*rasm_buf = NULL;
}

static inline void rasm_buf_init(rle_rasm_buf_t *const rasm_buf)
{
	rasm_buf->buffer = rasm_buf->sdu_info.buffer;

	memset(rasm_buf->buffer, '\0', RLE_R_BUFF_LEN);

	rasm_buf_ptrs_set(&rasm_buf->sdu, rasm_buf->buffer);
	rasm_buf_ptrs_set(&rasm_buf->sdu_frag, rasm_buf->buffer);
}

static inline int rasm_buf_in_use(const rle_rasm_buf_t *const rasm_buf)
{
	return rasm_buf->sdu.start != rasm_buf->sdu.end;
}

static inline int rasm_buf_dump_mem(const rle_rasm_buf_t *const rasm_buf,
                                    const unsigned char *const start,
                                    const unsigned char *const end)
{
	const unsigned char *b = start;

	if (!rasm_buf_in_use(rasm_buf)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	if ((start < rasm_buf->buffer) || (end > (rasm_buf->buffer + sizeof(rasm_buf->buffer)))) {
		PRINT_RLE_ERROR("address out of buffer ([%p - %p]/[%p - %p]).", start, end,
		                rasm_buf->buffer,
		                rasm_buf->buffer + sizeof(rasm_buf->buffer));
		goto out;
	}

	if (end < start) {
		PRINT_RLE_ERROR("start after end (%p/%p)", start, end);
		goto out;
	}

	for (; b < end; ++b) {
		PRINT_RLE_DEBUG("%02x", *b);
	}

out:

	return (int)(end - start);
}

static inline int rasm_buf_dump_sdu(const rle_rasm_buf_t *const rasm_buf)
{
	int status = -1;
	int ret;

	if (!rasm_buf_in_use(rasm_buf)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	ret = rasm_buf_dump_mem(rasm_buf, rasm_buf->sdu.start, rasm_buf->sdu.end);

	if (ret != -1) {
		goto out;
	}

	PRINT_RLE_DEBUG("%d-octets SDU dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int rasm_buf_dump_reassembled_sdu(const rle_rasm_buf_t *const rasm_buf)
{
	int status = -1;
	int ret;

	if (!rasm_buf_in_use(rasm_buf)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	ret = rasm_buf_dump_mem(rasm_buf, rasm_buf->sdu.start, rasm_buf->sdu_frag.end);

	if (ret != -1) {
		goto out;
	}

	PRINT_RLE_DEBUG("%d-octets reassembled SDU dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int rasm_buf_dump_full_rasm_buf(const rle_rasm_buf_t *const rasm_buf)
{
	int status = -1;
	int ret;

	if (!rasm_buf_in_use(rasm_buf)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	ret =
	        rasm_buf_dump_mem(rasm_buf, rasm_buf->buffer, rasm_buf->buffer +
	                          sizeof(rasm_buf->buffer));

	if (ret != -1) {
		goto out;
	}

	PRINT_RLE_DEBUG("%d-octets reassembly buffer dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int rasm_buf_is_reassembled(const rle_rasm_buf_t *const rasm_buf)
{
	int is_reassembled = 0;

	if (!rasm_buf_in_use(rasm_buf)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	is_reassembled = rasm_buf->sdu.end > rasm_buf->sdu_frag.end ? 1 : 0;

out:
	return is_reassembled;
}

/* undef the module id set at start of file */
#undef MODULE_ID

#endif /* __REASSEMBLY_BUFFER_H__ */

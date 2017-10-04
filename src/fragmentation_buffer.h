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
 * @file   fragmentation_buffer.h
 * @brief  Definition of the fragmentation buffer.
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __FRAGMENTATION_BUFFER_H__
#define __FRAGMENTATION_BUFFER_H__

#include "rle.h"

#include "constants.h"
#include "header.h"
#include "trailer.h"


/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/
#define MODULE_ID RLE_MOD_ID_FRAGMENTATION_BUFFER

/** Maximum size for a fragmentation buffer. */
#define RLE_F_BUFF_LEN \
	(sizeof(rle_ppdu_hdr_t) + sizeof(rle_alpdu_hdr_t) + \
	 (RLE_MAX_PDU_SIZE) + sizeof(rle_alpdu_trailer_t))


/*------------------------------------------------------------------------------------------------*/
/*------------------------------- PROTECTED STRUCTS AND TYPEDEFS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * Fragmentation buffer pointers.
 * Used to delimitate a portion of the fragmentation buffer, such as a PPDU.
 *
 * ··· +-+-+-+-+ ···
 *     | | | | |
 * ··· +-+-+-+-+ ···
 *      ^     ^
 *      |     |
 *    start  end
 */
struct fragmentation_buffer_ptrs;

/** Fragmentation buffer pointers definition. */
typedef struct fragmentation_buffer_ptrs frag_buf_ptrs_t;

/**
 * Fragmentation buffer.
 * Used to stock an SDU, encapsulate it in ALPDU and fragment it in PPDU.
 *
 * Init:
 *
 *   MAX     MAX       MAX        MAX
 *   PPDU    ALPDU     SDU        ALPDU
 *   HDR     HDR                  TRL
 *  <-----> <-----> <---------> <----->
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *                  ^
 *                  |
 *                 ptrs
 *
 * In use:
 * +-+-···-+-+-+-···-+-+-+-···-+-+-+-···-+-+-+-···-+-+-+-···-+-+
 * |/|     |/|p|     |p|a|     |a|s|     |s|a|     |a|/|     |/|
 * +-+-···-+-+-+-···-+-+-+-···-+-+-+-···-+-+-+-···-+-+-+-···-+-+
 *            ^         ^         ^         ^         ^
 *            |         |         |         |         |
 *          start     start     start      end       end alpdu
 *          ppdu      alpdu      sdu       sdu       end ppdu
 *
 */
struct rle_frag_buf;

/** Fragmentation buffer definition. */
typedef struct rle_frag_buf rle_frag_buf_t;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Fragmentation buffer pointers implementation. */
struct fragmentation_buffer_ptrs {
	rle_frag_buf_t *frag_buf; /** Pointed fragmentation buffer. */
	unsigned char *start; /** Start pointer.                */
	unsigned char *end;   /** End pointer.                  */
};

/** Fragmentation buffer implementation. */
struct rle_frag_buf {
	unsigned char buffer[RLE_F_BUFF_LEN]; /** Buffer itself.                                     */
	unsigned char *cur_pos;               /** Current position.                                  */
	struct rle_sdu sdu_info;              /** RLE SDU struct used without buffer to store infos. */
	uint32_t crc;                         /**< The computed CRC if needed */
	frag_buf_ptrs_t sdu;                  /** SDU after copying it.                              */
	frag_buf_ptrs_t alpdu;                /** ALPDU after encapsulation.                         */
	frag_buf_ptrs_t ppdu;                 /** PPDU after each fragmentation.                     */
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/


/**
 * @brief         Set the start and end pointers of a fragmentation buffer pointers to an arbitraly
 *                choosen value (bound in the fragmentation buffer).
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *                  ^
 *        X-------> | <-------X
 *               ptr start
 *               ptr end
 *
 * @param[in,out] ptrs                     The fragmentation buffer pointers.
 * @param[in]     address                  The arbitraly choosen address.
 *
 * @ingroup       RLE Fragmentation buffer pointers.
 */
static void frag_buf_ptrs_set(frag_buf_ptrs_t *const ptrs, unsigned char *const address);

/**
 * @brief         Decrement the start pointer in the fragmentation buffer.
 *
 *
 * If size is positive:
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *        ^                   ^
 *        | <-------X         |
 *     ptr start           ptr end
 *
 *
 * If size is negative:
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *                  ^         ^
 *        X-------> |         |
 *               ptr start ptr end
 *
 * @param[in,out] ptrs                     The fragmentation buffer pointers.
 * @param[in]     size                     The size to push, may be negative
 *
 * @ingroup       RLE Fragmentation buffer pointers.
 */
static void frag_buf_ptrs_push(frag_buf_ptrs_t *const ptrs, const ssize_t size);

/**
 * @brief         Increment the end pointer in the fragmentation buffer.
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *        ^                   ^
 *        |         X-------> |
 *     ptr start           ptr end
 *
 * @param[in,out] ptrs                     The fragmentation buffer pointers.
 * @param[in]     size                     The size to put.
 *
 * @ingroup       RLE Fragmentation buffer pointers.
 */
static void frag_buf_ptrs_put(frag_buf_ptrs_t *const ptrs, const size_t size);

/**
 * @brief         Push the SDU, ALPDU and PPDU pointers.
 *
 * @param[in,out] frag_buf  The fragmentation buffer.
 * @param[in]     size      The size to pull.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
void frag_buf_sdu_push(rle_frag_buf_t *const frag_buf, const ssize_t size);

/**
 * @brief         Put the SDU, ALPDU and PPDU pointers.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 * @param[in]     size                     The size to pull.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline void frag_buf_sdu_put(rle_frag_buf_t *const frag_buf, const size_t size);

/**
 * @brief         Push the ALPDU and PPDU pointers.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 * @param[in]     size                     The size to push.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline void frag_buf_alpdu_push(rle_frag_buf_t *const frag_buf, const size_t size);

/**
 * @brief         Put the ALPDU pointers.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 * @param[in]     size                     The size to put.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline void frag_buf_alpdu_put(rle_frag_buf_t *const frag_buf, const size_t size);

/**
 * @brief         Push the PPDU pointers.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 * @param[in]     size                     The size to push.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline void frag_buf_ppdu_push(rle_frag_buf_t *const frag_buf, const size_t size);

/**
 * @brief         Set the PPDU pointers to the old ending position, with the current position.
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *                  X-------->^
 *        X------------------>|
 *    ptr start  cur pos   ptr end
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline void frag_buf_ppdu_init(rle_frag_buf_t *const frag_buf);

/**
 * @brief         Put the PPDU pointers.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 * @param[in]     size                     The size to put. Bounded to the ALPDU.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
void frag_buf_ppdu_put(rle_frag_buf_t *const frag_buf, const size_t size);

/**
 * @brief         Set the current position in the buffer depending on the last PPDU start.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline void frag_buf_set_cur_pos(rle_frag_buf_t *const frag_buf);

/**
 * @brief         Check if the fragmentation buffer is in use.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer to check.
 *
 * @return        0 if not in use, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_in_use(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Get the length of the SDU in the fragmentation buffer.
 *
 * @param  frag_buf   The fragmentation buffer.
 * @return            The SDU length
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline ssize_t frag_buf_get_sdu_len(const rle_frag_buf_t *const frag_buf)
__attribute__((warn_unused_result, nonnull(1)));

/**
 * @brief         Get the length of the ALPDU header in the fragmentation buffer.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline ssize_t frag_buf_get_alpdu_hdr_len(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Get the length of the ALPDU trailer in the fragmentation buffer.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline ssize_t frag_buf_get_alpdu_trailer_len(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Dump memory from the fragmentation buffer.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 * @param[in]     start                    The start of the dump.
 * @param[in]     end                      The end of the dump.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_dump_mem(const rle_frag_buf_t *const frag_buf,
                                    const unsigned char *const start,
                                    const unsigned char *const end);

/**
 * @brief         Dump the PPDU header from the fragmentation buffer
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_dump_ppdu_header(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Dump the ALPDU header from the fragmentation buffer
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_dump_alpdu_header(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Dump the SDU from the fragmentation buffer
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_dump_sdu(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Dump the ALPDU trailer from the fragmentation buffer
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_dump_alpdu_trailer(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Dump the fragmentation buffer fully.
 *
 * @param[in,out] frag_buf                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_dump_full_frag_buf(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Check if the fragmentation buffer fully is fragmented.
 *
 * @param[in]     frag_buf                   The fragmentation buffer.
 *
 * @return        0 if not fragmented, 1 if fragmented.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int frag_buf_is_fragmented(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Return the remaining ALPDU size in the fragmentation buffer
 *
 * @param[in]     frag_buf                   The fragmentation buffer.
 *
 * @return        The remaining ALPDU size in the fragmentation buffer
 *
 * @ingroup       RLE Fragmentation buffer.
 */
size_t frag_buf_get_remaining_alpdu_length(const rle_frag_buf_t *const frag_buf);

/**
 * @brief         Return the current PPDU size in the fragmentation buffer
 *
 * @param[in]     frag_buf                   The fragmentation buffer.
 *
 * @return        The current PPDU size in the fragmentation buffer
 *
 * @ingroup       RLE Fragmentation buffer.
 */
size_t frag_buf_get_current_ppdu_len(const rle_frag_buf_t *const frag_buf);

static void frag_buf_ptrs_set(frag_buf_ptrs_t *const ptrs, unsigned char *const address)
{
	assert((address >= ptrs->frag_buf->buffer) &&
	       (address < ptrs->frag_buf->buffer + sizeof(ptrs->frag_buf->buffer)));

	ptrs->start = ptrs->end = address;
}

static void frag_buf_ptrs_push(frag_buf_ptrs_t *const ptrs, const ssize_t size)
{
	assert((ptrs->frag_buf->buffer + size) <= ptrs->start);

	ptrs->start -= size;
}

static void frag_buf_ptrs_put(frag_buf_ptrs_t *const ptrs, const size_t size)
{
	const ptrdiff_t offset =
		(ptrs->frag_buf->buffer + sizeof(ptrs->frag_buf->buffer)) - ptrs->end;

	assert(size <= (size_t)offset);

	ptrs->end += size;
}

static inline void frag_buf_sdu_put(rle_frag_buf_t *const frag_buf, const size_t size)
{
	frag_buf_ptrs_put(&frag_buf->sdu, size);
	frag_buf_ptrs_put(&frag_buf->alpdu, size);
}

static inline void frag_buf_alpdu_push(rle_frag_buf_t *const frag_buf, const size_t size)
{
	frag_buf_ptrs_push(&frag_buf->alpdu, size);
	frag_buf_ptrs_set(&frag_buf->ppdu, frag_buf->alpdu.start);
	frag_buf_set_cur_pos(frag_buf);
}

static inline void frag_buf_alpdu_put(rle_frag_buf_t *const frag_buf, const size_t size)
{
	frag_buf_ptrs_put(&frag_buf->alpdu, size);
}

static inline void frag_buf_ppdu_push(rle_frag_buf_t *const frag_buf, const size_t size)
{
	frag_buf_ptrs_push(&frag_buf->ppdu, size);
}

static inline void frag_buf_ppdu_init(rle_frag_buf_t *const frag_buf)
{
	frag_buf_ptrs_set(&frag_buf->ppdu, frag_buf->cur_pos);
}

static inline void frag_buf_set_cur_pos(rle_frag_buf_t *const frag_buf)
{
	frag_buf->cur_pos = frag_buf->ppdu.end;
}

static inline int frag_buf_in_use(const rle_frag_buf_t *const frag_buf)
{
	return frag_buf->sdu.start != frag_buf->sdu.end;
}

static inline ssize_t frag_buf_get_sdu_len(const rle_frag_buf_t *const frag_buf)
{
	return (ssize_t)(frag_buf->sdu.end - frag_buf->sdu.start);
}

static inline ssize_t frag_buf_get_alpdu_hdr_len(const rle_frag_buf_t *const frag_buf)
{
	return (ssize_t)(frag_buf->sdu.start - frag_buf->alpdu.start);
}

static inline ssize_t frag_buf_get_alpdu_trailer_len(const rle_frag_buf_t *const frag_buf)
{
	return (ssize_t)(frag_buf->alpdu.end - frag_buf->sdu.end);
}

static inline int frag_buf_dump_mem(const rle_frag_buf_t *const frag_buf,
                                    const unsigned char *const start,
                                    const unsigned char *const end)
{
	const unsigned char *b = start;

	if (!frag_buf_in_use(frag_buf)) {
		RLE_ERR("fragmentation buffer not in use");
		goto out;
	}

	if ((start < frag_buf->buffer) || (end > (frag_buf->buffer + sizeof(frag_buf->buffer)))) {
		RLE_ERR("address out of buffer ([%p - %p]/[%p - %p])", start, end, frag_buf->buffer,
		        frag_buf->buffer + sizeof(frag_buf->buffer));
		goto out;
	}

	if (end < start) {
		RLE_ERR("start after end (%p/%p)", start, end);
		goto out;
	}

	for (; b < end; ++b) {
		RLE_DEBUG("%02x%s", *b, ((b - start) % 16) == 15 ? "\n" : " ");
	}

out:
	return (int)(end - start);
}

static inline int frag_buf_dump_ppdu_header(const rle_frag_buf_t *const frag_buf)
{
	int status = -1;
	int ret;
	const unsigned char *end;

	if (!frag_buf_in_use(frag_buf)) {
		RLE_ERR("fragmentation buffer not in use");
		goto out;
	}

	end = frag_buf->alpdu.start < frag_buf->cur_pos ? frag_buf->alpdu.start : frag_buf->cur_pos;

	ret = frag_buf_dump_mem(frag_buf, frag_buf->ppdu.start, end);

	if (ret != -1) {
		goto out;
	}

	RLE_DEBUG("%d-octets PPDU header dumped", ret);
	status = 0;

out:
	return status;
}

static inline int frag_buf_dump_alpdu_header(const rle_frag_buf_t *const frag_buf)
{
	int status = -1;
	int ret;

	if (!frag_buf_in_use(frag_buf)) {
		RLE_ERR("fragmentation buffer not in use");
		goto out;
	}

	ret = frag_buf_dump_mem(frag_buf, frag_buf->alpdu.start, frag_buf->sdu.start);

	if (ret != -1) {
		goto out;
	}

	RLE_DEBUG("%d-octets ALPDU header dumped", ret);
	status = 0;

out:
	return status;
}

static inline int frag_buf_dump_sdu(const rle_frag_buf_t *const frag_buf)
{
	int status = -1;
	int ret;

	if (!frag_buf_in_use(frag_buf)) {
		RLE_ERR("fragmentation buffer not in use");
		goto out;
	}

	ret = frag_buf_dump_mem(frag_buf, frag_buf->sdu.start, frag_buf->sdu.end);

	if (ret != -1) {
		goto out;
	}

	RLE_DEBUG("%d-octets SDU dumped", ret);
	status = 0;

out:
	return status;
}

static inline int frag_buf_dump_alpdu_trailer(const rle_frag_buf_t *const frag_buf)
{
	int status = -1;
	int ret;

	if (!frag_buf_in_use(frag_buf)) {
		RLE_ERR("fragmentation buffer not in use");
		goto out;
	}

	ret = frag_buf_dump_mem(frag_buf, frag_buf->sdu.end, frag_buf->alpdu.end);

	if (ret != -1) {
		goto out;
	}

	RLE_DEBUG("%d-octets ALPDU trailer dumped", ret);
	status = 0;

out:
	return status;
}

static inline int frag_buf_dump_full_frag_buf(const rle_frag_buf_t *const frag_buf)
{
	int status = -1;
	int ret;

	if (!frag_buf_in_use(frag_buf)) {
		RLE_ERR("fragmentation buffer not in use");
		goto out;
	}

	ret = frag_buf_dump_mem(frag_buf, frag_buf->buffer, frag_buf->buffer +
	                        sizeof(frag_buf->buffer));

	if (ret != -1) {
		goto out;
	}

	RLE_DEBUG("%d-octets fragmentation buffer dumped", ret);
	status = 0;

out:
	return status;
}

static inline int frag_buf_is_fragmented(const rle_frag_buf_t *const frag_buf)
{
	int is_fragmented;

	assert(frag_buf_in_use(frag_buf));

	is_fragmented = frag_buf->alpdu.start < frag_buf->ppdu.start ? 1 : 0;

	return is_fragmented;
}

#undef MODULE_ID
#endif /* __FRAGMENTATION_BUFFER_H__ */

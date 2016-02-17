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

/** Maximum size for a fragmentation buffer. */
#define RLE_F_BUFF_LEN (sizeof(rle_ppdu_header_t) + \
                        sizeof(rle_alpdu_header_t) + \
                        (RLE_MAX_PDU_SIZE) + \
                        sizeof(rle_alpdu_trailer_t))


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
typedef struct fragmentation_buffer_ptrs f_buff_ptrs_t;

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
struct rle_fragmentation_buffer;

/** Fragmentation buffer definition. */
typedef struct rle_fragmentation_buffer rle_f_buff_t;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Fragmentation buffer pointers implementation. */
struct fragmentation_buffer_ptrs {
	rle_f_buff_t *f_buff; /** Pointed fragmentation buffer. */
	unsigned char *start; /** Start pointer.                */
	unsigned char *end;   /** End pointer.                  */
};

/** Fragmentation buffer implementation. */
struct rle_fragmentation_buffer {
	unsigned char buffer[RLE_F_BUFF_LEN]; /** Buffer itself.                                     */
	unsigned char *cur_pos;               /** Current position.                                  */
	struct rle_sdu sdu_info;              /** RLE SDU struct used without buffer to store infos. */
	f_buff_ptrs_t sdu;                    /** SDU after copying it.                              */
	f_buff_ptrs_t alpdu;                  /** ALPDU after encapsulation.                         */
	f_buff_ptrs_t ppdu;                   /** PPDU after each fragmentation.                     */
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
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer pointers.
 */
static inline int f_buff_ptrs_set(f_buff_ptrs_t *const ptrs, unsigned char *const address);

/**
 * @brief         Decrement the start pointer in the fragmentation buffer.
 *
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 * |/|   |/|/|   |/|/|/|   |/|/|/|   |/|
 * +-+···+-+-+···+-+-+-+···+-+-+-+···+-+
 *        ^                   ^
 *        | <-------X         |
 *     ptr start           ptr end
 *
 * @param[in,out] ptrs                     The fragmentation buffer pointers.
 * @param[in]     size                     The size to push.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer pointers.
 */
static inline int f_buff_ptrs_push(f_buff_ptrs_t *const ptrs, const size_t size);

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
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer pointers.
 */
static inline int f_buff_ptrs_put(f_buff_ptrs_t *const ptrs, const size_t size);

/**
 * @brief         Put the SDU, ALPDU and PPDU pointers.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 * @param[in]     size                     The size to pull.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_sdu_put(rle_f_buff_t *const f_buff, const size_t size);

/**
 * @brief         Push the ALPDU and PPDU pointers.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 * @param[in]     size                     The size to push.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_alpdu_push(rle_f_buff_t *const f_buff, const size_t size);

/**
 * @brief         Put the ALPDU pointers.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 * @param[in]     size                     The size to put.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_alpdu_put(rle_f_buff_t *const f_buff, const size_t size);

/**
 * @brief         Push the PPDU pointers.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 * @param[in]     size                     The size to push.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_ppdu_push(rle_f_buff_t *const f_buff, const size_t size);

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
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_ppdu_init(rle_f_buff_t *const f_buff);

/**
 * @brief         Put the PPDU pointers.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 * @param[in]     size                     The size to put. Bounded to the ALPDU.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_ppdu_put(rle_f_buff_t *const f_buff, const size_t size);

/**
 * @brief         Set the current position in the buffer depending on the last PPDU start.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_set_cur_pos(rle_f_buff_t *const f_buff);

/**
 * @brief         Check if the fragmentation buffer is in use.
 *
 * @param[in,out] f_buff                   The fragmentation buffer to check.
 *
 * @return        0 if not in use, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_in_use(const rle_f_buff_t *const f_buff);

/**
 * @brief         Get the length of the ALPDU header in the fragmentation buffer.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline ssize_t f_buff_get_alpdu_header_len(const rle_f_buff_t *const f_buff);

/**
 * @brief         Get the length of the ALPDU trailer in the fragmentation buffer.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline ssize_t f_buff_get_alpdu_trailer_len(const rle_f_buff_t *const f_buff);

/**
 * @brief         Get the length of the PPDU header in the fragmentation buffer.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline ssize_t f_buff_get_ppdu_header_len(const rle_f_buff_t *const f_buff);

/**
 * @brief         Dump memory from the fragmentation buffer.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 * @param[in]     start                    The start of the dump.
 * @param[in]     end                      The end of the dump.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_dump_mem(const rle_f_buff_t *const f_buff,
                                  const unsigned char *const start, const unsigned char *const end);

/**
 * @brief         Dump the PPDU header from the fragmentation buffer
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_dump_ppdu_header(const rle_f_buff_t *const f_buff);

/**
 * @brief         Dump the ALPDU header from the fragmentation buffer
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_dump_alpdu_header(const rle_f_buff_t *const f_buff);

/**
 * @brief         Dump the SDU from the fragmentation buffer
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_dump_sdu(const rle_f_buff_t *const f_buff);

/**
 * @brief         Dump the ALPDU trailer from the fragmentation buffer
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_dump_alpdu_trailer(const rle_f_buff_t *const f_buff);

/**
 * @brief         Dump the fragmentation buffer fully.
 *
 * @param[in,out] f_buff                   The fragmentation buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_dump_full_f_buff(const rle_f_buff_t *const f_buff);

/**
 * @brief         Check if the fragmentation buffer fully is fragmented.
 *
 * @param[in]     f_buff                   The fragmentation buffer.
 *
 * @return        0 if not fragmented, 1 if fragmented.
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline int f_buff_is_fragmented(const rle_f_buff_t *const f_buff);

/**
 * @brief         Return the remaining ALPDU size in the fragmentation buffer
 *
 * @param[in]     f_buff                   The fragmentation buffer.
 *
 * @return        The remaining ALPDU size in the fragmentation buffer
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline size_t f_buff_get_remaining_alpdu_length(const rle_f_buff_t *const f_buff);

/**
 * @brief         Return the current PPDU size in the fragmentation buffer
 *
 * @param[in]     f_buff                   The fragmentation buffer.
 *
 * @return        The current PPDU size in the fragmentation buffer
 *
 * @ingroup       RLE Fragmentation buffer.
 */
static inline size_t f_buff_get_current_ppdu_len(const rle_f_buff_t *const f_buff);

static inline int f_buff_ptrs_set(f_buff_ptrs_t *const ptrs, unsigned char *const address)
{
	int status = 1;

	if ((address < ptrs->f_buff->buffer) ||
		(address >= ptrs->f_buff->buffer + sizeof(ptrs->f_buff->buffer))) {
		PRINT_RLE_ERROR("address out of buffer (%p/[%p - %p]).", address, ptrs->f_buff->buffer,
		                ptrs->f_buff->buffer + sizeof(ptrs->f_buff->buffer));
		goto out;
	}

	ptrs->start = ptrs->end = address;

	status = 0;

out:

	return status;
}

static inline int f_buff_ptrs_push(f_buff_ptrs_t *const ptrs, const size_t size)
{
	int status = 1;
	const ptrdiff_t offset  = ptrs->f_buff->buffer - ptrs->start;

	if (size > (size_t)offset) {
		PRINT_RLE_ERROR("Not enough space to put (%zu/%zu).", size, offset);
		goto out;
	}

	ptrs->start -= size;

	status = 0;

out:

	return status;
}

static inline int f_buff_ptrs_put(f_buff_ptrs_t *const ptrs, const size_t size)
{
	int status = 1;

	const ptrdiff_t offset = (ptrs->f_buff->buffer + sizeof(ptrs->f_buff->buffer)) - ptrs->end;

	if (size > (size_t)offset) {
		PRINT_RLE_ERROR("Not enough space to put (%zu/%zu).", size, offset);
		goto out;
	}

	ptrs->end += size;

	status = 0;

out:

	return status;
}

static inline int f_buff_sdu_put(rle_f_buff_t *const f_buff, const size_t size)
{
	int status = 1;

	status =  f_buff_ptrs_put(&f_buff->sdu,   size);
	status |= f_buff_ptrs_put(&f_buff->alpdu, size);

	return status;
}

static inline int f_buff_alpdu_push(rle_f_buff_t *const f_buff, const size_t size)
{
	int status = 1;

	status =  f_buff_ptrs_push(&f_buff->alpdu, size);
	status |= f_buff_ptrs_set(&f_buff->ppdu, f_buff->alpdu.start);
	status |= f_buff_set_cur_pos(f_buff);

	return status;
}

static inline int f_buff_alpdu_put(rle_f_buff_t *const f_buff, const size_t size)
{
	int status = 1;

	status =  f_buff_ptrs_put(&f_buff->alpdu, size);

	return status;
}

static inline int f_buff_ppdu_push(rle_f_buff_t *const f_buff, const size_t size)
{
	int status = 1;

	status = f_buff_ptrs_push(&f_buff->ppdu, size);

	return status;
}

static inline int f_buff_ppdu_init(rle_f_buff_t *const f_buff)
{
	int status = 1;

	status = f_buff_ptrs_set(&f_buff->ppdu, f_buff->ppdu.end);

	return status;
}

static inline int f_buff_ppdu_put(rle_f_buff_t *const f_buff, const size_t size)
{
	int status = 1;
	size_t bounded_size;

	if (size > RLE_MAX_PPDU_PL_SIZE) {
		PRINT_RLE_ERROR("fragment is at most %d-octets. %zu octets requested.",
		                RLE_MAX_PPDU_PL_SIZE, size);
		goto out;
	}

	if (f_buff_get_remaining_alpdu_length(f_buff) < size) {
		bounded_size = f_buff_get_remaining_alpdu_length(f_buff);
	} else {
		bounded_size = size;
	}

	status =  f_buff_ptrs_put(&f_buff->ppdu, bounded_size);

out:

	return status;
}

static inline int f_buff_set_cur_pos(rle_f_buff_t *const f_buff)
{
	int status = 1;

	f_buff->cur_pos = f_buff->ppdu.end;

	status = 0;

	return status;
}

static inline int f_buff_in_use(const rle_f_buff_t *const f_buff)
{
	return f_buff->sdu.start != f_buff->sdu.end;
}

static inline ssize_t f_buff_get_alpdu_header_len(const rle_f_buff_t *const f_buff)
{
	return (ssize_t)(f_buff->sdu.start - f_buff->alpdu.start);
}

static inline ssize_t f_buff_get_alpdu_trailer_len(const rle_f_buff_t *const f_buff)
{
	return (ssize_t)(f_buff->alpdu.end - f_buff->sdu.end);
}

static inline ssize_t f_buff_get_ppdu_header_len(const rle_f_buff_t *const f_buff)
{
	return (ssize_t)(f_buff->cur_pos - f_buff->ppdu.start);
}

static inline int f_buff_dump_mem(const rle_f_buff_t *const f_buff,
                                  const unsigned char *const start, const unsigned char *const end)
{
	const unsigned char *b = start;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	if ((start < f_buff->buffer) || (end > (f_buff->buffer + sizeof(f_buff->buffer)))) {
		PRINT_RLE_ERROR("address out of buffer ([%p - %p]/[%p - %p]).", start, end, f_buff->buffer,
		                f_buff->buffer + sizeof(f_buff->buffer));
		goto out;
	}

	if (end < start) {
		PRINT_RLE_ERROR("start after end (%p/%p)", start, end);
		goto out;
	}

	for (; b < end; ++b) {
		PRINT("%02x%s", *b, ((b - start) % 16) == 15 ? "\n" : " ");
	}
	PRINT("\n");

out:

	return (int)(end - start);
}

static inline int f_buff_dump_ppdu_header(const rle_f_buff_t *const f_buff)
{
	int status = -1;
	int ret;
	const unsigned char *end;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	end = f_buff->alpdu.start < f_buff->cur_pos ? f_buff->alpdu.start : f_buff->cur_pos;

	ret = f_buff_dump_mem(f_buff, f_buff->ppdu.start, end);

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets PPDU header dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int f_buff_dump_alpdu_header(const rle_f_buff_t *const f_buff)
{
	int status = -1;
	int ret;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	ret = f_buff_dump_mem(f_buff, f_buff->alpdu.start, f_buff->sdu.start);

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets ALPDU header dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int f_buff_dump_sdu(const rle_f_buff_t *const f_buff)
{
	int status = -1;
	int ret;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	ret = f_buff_dump_mem(f_buff, f_buff->sdu.start, f_buff->sdu.end);

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets SDU dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int f_buff_dump_alpdu_trailer(const rle_f_buff_t *const f_buff)
{
	int status = -1;
	int ret;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	ret = f_buff_dump_mem(f_buff, f_buff->sdu.end, f_buff->alpdu.end);

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets ALPDU trailer dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int f_buff_dump_full_f_buff(const rle_f_buff_t *const f_buff)
{
	int status = -1;
	int ret;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	ret = f_buff_dump_mem(f_buff, f_buff->buffer, f_buff->buffer + sizeof(f_buff->buffer));

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets fragmentation buffer dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int f_buff_is_fragmented(const rle_f_buff_t *const f_buff)
{
	int is_fragmented = 0;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	is_fragmented = f_buff->alpdu.start < f_buff->ppdu.start ? 1 : 0;

out:
	return is_fragmented;
}

static inline size_t f_buff_get_remaining_alpdu_length(const rle_f_buff_t *const f_buff)
{
	size_t remaining_alpdu_length = 0;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	if (f_buff->alpdu.end < f_buff->cur_pos) {
		PRINT_RLE_ERROR("fragmentation buffer current position after ALPDU end.");
		goto out;
	}

	remaining_alpdu_length = f_buff->alpdu.end - f_buff->cur_pos;

out:
	return remaining_alpdu_length;
}

static inline size_t f_buff_get_current_ppdu_len(const rle_f_buff_t *const f_buff)
{
	size_t current_ppdu_len = 0;

	if (!f_buff_in_use(f_buff)) {
		PRINT_RLE_ERROR("fragmentation buffer not in use.");
		goto out;
	}

	current_ppdu_len = f_buff->ppdu.end - f_buff->ppdu.start;

out:
	return current_ppdu_len;
}


#endif /* __FRAGMENTATION_BUFFER_H__ */

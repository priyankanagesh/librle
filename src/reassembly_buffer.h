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

#include "../include/rle.h"

#include "constants.h"


/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Maximum size for a reassembly buffer. */
#define RLE_R_BUFF_LEN (RLE_MAX_PDU_SIZE)

/** Maximum number of fragments to reassembly. */
#define RLE_R_BUFF_MAX_FRAGS 255


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
typedef struct reassembly_buffer_ptrs r_buff_ptrs_t;

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
typedef struct rle_reassembly_buffer rle_r_buff_t;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Reassembly buffer pointers implementation. */
struct reassembly_buffer_ptrs {
	rle_r_buff_t *r_buff; /** Pointed reassembly buffer. */
	unsigned char *start; /** Start pointer.             */
	unsigned char *end;   /** End pointer.               */
};

/** Reassembly buffer implementation. */
struct rle_reassembly_buffer {
	unsigned char *buffer;                /** Buffer. Given by the library caller.               */
	struct rle_sdu sdu_info;              /** RLE SDU struct used without buffer to store infos. */
	size_t nb_fragments;                  /** Current number of fragments.                       */
	r_buff_ptrs_t sdu;                    /** SDU after copying it.                              */
	r_buff_ptrs_t sdu_frag;               /** Current SDU fragment.                              */
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
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer pointers.
 */
static inline int r_buff_ptrs_set(r_buff_ptrs_t *const ptrs, unsigned char *const address);

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
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer pointers.
 */
static inline int r_buff_ptrs_put(r_buff_ptrs_t *const ptrs, const size_t size);

/**
 * @brief         Put the SDU pointers.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 * @param[in]     size                     The size to put.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_sdu_put(rle_r_buff_t *const r_buff, const size_t size);

/**
 * @brief         Put the SDU fragment pointers. Automatically used by the copying function.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 * @param[in]     size                     The size to put.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_sdu_frag_put(rle_r_buff_t *const r_buff, const size_t size);

/**
 * @brief         Create a new reassembly buffer.
 *
 * @return        The reassembly buffer if OK, else NULL.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline rle_r_buff_t *r_buff_new(void);

/**
 * @brief         Destroy a reassembly buffer.
 *
 * @param[in,out] r_buff                   The reassembly buffer to destroy.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline void r_buff_del(rle_r_buff_t **const r_buff);

/**
 * @brief         Initialize (eventually reinitialize) a reassembly buffer.
 *
 * @param[in,out] r_buff                   The reassembly buffer to (re)initialize.
 * @param[in,out] sdu                      the SDU structure, containing the buffer that will be
 *                                         used to store the reassembled SDU.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_init(rle_r_buff_t *const r_buff);

/**
 * @brief         Check if the reassembly buffer is in use.
 *
 * @param[in,out] r_buff                   The reassembly buffer to check.
 *
 * @return        0 if not in use, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_in_use(const rle_r_buff_t *const r_buff);

/**
 * @brief         Copy a fragment of SDU in a reassembly buffer.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 * @param[in]     size                     The SDU to copy.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_cpy_sdu_frag(rle_r_buff_t *const r_buff, const unsigned char sdu_frag[]);

/**
 * @brief         Get the length of the SDU in the reassembly buffer (reassembled or not).
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 *
 * @return        The total length of the SDU.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline ssize_t r_buff_get_sdu_length(const rle_r_buff_t *const r_buff);

/**
 * @brief         Get the length of SDU currently reassembled.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 *
 * @return        The currently reassembled SDU length.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline ssize_t r_buff_get_reassembled_sdu_length(const rle_r_buff_t *const r_buff);

/**
 * @brief         Dump memory from the reassembly buffer.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 * @param[in]     start                    The start of the dump.
 * @param[in]     end                      The end of the dump.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_dump_mem(const rle_r_buff_t *const r_buff,
                                  const unsigned char *const start, const unsigned char *const end);

/**
 * @brief         Dump the SDU from the reassembly buffer.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_dump_sdu(const rle_r_buff_t *const r_buff);

/**
 * @brief         Dump the currently reassembled SDU from the reassembly buffer.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_dump_reassembled_sdu(const rle_r_buff_t *const r_buff);

/**
 * @brief         Dump the reassembly buffer fully.
 *
 * @param[in,out] r_buff                   The reassembly buffer.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_dump_full_r_buff(const rle_r_buff_t *const r_buff);

/**
 * @brief         Check if the reassembly buffer is fully reassembled.
 *
 * @param[in]     r_buff                   The reassembly buffer.
 *
 * @return        0 if not reassembled, 1 if reassembled.
 *
 * @ingroup       RLE Reassembly buffer.
 */
static inline int r_buff_is_reassembled(const rle_r_buff_t *const r_buff);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static inline int r_buff_ptrs_set(r_buff_ptrs_t *const ptrs, unsigned char *const address)
{
	int status = 1;

	if ((address < ptrs->r_buff->buffer) ||
		(address >= ptrs->r_buff->buffer + RLE_R_BUFF_LEN)) {
		PRINT_RLE_ERROR("address out of buffer (%p/[%p - %p]).", address, ptrs->r_buff->buffer,
		                ptrs->r_buff->buffer + RLE_R_BUFF_LEN);
		goto out;
	}

	ptrs->start = ptrs->end = address;

	status = 0;

out:

	return status;
}

static inline int r_buff_ptrs_put(r_buff_ptrs_t *const ptrs, const size_t size)
{
	int status = 1;

	const ptrdiff_t offset = (ptrs->r_buff->buffer + RLE_R_BUFF_LEN) - ptrs->end;

	if (size > (size_t)offset) {
		PRINT_RLE_ERROR("Not enough space to put (%zu/%zu).", size, offset);
		goto out;
	}

	ptrs->end += size;

	status = 0;

out:

	return status;
}

static inline int r_buff_sdu_put(rle_r_buff_t *const r_buff, const size_t size)
{
	return r_buff_ptrs_put(&r_buff->sdu, size);
}

static inline int r_buff_sdu_frag_put(rle_r_buff_t *const r_buff, const size_t size)
{
	int status = 1;
	const ptrdiff_t remaining_sdu_length = r_buff->sdu.end - r_buff->sdu_frag.end;

	if (size > (remaining_sdu_length > 0 ? (size_t)remaining_sdu_length : 0) ) {
		PRINT_RLE_ERROR("SDU reassembly overflow. Expecting %zu, getting %zu.", size,
		                (size_t)remaining_sdu_length);
	}

	status =  r_buff_ptrs_put(&r_buff->sdu_frag, size);

	return status;
}

static inline int r_buff_init_sdu_frag(rle_r_buff_t *const r_buff)
{
	int status = 1;

	if (++(r_buff->nb_fragments) == RLE_R_BUFF_MAX_FRAGS) {
		PRINT_RLE_ERROR("Too much fragments in reassembly buffer.");
		goto out;
	}

	status = r_buff_ptrs_set(&r_buff->sdu_frag, r_buff->sdu_frag.end);

out:
	return status;
}

static inline rle_r_buff_t *r_buff_new(void)
{
	rle_r_buff_t *r_buff = (rle_r_buff_t *)MALLOC(sizeof(rle_r_buff_t));

	if (!r_buff) {
		PRINT_RLE_ERROR("reassembly buffer not allocated.");
		goto out;
	}

	r_buff->buffer = r_buff->sdu_info.buffer = (unsigned char *)MALLOC(RLE_R_BUFF_LEN);
	r_buff->sdu.r_buff      = r_buff;
	r_buff->sdu_frag.r_buff = r_buff;
	r_buff->nb_fragments = 0;

out:

	return r_buff;
}

static inline void r_buff_del(rle_r_buff_t **const r_buff)
{
	if (!r_buff) {
		PRINT_RLE_WARNING("reassembly buffer pointer NULL, nothing can be done.");
		goto out;
	}

	if (!*r_buff) {
		PRINT_RLE_WARNING("reassembly buffer NULL, nothing to do.");
		goto out;
	}

	if ((*r_buff)->sdu_info.buffer) {
		FREE((*r_buff)->sdu_info.buffer);
		(*r_buff)->sdu_info.buffer = NULL;
	}

	FREE(*r_buff);
	*r_buff = NULL;

out:

	return;
}

static inline int r_buff_init(rle_r_buff_t *const r_buff)
{
	int status;

	r_buff->buffer = r_buff->sdu_info.buffer;

	memset(r_buff->buffer, '\0', RLE_R_BUFF_LEN);

	r_buff->nb_fragments = 0;

	status =  r_buff_ptrs_set(&r_buff->sdu,      r_buff->buffer);
	status |= r_buff_ptrs_set(&r_buff->sdu_frag, r_buff->buffer);

	return status;
}

static inline int r_buff_in_use(const rle_r_buff_t *const r_buff)
{
	return r_buff->sdu.start != r_buff->sdu.end;
}

static inline int r_buff_cpy_sdu_frag(rle_r_buff_t *const r_buff, const unsigned char sdu_frag[])
{
	int status = 1;

	if (!r_buff_in_use(r_buff)) {
		PRINT_RLE_ERROR("reassembly buffer not initialized.");
		goto out;
	}

	memcpy(r_buff->sdu_frag.start, sdu_frag, r_buff->sdu_frag.end - r_buff->sdu_frag.start);

	status = 0;

out:

	return status;
}

static inline ssize_t r_buff_get_sdu_length(const rle_r_buff_t *const r_buff)
{
	return (ssize_t)(r_buff->sdu.end - r_buff->sdu.start);
}

static inline ssize_t r_buff_get_reassembled_sdu_length(const rle_r_buff_t *const r_buff)
{
	return (ssize_t)(r_buff->sdu_frag.end - r_buff->sdu.start);
}

static inline int r_buff_dump_mem(const rle_r_buff_t *const r_buff,
                                  const unsigned char *const start, const unsigned char *const end)
{
	const unsigned char *b = start;

	if (!r_buff_in_use(r_buff)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	if ((start < r_buff->buffer) || (end > (r_buff->buffer + sizeof(r_buff->buffer)))) {
		PRINT_RLE_ERROR("address out of buffer ([%p - %p]/[%p - %p]).", start, end, r_buff->buffer,
		                r_buff->buffer + sizeof(r_buff->buffer));
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

static inline int r_buff_dump_sdu(const rle_r_buff_t *const r_buff)
{
	int status = -1;
	int ret;

	if (!r_buff_in_use(r_buff)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	ret = r_buff_dump_mem(r_buff, r_buff->sdu.start, r_buff->sdu.end);

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets SDU dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int r_buff_dump_reassembled_sdu(const rle_r_buff_t *const r_buff)
{
	int status = -1;
	int ret;

	if (!r_buff_in_use(r_buff)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	ret = r_buff_dump_mem(r_buff, r_buff->sdu.start, r_buff->sdu_frag.end);

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets reassembled SDU dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int r_buff_dump_full_r_buff(const rle_r_buff_t *const r_buff)
{
	int status = -1;
	int ret;

	if (!r_buff_in_use(r_buff)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	ret = r_buff_dump_mem(r_buff, r_buff->buffer, r_buff->buffer + sizeof(r_buff->buffer));

	if (ret != -1) {
		goto out;
	}

	PRINT("%d-octets reassembly buffer dumped.", ret);
	status = 0;

out:

	return status;
}

static inline int r_buff_is_reassembled(const rle_r_buff_t *const r_buff)
{
	int is_reassembled = 0;

	if (!r_buff_in_use(r_buff)) {
		PRINT_RLE_ERROR("reassembly buffer not in use.");
		goto out;
	}

	is_reassembled = r_buff->sdu.end > r_buff->sdu_frag.end ? 1 : 0;

out:
	return is_reassembled;
}


#endif /* __REASSEMBLY_BUFFER_H__ */

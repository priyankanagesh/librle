/**
 * @file   zc_buffer.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE trailer constants, functions and variables
 *
 *
 */

#ifndef _ZC_BUFFER_H
#define _ZC_BUFFER_H

#include "header.h"
#include "trailer.h"
#include "constants.h"

/**
 * This define compute the size of the zc buffer, based on the hard coded values of the differents
 * headers, trailers and pointers sizes.
 */
#define ZC_BUFFER_MAX_SIZE_PACKED (((RLE_START_MANDATORY_HEADER_SIZE) + \
      (RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP)) +	\
    ((RLE_MAX_SEQ_NO - 2) * (RLE_CONT_HEADER_SIZE)) +	\
	  (RLE_END_HEADER_SIZE) +	\
		(RLE_CRC32_FIELD_SIZE) + \
		(RLE_MAX_SEQ_NO * sizeof(struct zc_ptrs_data)))

/**
 * This define ajusts the size of the zc buffer, taking account of the architecture alignement
 * in the structures. 
 *
 *     1 x ( Max start header size + alignement + 2 x zc pointers )
 * + 254 x ( Continue header size  + alignement + 2 x zc pointers )
 * +   1 x ( End header size       + alignement + 2 x zc pointers )
 * +   1 x ( Max trailer size                                     )
 * ----------------------------------------------------------------
 * = 3080 Octets (arch. 32-bits) / 6148 Octets (arch. 64-bits)
 *
 */
#define ZC_BUFFER_MAX_SIZE ((1 * (int) (sizeof(struct zc_rle_header_complete_w_ptype))) + \
    (((RLE_MAX_SEQ_NO) - 2) * (int) (sizeof(struct zc_rle_header_cont_end))) + \
    (1 * (int) (sizeof(struct zc_rle_header_cont_end))) + \
    (1 * (int) (sizeof(struct zc_rle_trailer))))

/**
 * Structure of pair or pointers
 * pointing to start and end addresses
 * of PDU data (complete or fragment)
 * */
struct zc_ptrs_data {
	char *start;
	char *end;
};

/**
 * Structure to map into an
 * already allocated buffer
 * to get an RLE header of
 * a complete packet followed
 * by a pair of pointers
 * for the PDU
 * */
struct zc_rle_header_complete_w_ptype {
	struct rle_header_complete_w_ptype header;
	struct zc_ptrs_data ptrs;
};

struct zc_rle_header_complete {
	struct rle_header_complete header;
	struct zc_ptrs_data ptrs;
};

/**
 * Structure to map into an
 * already allocated buffer
 * to get an rle header of
 * a start packet followed
 * by a pair of pointers
 * for the fragment of pdu
 * */
struct zc_rle_header_start_w_ptype {
	struct rle_header_start_w_ptype header;
	struct zc_ptrs_data ptrs;
};

struct zc_rle_header_start {
	struct rle_header_start header;
	struct zc_ptrs_data ptrs;
};

/**
 * Structure to map into an
 * already allocated buffer
 * to get an rle header of
 * a CONTINUATION or END
 * packet followed
 * by a pair of pointers
 * for the fragment of pdu
 * */
struct zc_rle_header_cont_end {
	struct rle_header_cont_end header;
	struct zc_ptrs_data ptrs;
};

/**
 * Structure to map into an
 * already allocated buffer
 * to get an rle trailer of
 * an END
 * packet followed
 */
struct zc_rle_trailer {
	struct rle_trailer trailer;
};


#endif /* _ZC_BUFFER_H */

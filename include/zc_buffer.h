/**
 * @file   zc_buffer.h
 * @author Aurelien Castanie
 * @date   Fri Aug  3 10:49:38 CEST 2012
 *
 * @brief  Definition of RLE trailer constants, functions and variables
 *
 *
 */

#ifndef _ZC_BUFFER_H
#define _ZC_BUFFER_H

#include "header.h"
#include "trailer.h"

#define ZC_BUFFER_MAX_SIZE (RLE_START_HEADER_SIZE +		\
		(RLE_MAX_SEQ_NO * RLE_CONT_HEADER_SIZE) +	\
	       	RLE_END_HEADER_SIZE +				\
		RLE_CRC32_FIELD_SIZE +				\
		(RLE_MAX_SEQ_NO * sizeof(int *))

/**
 * Structure of pair or pointers
 * pointing to start and end addresses
 * of PDU data (complete or fragment)
 * */
struct zc_ptrs_data {
	int *start;
	int *end;
};

/**
 * Structure to map into an
 * already allocated buffer
 * to get an RLE header of
 * a complete packet followed
 * by a pair of pointers
 * for the PDU
 * */
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

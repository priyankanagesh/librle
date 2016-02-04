/**
 * @file   trailer.h
 * @brief  Definition of RLE trailer constants, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TRAILER_H__
#define __TRAILER_H__

/** Max Sequence Number value */
#define RLE_MAX_SEQ_NO          256
/** Size of Seq_No trailer in Bytes */
#define RLE_SEQ_NO_FIELD_SIZE   1
/** Size of CRC32 trailer in Bytes */
#define RLE_CRC32_FIELD_SIZE    4

/*
 * RLE packet tail
 * for multi frag context
 * */
struct rle_trailer {
	union {
		/* for sequence number
		 * usage in trailer */
		struct {
			uint32_t seq_no : 8;
			uint32_t : 24;
		} b;
		/* for CRC32 usage in trailer */
		uint32_t crc;
	};
} __attribute__ ((packed));

/** RLE packet Seq No trailer. */
struct rle_alpdu_seqno_trailer {
	uint8_t seq_no;
} __attribute__ ((packed));

/** RLE packet Seq No trailer definition. */
typedef struct rle_alpdu_seqno_trailer rle_alpdu_seqno_trailer_t;

/** RLE packet CRC trailer. */
struct rle_alpdu_crc_trailer {
	uint32_t crc;
} __attribute__ ((packed));

/** RLE packet CRC trailer definition. */
typedef struct rle_alpdu_crc_trailer rle_alpdu_crc_trailer_t;

/** RLE packet trailer definition. */
union rle_alpdu_trailer {
	rle_alpdu_seqno_trailer_t seqno_trailer;
	rle_alpdu_crc_trailer_t crc_trailer;
} __attribute__ ((packed));

typedef union rle_alpdu_trailer rle_alpdu_trailer_t;

#endif /* __TRAILER_H__ */

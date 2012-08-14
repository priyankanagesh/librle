/**
 * @file   trailer.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE trailer constants, functions and variables
 *
 *
 */

#ifndef _TRAILER_H
#define _TRAILER_H

/** Max Sequence Number value */
#define RLE_MAX_SEQ_NO		256
/** Size of Seq_No trailer in Bytes */
#define RLE_SEQ_NO_FIELD_SIZE	1
/** Size of CRC32 trailer in Bytes */
#define RLE_CRC32_FIELD_SIZE	4

/*
 * RLE packet tail
 * for multi frag context
 * */
struct rle_trailer {
	/* for sequence number
	 * usage in trailer */
	union {
		uint32_t seq_no:8;
		uint32_t :24; /* unused */
	};
	/* for CRC32 usage in trailer */
	union {
		uint32_t crc:32;
	};
};

#endif /* _TRAILER_H */

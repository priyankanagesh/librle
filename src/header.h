/**
 * @file   header.h
 * @brief  Definition of RLE header constants, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __HEADER_H__
#define __HEADER_H__

#ifndef __KERNEL__

#include <stdint.h>
#include <endian.h>

#else

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/byteorder/little_endian.h>

#if defined(__LITTLE_ENDIAN)
#define __BYTE_ORDER __LITTLE_ENDIAN
#define __BIG_ENDIAN 0
#elif defined(__BIG_ENDIAN)
#define __BYTE_ORDER __BIG_ENDIAN
#define __LITTLE_ENDIAN 0
#else
#error "platform is not little nor big endian"
#endif

#endif

#include "../include/rle.h"

#include "constants.h"
#include "rle_header_proto_type_field.h"

/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Macros to set Label Type,
 *  Protocol Type Suppressed
 *  and Fragment ID
 *  on a union rle_header_all */

#define RLE_START_MANDATORY_HEADER_SIZE         4

/** Size of fields in a continuation packet in Bytes */
#define RLE_CONT_HEADER_SIZE                    2

/** Size of fields in a end packet in Bytes */
#define RLE_END_HEADER_SIZE                     RLE_CONT_HEADER_SIZE

/** Size of fields in a complete packet in Bytes without protocol type field */
#define RLE_COMPLETE_HEADER_SIZE                RLE_CONT_HEADER_SIZE

#define SET_LABEL_TYPE(_y, _x)  do {                             \
		(_y) = ((_y & 0x1) ^ (_x << 1));        \
} while (0)

#define GET_LABEL_TYPE(_y) (((_y) >> 1) & 0x3)

#define SET_PROTO_TYPE_SUPP(_y, _x) do {                 \
		(_y) = ((_y & 0x6) ^ (_x));     \
} while (0)

#define GET_PROTO_TYPE_SUPP(_y) ((_y) & 0x1)

#define SET_FRAG_ID(_y, _x) do {                         \
		(_y) = (_x);                    \
} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define RLE_SET_PPDU_LEN(PPDU, LEN) do { \
	(PPDU)->rle_packet_length_1 = (uint8_t)((((uint16_t)(LEN) & 0x7ff) >> 5) & 0x3f); \
	(PPDU)->rle_packet_length_2 = (uint8_t)(((uint16_t)(LEN) & 0x7ff) & 0x1f); \
} while (0)

#define RLE_GET_PPDU_LEN(PPDU) ((int16_t)(\
        (((PPDU)->rle_packet_length_1 & 0x3f) << 5) + \
        ( (PPDU)->rle_packet_length_2 & 0x1f)))


#elif __BYTE_ORDER == __BIG_ENDIAN

#define RLE_SET_PPDU_LEN(PPDU, LEN) do {\
	(PPDU)->rle_packet_length = (uint16_t)(LEN);
} while (0)

#define RLE_GET_PPDU_LEN(PPDU) ((PPDU)->rle_packet_length)

#else
#error "Please fix <asm/byteorder.h>"
#endif


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------- PROTECTED STRUCTS AND TYPEDEFS --------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Stubs for visibility */
struct rle_ctx_management;

/** Stubs for visibility */
struct rle_configuration;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/*
 * common RLE packet header
 * for complete, START, CONT,
 * END packet
 * */
union rle_header_all {
	uint16_t all;
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint16_t rle_packet_length_1 : 6;
		uint16_t end_ind : 1;
		uint16_t start_ind : 1;
		uint16_t LT_T_FID : 3;
		uint16_t rle_packet_length_2 : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t start_ind : 1;
		uint16_t end_ind : 1;
		uint16_t rle_packet_length : 11;
		uint16_t LT_T_FID : 3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	} b;
};

/*
 * RLE START packet header
 * specific part
 * */
union rle_header_start_packet {
	uint16_t all;
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint16_t total_length_1 : 7;
		uint16_t use_crc : 1;
		uint16_t proto_type_supp : 1;
		uint16_t label_type : 2;
		uint16_t total_length_2 : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t use_crc : 1;
		uint16_t total_length : 12;
		uint16_t label_type : 2; /* LT for fragmented packet */
		uint16_t proto_type_supp : 1; /* T for fragmented packet */
#else
#error "Please fix <asm/byteorder.h>"
#endif
	} b;
};

/* RLE packet header
 * for complete PDU with
 * protocol type uncompressed &
 * compressed */
struct rle_header_complete_w_ptype {
	union rle_header_all head;
	union {
		struct {
			uint16_t proto_type;
		} __attribute__ ((packed)) ptype_u_s;

		struct {
			union {
				struct {
					uint8_t proto_type;
				} __attribute__ ((packed)) c;
				struct {
					uint8_t proto_type;
					uint16_t proto_type_uncompressed;
				} __attribute__ ((packed)) e;
			};
		} __attribute__ ((packed)) ptype_c_s;
	};
} __attribute__ ((packed));

/* RLE packet header for
 * complete PDU with
 * no protocol type */
struct rle_header_complete {
	union rle_header_all head;
} __attribute__ ((packed));

/* RLE START packet header
 * with protocol type
 * uncompressed
 * for fragmented
 * PDU */
struct rle_header_start_w_ptype {
	union rle_header_all head;
	union rle_header_start_packet head_start;
	union {
		struct {
			uint16_t proto_type;
		} __attribute__ ((packed)) ptype_u_s;

		struct {
			union {
				struct {
					uint8_t proto_type;
				} __attribute__ ((packed)) c;
				struct {
					uint8_t proto_type;
					uint16_t proto_type_uncompressed;
				} __attribute__ ((packed)) e;
			};
		} __attribute__ ((packed)) ptype_c_s;
	};
} __attribute__ ((packed));

/* RLE packet header for
 * START packet with
 * no protocol type */
struct rle_header_start {
	union rle_header_all head;
	union rle_header_start_packet head_start;
} __attribute__ ((packed));

/* RLE CONTINUATION & END packet header
 * for fragmented
 * PDU */
struct rle_header_cont_end {
	union rle_header_all head;
} __attribute__ ((packed));

/**
 * RLE PPDU start header
 *
 * TODO Replacement of old structures
 */
struct rle_ppdu_header_start {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t rle_packet_length_1   : 6;
	uint32_t end_ind               : 1;
	uint32_t start_ind             : 1;
	uint32_t frag_id               : 3;
	uint32_t rle_packet_length_2   : 5;
	uint32_t total_length_1        : 7;
	uint32_t use_crc               : 1;
	uint32_t proto_type_supp       : 1;
	uint32_t label_type            : 2;
	uint32_t total_length_2        : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t start_ind             : 1;
	uint32_t end_ind               : 1;
	uint32_t rle_packet_length     : 11;
	uint32_t frag_id               : 3;
	uint32_t use_crc               : 1;
	uint32_t total_length          : 12;
	uint32_t label_type            : 2;
	uint32_t proto_type_supp       : 1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/** RLE PPDU start header definition */
typedef struct rle_header_start rle_header_start_t;

/** RLE PPDU completet header
 *
 * TODO Replacement of old structures
 */
struct rle_ppdu_header_comp {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rle_packet_length_1   : 6;
	uint16_t end_ind               : 1;
	uint16_t start_ind             : 1;
	uint16_t proto_type_supp       : 1;
	uint16_t label_type            : 2;
	uint16_t rle_packet_length_2   : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t start_ind             : 1;
	uint16_t end_ind               : 1;
	uint16_t rle_packet_length     : 11;
	uint16_t label_type            : 2;
	uint16_t proto_type_supp       : 1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/** RLE PPDU completet header definition */
typedef struct rle_ppdu_header_comp rle_header_comp_t;

/** RLE PPDU contininuation or end header
 *
 * TODO Replacement of old structures
 */
struct rle_ppdu_header_cont_end {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rle_packet_length_1   : 6;
	uint16_t end_ind               : 1;
	uint16_t start_ind             : 1;
	uint16_t frag_id               : 3;
	uint16_t rle_packet_length_2   : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t start_ind             : 1;
	uint16_t end_ind               : 1;
	uint16_t rle_packet_length     : 11;
	uint16_t frag_id               : 3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/** RLE PPDU contininuation or end header definition */
typedef struct rle_ppdu_header_cont_end rle_header_cont_end_t;

/** RLE PPDU header
 *
 * TODO Replacement of old structures
 */
union rle_ppdu_header {
	rle_header_start_t    start;
	rle_header_cont_end_t cont;
	rle_header_cont_end_t end;
	rle_header_comp_t     comp;
} __attribute__ ((packed));

/** RLE PPDU header definition */
typedef union rle_ppdu_header rle_ppdu_header_t;

union rle_alpdu_header {
	struct {
		uint16_t proto_type;
	} __attribute__ ((packed)) uncompressed;
	struct {
		union {
			struct {
				uint8_t proto_type;
			} __attribute__ ((packed)) supported;
			struct {
				uint8_t proto_type;
				uint16_t proto_type_uncompressed;
			} __attribute__ ((packed)) fallback;
		};
	} __attribute__ ((packed)) compressed;
} __attribute__ ((packed));

/** RLE ALPDU header definition */
typedef union rle_alpdu_header rle_alpdu_header_t;

/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief create header into an rle packet
 *
 *  @warning
 *
 *  @param rle_ctx              the rle fragment context
 *  @param rle_conf             the rle configuration
 *  @param data_buffer          data buffer's address to encapsulate
 *  @param data_length          data length to encapsulate
 *  @param protocol_type        the protocol type
 *
 *  @return C_ERROR if KO
 *                C_OK if OK
 *
 *  @ingroup
 */
int create_header(struct rle_ctx_management *rle_ctx, struct rle_configuration *rle_conf,
                  void *data_buffer, size_t data_length, uint16_t protocol_type);

#endif /* __HEADER_H__ */

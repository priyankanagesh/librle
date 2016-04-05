/**
 * @file   rle_header_proto_type_field.c
 * @brief  RLE header protocol type fields functions
 * @author Henrick Deschamps, based on Aurelien Castanie works.
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_header_proto_type_field.h"

#include "constants.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define RLE_PROTO_TYPE_IPV4_OR_IPV6 0

/**
 * Lots of define to easily populate the array of protocol references, that allow to concatenate
 * initializing value for arrays. The concat initializer are based on the binary arithmetic and more
 * especially on the powers of two.
 *
 * For instance CONCAT_INITIALIZER_POW_2(RLE_PROTO_TYPE_RESERVED) is replaced by
 * "RLE_PROTO_TYPE_RESERVED, RLE_PROTO_TYPE_RESERVED" by the preprocessor.
 * We can write array "arr[2] = { CONCAT_INITIALIZER_POW_2(RLE_PROTO_TYPE_RESERVED) };"
 * and the preprocessor replaces it by
 * "arr[2] = { RLE_PROTO_TYPE_RESERVED, RLE_PROTO_TYPE_RESERVED };"
 */
#define CONCAT_INITIALIZER_POW_2(_x)  (_x), (_x)
#define CONCAT_INITIALIZER_POW_4(_x)  CONCAT_INITIALIZER_POW_2(_x), CONCAT_INITIALIZER_POW_2(_x)
#define CONCAT_INITIALIZER_POW_8(_x)  CONCAT_INITIALIZER_POW_4(_x), CONCAT_INITIALIZER_POW_4(_x)
#define CONCAT_INITIALIZER_POW_16(_x) CONCAT_INITIALIZER_POW_8(_x), CONCAT_INITIALIZER_POW_8(_x)
#define CONCAT_INITIALIZER_POW_32(_x) CONCAT_INITIALIZER_POW_16(_x), CONCAT_INITIALIZER_POW_16(_x)
#define CONCAT_INITIALIZER_POW_64(_x) CONCAT_INITIALIZER_POW_32(_x), CONCAT_INITIALIZER_POW_32(_x)

/** 16 reserved protocol type for range 0x32 -> 0x41 */
#define RLE_PROTO_TYPE_RESERVED_16      CONCAT_INITIALIZER_POW_16(RLE_PROTO_TYPE_RESERVED)

/** 21 reserved protocol type for range 0x1b -> 0x2f */
#define RLE_PROTO_TYPE_RESERVED_21      CONCAT_INITIALIZER_POW_16(RLE_PROTO_TYPE_RESERVED), \
        CONCAT_INITIALIZER_POW_4(RLE_PROTO_TYPE_RESERVED), \
        RLE_PROTO_TYPE_RESERVED

/** 56 reserved protocol type for range 0x48 -> 0x7f */
#define RLE_PROTO_TYPE_RESERVED_56      CONCAT_INITIALIZER_POW_32(RLE_PROTO_TYPE_RESERVED), \
        CONCAT_INITIALIZER_POW_16(RLE_PROTO_TYPE_RESERVED), \
        CONCAT_INITIALIZER_POW_8(RLE_PROTO_TYPE_RESERVED)

/** 127 user defined protocol type for range 0x80 -> 0xfe */
#define RLE_PROTO_TYPE_USER_DEFINED_127 CONCAT_INITIALIZER_POW_64(RLE_PROTO_TYPE_USER_DEFINED), \
        CONCAT_INITIALIZER_POW_32(RLE_PROTO_TYPE_USER_DEFINED), \
        CONCAT_INITIALIZER_POW_16(RLE_PROTO_TYPE_USER_DEFINED), \
        CONCAT_INITIALIZER_POW_8(RLE_PROTO_TYPE_USER_DEFINED), \
        CONCAT_INITIALIZER_POW_4(RLE_PROTO_TYPE_USER_DEFINED), \
        CONCAT_INITIALIZER_POW_2(RLE_PROTO_TYPE_USER_DEFINED), \
        RLE_PROTO_TYPE_USER_DEFINED

/* Protocol type references decompression array. ref: Table 7-3 p. 110 ETSI EN 301 545-2 v.1.2.1 */
static const uint16_t rle_header_ptype_decomp[RLE_PROTO_TYPE_MAX_COMP_VALUE + 1] = {
	/* 0x00 -> 0x1a */
	0x0000,
	0x0001,
	0x0002,
	0x0003,
	0x00c8,
	0x0100,
	0x0200,
	0x0300,
	0x0301,
	0x03c3,
	0x0400,
	0x04c2,
	0x0500,
	RLE_PROTO_TYPE_IPV4_UNCOMP,
	0x0806,
	RLE_PROTO_TYPE_VLAN_UNCOMP,
	0x22f1,
	RLE_PROTO_TYPE_IPV6_UNCOMP,
	0x8809,
	0x8847,
	0x8848,
	0x8863,
	0x8864,
	0x888e,
	0x8906,
	RLE_PROTO_TYPE_VLAN_QINQ_UNCOMP,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_UNCOMP,
	/* 0x1b -> 0x2f */
	RLE_PROTO_TYPE_RESERVED_21,
	/* 0x30 -> 0x31 */
	RLE_PROTO_TYPE_IPV4_OR_IPV6,
	RLE_PROTO_TYPE_VLAN_UNCOMP,
	/* 0x32 -> 0x41 */
	RLE_PROTO_TYPE_RESERVED_16,
	/* 0x42 -> 0x47 */
	RLE_PROTO_TYPE_SIGNAL_UNCOMP,
	/* TODO: Find the good value for "Chaff filling connection with TRANSEC". */
	/*  ETSI EN 301 545-2 v.1.2.1 referes to ETSI TS 101 545-1 v1.2.1 that referes to IETF... */
	RLE_PROTO_TYPE_RESERVED,
	/*  ETSI EN 301 545-2 v.1.2.1 referes to ETSI TS 101 545-1 v1.2.1 that referes to IETF... */
	/* TODO: Find the good value for "X.509 certificate exchange". */
	RLE_PROTO_TYPE_RESERVED,
	0x0085,
	0x0083,
	/* 0x48 -> 0x7f */
	RLE_PROTO_TYPE_RESERVED_56,
	/* 0x80 -> 0xfe */
	RLE_PROTO_TYPE_USER_DEFINED_127,
	/* 0xff */
	RLE_PROTO_TYPE_ADJACENT_2BYTES_PTYPE
};


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

uint16_t rle_header_ptype_decompression(uint8_t compressed_ptype)
{
	uint16_t uncompressed_ptype = 0x0000;

	uncompressed_ptype = rle_header_ptype_decomp[compressed_ptype];

	return uncompressed_ptype;
}

int rle_header_ptype_is_compressible(uint16_t uncompressed_ptype)
{
	int return_value = C_ERROR;

	switch (uncompressed_ptype) {
	case RLE_PROTO_TYPE_SIGNAL_UNCOMP:
	case RLE_PROTO_TYPE_VLAN_UNCOMP:
	case RLE_PROTO_TYPE_VLAN_QINQ_UNCOMP:
	case RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_UNCOMP:
	case RLE_PROTO_TYPE_IPV4_UNCOMP:
	case RLE_PROTO_TYPE_IPV6_UNCOMP:
	case RLE_PROTO_TYPE_ARP_UNCOMP:
		/* TODO: To modify when RLE_PROTO_TYPE_SACH_UNCOMP and RLE_PROTO_TYPE_IP_UNCOMP will be
		 * different. */
		/* case RLE_PROTO_TYPE_SACH_UNCOMP:
		 * compressed_ptype = RLE_PROTO_TYPE_SACH_COMP;
		 * break; */
		return_value = C_OK;
		break;
	default:
		break;
	}

	return return_value;
}

uint8_t rle_header_ptype_compression(uint16_t uncompressed_ptype)
{
	uint8_t compressed_ptype = 0x00;

	switch (uncompressed_ptype) {
	case RLE_PROTO_TYPE_SIGNAL_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_SIGNAL_COMP;
		break;
	case RLE_PROTO_TYPE_VLAN_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_VLAN_COMP;
		break;
	case RLE_PROTO_TYPE_VLAN_QINQ_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_VLAN_QINQ_COMP;
		break;
	case RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_COMP;
		break;
	case RLE_PROTO_TYPE_IPV4_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_IPV4_COMP;
		break;
	case RLE_PROTO_TYPE_IPV6_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_IPV6_COMP;
		break;
	case RLE_PROTO_TYPE_ARP_UNCOMP:
		compressed_ptype = RLE_PROTO_TYPE_ARP_COMP;
		break;
	/* TODO: To modify when RLE_PROTO_TYPE_SACH_UNCOMP and RLE_PROTO_TYPE_IP_UNCOMP will be
	 * different. */
	/* case RLE_PROTO_TYPE_SACH_UNCOMP:
	 * compressed_ptype = RLE_PROTO_TYPE_SACH_COMP;
	 * break; */
	default:
		break;
	}

	return compressed_ptype;
}

uint8_t get_alpdu_label_type(const uint16_t protocol_type,
                             const bool is_protocol_type_suppressed,
                             const uint8_t type_0_alpdu_label_size)
{
	int alpdu_label_type = 0; /* 0 by default. */

	if (protocol_type == RLE_PROTO_TYPE_SIGNAL_UNCOMP) {
		/* RCS2 requirement */
		alpdu_label_type = RLE_LT_PROTO_SIGNAL;
	} else if (is_protocol_type_suppressed && type_0_alpdu_label_size != 0) {
		alpdu_label_type = RLE_LT_IMPLICIT_PROTO_TYPE;
	}

	return alpdu_label_type;
}

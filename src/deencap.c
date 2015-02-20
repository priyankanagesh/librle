#include "deencap.h"
#include "rle_header_proto_type_field.h" 

/* Protocol type references decompression array. ref: Table 7-3 p. 110 ETSI EN 301 545-2 v.1.2.1 */
/* TODO: Eventualy, change every hex value by a RLE_PROTO_TYPE_..._UNCOMP. */
/* TODO: Const ? Not sure if we use a variable for IPv4 <-> IPv6... */
uint16_t rle_header_proto_type_protocol_references_decomp[RLE_PROTO_TYPE_MAX_COMP_VALUE + 1] = {
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
	/* TODO: Choose between IPv4 or v6, maybe with a variable, modified by the conf. */
	RLE_PROTO_TYPE_IPV4_OR_IPV6,
	/* TODO: Choose between IPv4 or v6, maybe with a variable, modified by the conf. */
	RLE_PROTO_TYPE_IPV4_OR_IPV6,
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
	0x0086,
	0x0083,
	/* 0x48 -> 0x7f */
	RLE_PROTO_TYPE_RESERVED_56,
	/* 0x80 -> 0xfe */
	RLE_PROTO_TYPE_USER_DEFINED_127,
	/* 0xff */
	RLE_PROTO_TYPE_ADJACENT_2BYTES_PTYPE
};

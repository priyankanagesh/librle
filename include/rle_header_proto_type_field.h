/**
 * @file   rle_header_proto_type_field.h
 * @brief  Definition of RLE header protocol type fields constant values and meanings.
 *         Removed from header for more readibility, especialy since the ICD v.10 specifications.
 * @author Henrick Deschamps, based on Aurelien Castanie works.
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <stdint.h>

#ifndef __RLE_HEADER_PROTO_TYPE_FIELD_H__
#define __RLE_HEADER_PROTO_TYPE_FIELD_H__

/** Label Type for implicit protocol type */
#define RLE_LT_IMPLICIT_PROTO_TYPE         2
/** Label Type for protocol signalling */
#define RLE_LT_PROTO_SIGNAL                3
/** Type field - protocol type not supressed */
#define RLE_T_PROTO_TYPE_NO_SUPP           0
/** Type field - protocol type supressed */
#define RLE_T_PROTO_TYPE_SUPP              1

/** Protocol types field values compressed. */
enum {
	/* for signaling. */
	RLE_PROTO_TYPE_SIGNAL_COMP              = 0x42,
	/*	for VLAN. */
	RLE_PROTO_TYPE_VLAN_COMP                = 0x0f,
	RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD = 0x31,
	RLE_PROTO_TYPE_VLAN_QINQ_COMP           = 0x19,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_COMP    = 0x1a,
	/*	for IPv4/v6. */
	RLE_PROTO_TYPE_IP_COMP                  = 0x30,
	RLE_PROTO_TYPE_IPV4_COMP                = 0x0d,
	RLE_PROTO_TYPE_IPV6_COMP                = 0x11,
	/*	for ARP. */
	/* TODO: ARP not in the RLE_ICD v.10 (19/02/2015). Should we considere to remove it ? */
	RLE_PROTO_TYPE_ARP_COMP                 = 0x0e,
	/*	for SACH. */
	/* TODO: SACH not in the RLE_ICD v.10 (19/02/2015). Should we considere to remove it ? */
	/* TODO modify */
	RLE_PROTO_TYPE_SACH_COMP                = RLE_PROTO_TYPE_IP_COMP
};

/** Protocol types field values uncompressed. */
enum {
	/*	for signaling */
	RLE_PROTO_TYPE_SIGNAL_UNCOMP            = 0x0082,
	/*	for VLAN */
	RLE_PROTO_TYPE_VLAN_UNCOMP              = 0x8100,
	RLE_PROTO_TYPE_VLAN_QINQ_UNCOMP         = 0x88a8,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_UNCOMP  = 0x9100,
	/*	for IPv4/v6 */
	RLE_PROTO_TYPE_IPV4_UNCOMP              = 0x0800,
	RLE_PROTO_TYPE_IPV6_UNCOMP              = 0x86dd,
	/*	for ARP */
	/* TODO: ARP not in the ICD (19/02/2015). Should we considere to remove it ? */
	RLE_PROTO_TYPE_ARP_UNCOMP               = 0x0806,
	/*	for SACH */
	/* TODO: SACH not in the ICD (19/02/2015). Should we considere to remove it ? */
	/* TODO modify */
	RLE_PROTO_TYPE_SACH_UNCOMP              = RLE_PROTO_TYPE_IPV4_UNCOMP
};


/**
 * @brief		RLE header decompression of protocol type function.
 *
 * @param[in]	compressed_ptype                A compressed protocol type to uncompress.
 *
 * @return		The uncompressed protocol type.
 *
 * @ingroup
 */
uint16_t rle_header_ptype_decompression(uint8_t compressed_ptype);


/**
 * @brief		RLE header check if protocol type is compressable function.
 *
 * @param[in]	uncompressed_ptype	An uncompressed protocol type to compress.
 *
 * @return		C_OK if the protocol type is compressable else C_ERROR.
 *
 * @ingroup
 */
int rle_header_ptype_is_compressable(uint16_t uncompressed_ptype);

/**
 * @brief		RLE header compression of protocol type function.
 *
 * @param[in]	uncompressed_ptype	An uncompressed protocol type to compress.
 *
 * @return		The compressed protocol type.
 *
 * @ingroup
 */
uint8_t rle_header_ptype_compression(uint16_t uncompressed_ptype);

/** Max size of input packet (PDU) in Bytes */
#define RLE_MAX_PDU_SIZE                   4088
/** Size of Protocol Type uncompressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP   2
/** Size of Protocol Type compressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_COMP     1

/** Max protocol type compressed value */
#define RLE_PROTO_TYPE_MAX_COMP_VALUE      0xff

/**
 * Special procotol type values.
 *
 *	Chosen from among reserved values in IEEE public EtherType list.
 *	May evolve in the future.
 *
 *	@see http://standards.ieee.org/develop/regauth/ethertype/eth.txt
 */
enum {
	RLE_PROTO_TYPE_RESERVED                 = 0x0b04,
	RLE_PROTO_TYPE_USER_DEFINED,
	RLE_PROTO_TYPE_IPV4_OR_IPV6,
	RLE_PROTO_TYPE_ADJACENT_2BYTES_PTYPE
};

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

#endif /* __RLE_HEADER_PROTO_TYPE_FIELD_H__ */

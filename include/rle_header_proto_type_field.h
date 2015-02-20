/**
 * @file        rle_header_proto_type_field.h
 * @author      Henrick Deschamps
 *                      Based on Aurelien Castanie works.
 * @brief	Definition of RLE header protocol type fields constant values and meanings.
 *				Removed from header for more readibility, especialy since the ICD v.10 specifications.
 *
 */

#include <stdint.h>

#ifndef _RLE_HEADER_PROTO_TYPE_H
#define _RLE_HEADER_PROTO_TYPE_H

/** Label Type for implicit protocol type */
#define RLE_LT_IMPLICIT_PROTO_TYPE         2
/** Label Type for protocol signalling */
#define RLE_LT_PROTO_SIGNAL                3
/** Type field - protocol type not supressed */
#define RLE_T_PROTO_TYPE_NO_SUPP           0
/** Type field - protocol type supressed */
#define RLE_T_PROTO_TYPE_SUPP              1

/* Protocol types field values: */
/*		compressed */
enum {
	/*		for signaling */
	RLE_PROTO_TYPE_SIGNAL_COMP              = 0x42,
	/*		for VLAN */
	RLE_PROTO_TYPE_VLAN_COMP                = 0x0f,
	RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD = 0x31,
	RLE_PROTO_TYPE_VLAN_QINQ_COMP           = 0x19,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_COMP    = 0x1a,
	/*		for IPv4/v6 */
	RLE_PROTO_TYPE_IP_COMP                  = 0x30,
	RLE_PROTO_TYPE_IPV4_COMP                = 0x0d,
	RLE_PROTO_TYPE_IPV6_COMP                = 0x11,
	/*		for ARP */
	/* TODO: ARP not in the RLE_ICD v.10 (19/02/2015). Should we considere to remove it ? */
	RLE_PROTO_TYPE_ARP_COMP                 = 0x0e,
	/*		for SACH */
	/* TODO modify */
	/* TODO: SACH not in the RLE_ICD v.10 (19/02/2015). Should we considere to remove it ? */
	RLE_PROTO_TYPE_SACH_COMP                = RLE_PROTO_TYPE_IP_COMP
};

/*		uncompressed. */
enum {
	/*		for signaling */
	RLE_PROTO_TYPE_SIGNAL_UNCOMP            = 0x0082,
	/*		for VLAN */
	RLE_PROTO_TYPE_VLAN_UNCOMP              = 0x8100,
	RLE_PROTO_TYPE_VLAN_QINQ_UNCOMP         = 0x88a8,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_UNCOMP  = 0x9100,
	/*		for IPv4/v6 */
	RLE_PROTO_TYPE_IPV4_UNCOMP              = 0x0800,
	RLE_PROTO_TYPE_IPV6_UNCOMP              = 0x86dd,
	/*		for ARP */
	/* TODO: ARP not in the ICD (19/02/2015). Should we considere to remove it ? */
	RLE_PROTO_TYPE_ARP_UNCOMP               = 0x0806,
	/*		for SACH */
	/* TODO modify */
	/* TODO: SACH not in the ICD (19/02/2015). Should we considere to remove it ? */
	RLE_PROTO_TYPE_SACH_UNCOMP              = RLE_PROTO_TYPE_IPV4_UNCOMP
};

/** Sizes */
/** Max size of input packet (PDU) in Bytes */
#define RLE_MAX_PDU_SIZE                   4088
/** Size of Protocol Type uncompressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP   2
/** Size of Protocol Type compressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_COMP     1

#define RLE_PROTO_TYPE_MAX_COMP_VALUE      0xFF

/* Special procotol type values */
enum {
	RLE_PROTO_TYPE_RESERVED                 = 0x0b04,
	RLE_PROTO_TYPE_USER_DEFINED,
	RLE_PROTO_TYPE_IPV4_OR_IPV6,
	RLE_PROTO_TYPE_ADJACENT_2BYTES_PTYPE
};

/** Lots of define to easily populate the array of protocol references.
 *
 * For instance POW_2(RLE_PROTO_TYPE_RESERVED) is replaced by
 * "RLE_PROTO_TYPE_RESERVED, RLE_PROTO_TYPE_RESERVED" by the preprocessor.
 * We can write array "arr[2] = { POW_2(RLE_PROTO_TYPE_RESERVED) };"
 * and the preprocessor replace it by
 * "arr[2] = { RLE_PROTO_TYPE_RESERVED, RLE_PROTO_TYPE_RESERVED };"
 *
 */
#define POW_2(_x)  (_x), (_x)
#define POW_4(_x)  POW_2(_x), POW_2(_x)
#define POW_8(_x)  POW_4(_x), POW_4(_x)
#define POW_16(_x) POW_8(_x), POW_8(_x)
#define POW_32(_x) POW_16(_x), POW_16(_x)
#define POW_64(_x) POW_32(_x), POW_32(_x)

#define RLE_PROTO_TYPE_RESERVED_16      POW_16(RLE_PROTO_TYPE_RESERVED)

#define RLE_PROTO_TYPE_RESERVED_21      POW_16(RLE_PROTO_TYPE_RESERVED), \
        POW_4(RLE_PROTO_TYPE_RESERVED), \
        RLE_PROTO_TYPE_RESERVED

#define RLE_PROTO_TYPE_RESERVED_56      POW_32(RLE_PROTO_TYPE_RESERVED), \
        POW_16(RLE_PROTO_TYPE_RESERVED), \
        POW_8(RLE_PROTO_TYPE_RESERVED)

#define RLE_PROTO_TYPE_USER_DEFINED_127 POW_64(RLE_PROTO_TYPE_USER_DEFINED), \
        POW_32(RLE_PROTO_TYPE_USER_DEFINED), \
        POW_16(RLE_PROTO_TYPE_USER_DEFINED), \
        POW_8(RLE_PROTO_TYPE_USER_DEFINED), \
        POW_4(RLE_PROTO_TYPE_USER_DEFINED), \
        POW_2(RLE_PROTO_TYPE_USER_DEFINED), \
        RLE_PROTO_TYPE_USER_DEFINED

#endif /* _RLE_HEADER_PROTO_TYPE_H */

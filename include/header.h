/**
 * @file   header.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE header constants, functions and variables
 *
 *
 */

#ifndef _HEADER_H
#define _HEADER_H

#include <endian.h>
#include <stdint.h>

/** Label Type for implicit protocol type */
#define RLE_LT_IMPLICIT_PROTO_TYPE		2
/** Label Type for protocol signalling */
#define RLE_LT_PROTO_SIGNAL			3
/** Type field - protocol type not supressed */
#define RLE_T_PROTO_TYPE_NO_SUPP		0
/** Type field - protocol type supressed */
#define RLE_T_PROTO_TYPE_SUPP			1
/** Protocol type for signalling compressed */
#define RLE_PROTO_TYPE_SIGNAL_COMP		0x42
/** Protocol type for signalling non compressed */
#define RLE_PROTO_TYPE_SIGNAL_UNCOMP		0x0082
/** Protocol type for VLAN 802.1q */
#define RLE_PROTO_TYPE_VLAN			0x8100
/** Protocol type for VLAN stacking 802.3ad */
#define RLE_PROTO_TYPE_VLAN_STACKING		0x88a8
/** Protocol type for VLAN Q-in-Q */
#define RLE_PROTO_TYPE_VLAN_QINQ		0x9100
/** Protocol type for ARP */
#define RLE_PROTO_TYPE_ARP			0x0806
/** Protocol type compressed for IPv4/v6 */
#define RLE_PROTO_TYPE_IP_COMP			0x30
/** Protocol type uncompressed for IPv4 */
#define RLE_PROTO_TYPE_IPV4_UNCOMP		0x0800
/** Protocol type uncompressed for IPv6 */
#define RLE_PROTO_TYPE_IPV6_UNCOMP		0x86dd
/** Protocol type uncompressed for SACH
 * TODO modify */
#define RLE_PROTO_TYPE_SACH_UNCOMP		RLE_PROTO_TYPE_IPV4_UNCOMP
/** Protocol type compressed for SACH
 * TODO modify */
#define RLE_PROTO_TYPE_SACH_COMP		RLE_PROTO_TYPE_IP_COMP
/** Max size of input packet (PDU) in Bytes */
#define RLE_MAX_PDU_SIZE			4096
/** Size of Protocol Type uncompressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP	2
/** Size of Protocol Type compressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_COMP		1
/** Size of mandatory fields in a start packet in Bytes */
#define RLE_START_MANDATORY_HEADER_SIZE		4
/** Size of fields in a continuation packet in Bytes */
#define RLE_CONT_HEADER_SIZE			2
/** Size of fields in a end packet in Bytes */
#define RLE_END_HEADER_SIZE			RLE_CONT_HEADER_SIZE
/** Size of fields in a complete packet in Bytes without
 * protocol type field */
#define RLE_COMPLETE_HEADER_SIZE		RLE_CONT_HEADER_SIZE
/**  Max value of fragment_id */
#define RLE_MAX_FRAG_ID				7
/**  Max number of fragment id */
#define RLE_MAX_FRAG_NUMBER			(RLE_MAX_FRAG_ID + 1)

/** Macros to set Label Type,
 *  Protocol Type Suppressed
 *  and Fragment ID
 *  on a union rle_header_all */
#if __BYTE_ORDER == __LITTLE_ENDIAN

#define SET_LABEL_TYPE(_y,_x)  do {				\
			(_y) = ((_y & 0x1) ^ (_x << 1));	\
		} while (0)

#define GET_LABEL_TYPE(_y) ((_y) >> 1)

#define SET_PROTO_TYPE_SUPP(_y,_x) do {			\
			(_y) = ((_y & 0x6) ^ (_x));	\
		} while (0)

#define GET_PROTO_TYPE_SUPP(_y) ((_y) & 0x1)

#elif __BYTE_ORDER == __BIG_ENDIAN

#define SET_LABEL_TYPE(_y,_x)  do {			\
			(_y) = ((_y & 0x4) ^ (_x));	\
		} while (0)

#define GET_LABEL_TYPE(_y) ((_y) & 0x7)

#define SET_PROTO_TYPE_SUPP(_y,_x) do {				\
			(_y) = ((_y & 0x3) ^ (_x << 2));	\
		} while (0)

#define GET_PROTO_TYPE_SUPP(_y) ((_y) >> 2)

#else
#error "Please fix <asm/byteorder.h>"
#endif

#define SET_FRAG_ID(_y,_x) do {				\
			(_y) = (_x);			\
		} while(0)

/*
 * common RLE packet header
 * for complete, START, CONT,
 * END packet
 * */
union rle_header_all {
	uint16_t all;
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint16_t start_ind:1;
		uint16_t end_ind:1;
		uint16_t rle_packet_length:11;
		uint16_t LT_T_FID:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t LT_T_FID:3;
		uint16_t rle_packet_length:11;
		uint16_t end_ind:1;
		uint16_t start_ind:1;
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
		uint16_t total_length:13;
		uint16_t label_type:2; /* LT for fragmented packet */
		uint16_t proto_type_supp:1; /* T for fragmented packet */
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t proto_type_supp:1;
		uint16_t label_type:2;
		uint16_t total_length:13;
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
			uint8_t proto_type;
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
			uint8_t proto_type;
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

#endif /* _HEADER_H */

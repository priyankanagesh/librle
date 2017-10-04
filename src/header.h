/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

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
#include <stdbool.h>

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

#include "rle.h"

#include "constants.h"
#include "rle_header_proto_type_field.h"


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------- PROTECTED STRUCTS AND TYPEDEFS --------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Stubs for visibility */
struct rle_ctx_mngt;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** * RLE PPDU start header */
struct rle_ppdu_hdr_start {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t pkt_len_1       : 6;
	uint32_t end_ind         : 1;
	uint32_t start_ind       : 1;
	uint32_t frag_id         : 3;
	uint32_t pkt_len_2       : 5;
	uint32_t total_len_1     : 7;
	uint32_t use_crc         : 1;
	uint32_t proto_type_supp : 1;
	uint32_t label_type      : 2;
	uint32_t total_len_2     : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t start_ind       : 1;
	uint32_t end_ind         : 1;
	uint32_t pkt_len         : 11;
	uint32_t frag_id         : 3;
	uint32_t use_crc         : 1;
	uint32_t total_len       : 12;
	uint32_t label_type      : 2;
	uint32_t proto_type_supp : 1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/** RLE PPDU start header definition */
typedef struct rle_ppdu_hdr_start rle_ppdu_hdr_start_t;

/** RLE PPDU complete header */
struct rle_ppdu_hdr_comp {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t pkt_len_1       : 6;
	uint16_t end_ind         : 1;
	uint16_t start_ind       : 1;
	uint16_t proto_type_supp : 1;
	uint16_t label_type      : 2;
	uint16_t pkt_len_2       : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t start_ind       : 1;
	uint16_t end_ind         : 1;
	uint16_t pkt_len         : 11;
	uint16_t label_type      : 2;
	uint16_t proto_type_supp : 1;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/** RLE PPDU completet header definition */
typedef struct rle_ppdu_hdr_comp rle_ppdu_hdr_comp_t;

/** RLE PPDU continuation or end header */
struct rle_ppdu_hdr_cont_end {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t pkt_len_1   : 6;
	uint16_t end_ind     : 1;
	uint16_t start_ind   : 1;
	uint16_t frag_id     : 3;
	uint16_t pkt_len_2   : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t start_ind   : 1;
	uint16_t end_ind     : 1;
	uint16_t pkt_len     : 11;
	uint16_t frag_id     : 3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
} __attribute__ ((packed));

/** RLE PPDU contininuation or end header definition. */
typedef struct rle_ppdu_hdr_cont_end rle_ppdu_hdr_cont_end_t;

/** RLE PPDU header.  */
union rle_ppdu_hdr {
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		uint16_t rle_packet_length_1 : 6;
		uint16_t end_ind             : 1;
		uint16_t start_ind           : 1;
		uint16_t                     : 3;
		uint16_t rle_packet_length_2 : 5;
#elif __BYTE_ORDER == __BIG_ENDIAN
		uint16_t start_ind           : 1;
		uint16_t end_ind             : 1;
		uint16_t rle_packet_length   : 11;
		uint16_t                     : 3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	} __attribute__ ((packed)) common;
	rle_ppdu_hdr_start_t start;
	rle_ppdu_hdr_cont_end_t cont;
	rle_ppdu_hdr_cont_end_t end;
	rle_ppdu_hdr_comp_t comp;
} __attribute__ ((packed));

/** RLE PPDU header definition. */
typedef union rle_ppdu_hdr rle_ppdu_hdr_t;


/** RLE uncompressed ALPDU header. */
struct rle_alpdu_hdr_uncomp {
	uint16_t proto_type;
} __attribute__ ((packed));

/** RLE uncompressed ALPDU header definition. */
typedef struct rle_alpdu_hdr_uncomp rle_alpdu_hdr_uncomp_t;


/** RLE compressed supported ALPDU header. */
struct rle_alpdu_hdr_comp_supported {
	uint8_t proto_type;
} __attribute__ ((packed));

/** RLE compressed supported ALPDU header definition. */
typedef struct rle_alpdu_hdr_comp_supported rle_alpdu_hdr_comp_supported_t;


/** RLE compressed fallback ALPDU header. */
struct rle_alpdu_hdr_comp_fallback {
	rle_alpdu_hdr_comp_supported_t comp;
	rle_alpdu_hdr_uncomp_t uncomp;
} __attribute__ ((packed));

/** RLE compressed fallback ALPDU header definition. */
typedef struct rle_alpdu_hdr_comp_fallback rle_alpdu_hdr_comp_fallback_t;

/** RLE ALPDU header. */
union rle_alpdu_hdr {
	rle_alpdu_hdr_uncomp_t uncomp;
	rle_alpdu_hdr_comp_supported_t comp_supported;
	rle_alpdu_hdr_comp_fallback_t comp_fallback;
} __attribute__ ((packed));

/** RLE ALPDU header definition. */
typedef union rle_alpdu_hdr rle_alpdu_hdr_t;


/** The IEEE 802.1q (VLAN) header */
struct vlan_hdr {
	union {
		uint16_t tci;         /**< Tag Control Information (TCI) */
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint16_t pcp : 3;    /**< Priority Code Point (PCP) */
			uint16_t dei : 1;    /**< Drop Eligible Indicator (DEI) */
			uint16_t vid : 12;   /**< VLAN identifier (VID) */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t vid : 12;
			uint16_t dei : 1;
			uint16_t pcp : 3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint16_t tpid;           /**< Tag Protocol Identifier (TPID) */
} __attribute__((packed));



/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief Check whether the Ethernet/VLAN header contains IP or not
 *
 * @param sdu      The SDU to check for Ethernet/VLAN/IP
 * @param sdu_len  The length of the SDU to check
 * @return         RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD if the frame is Ethernet/VLAN/IPv4,
 *                 RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD if the frame is Ethernet/VLAN/IPv6,
 *                 RLE_PROTO_TYPE_VLAN_COMP if the frame is Ethernet/VLAN/<not IPv4 nor IPv6>,
 *                 RLE_PROTO_TYPE_FALLBACK if the SDU is malformed
 *
 * @ingroup RLE header
 */
int is_eth_vlan_ip_frame(const uint8_t *const sdu, const size_t sdu_len)
__attribute__((warn_unused_result, nonnull(1)));

/**
 *  @brief         create and push ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf             the fragmentation buffer in use.
 *  @param[in]     rle_conf             the RLE configuration
 *
 *  @ingroup RLE header
 */
void push_alpdu_hdr(struct rle_frag_buf *const frag_buf,
                    const struct rle_config *const rle_conf);

/**
 *  @brief         create and push PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf             the fragmentation buffer in use.
 *  @param[in]     rle_conf             the RLE configuration
 *  @param[in,out] rle_ctx              the RLE context if needed (NULL if not).
 *
 *  @return        true if OK
 *                 false if buffer is too small for the smallest PPDU fragment
 *
 *  @ingroup RLE header
 */
bool push_ppdu_hdr(struct rle_frag_buf *const frag_buf,
                   const struct rle_config *const rle_conf,
                   const size_t ppdu_len,
                   struct rle_ctx_mngt *const rle_ctx);

/**
 *  @brief         Extract ALPDU fragment from complete PPDU.
 *
 *
 *  @param[in]     comp_ppdu        the complete PPDU.
 *  @param[in]     ppdu_len         the length of the complete PPDU.
 *  @param[out]    alpdu_frag       the ALPDU fragment extracted.
 *  @param[out]    alpdu_frag_len   the length of the ALPDU fragment extracted.
 *
 *  @ingroup RLE header
 */
void comp_ppdu_extract_alpdu_frag(unsigned char comp_ppdu[],
                                  const size_t ppdu_len,
                                  unsigned char **alpdu_frag,
                                  size_t *alpdu_frag_len);

/**
 *  @brief         Extract ALPDU fragment from start PPDU.
 *
 *
 *  @param[in]     start_ppdu       the complete PPDU.
 *  @param[in]     ppdu_len         the length of the complete PPDU.
 *  @param[out]    alpdu_frag       the ALPDU fragment extracted.
 *  @param[out]    alpdu_frag_len   the length of the ALPDU fragment extracted.
 *  @param[out]    alpdu_total_len  the length of the full ALPDU.
 *  @param[out]    is_crc_used      wether CRC is used or not.
 *
 *  @ingroup RLE header
 */
void start_ppdu_extract_alpdu_frag(unsigned char start_ppdu[],
                                   const size_t ppdu_len,
                                   unsigned char *alpdu_frag[],
                                   size_t *const alpdu_frag_len,
                                   size_t *const alpdu_total_len,
                                   int *const is_crc_used);

/**
 *  @brief         Extract ALPDU fragment from cont or end PPDU.
 *
 *
 *  @param[in]     cont_end_ppdu   the cont or end PPDU.
 *  @param[in]     ppdu_len        the length of the complete PPDU.
 *  @param[out]    alpdu_frag      the ALPDU fragment extracted.
 *  @param[out]    alpdu_frag_len  the length of the ALPDU fragment extracted.
 *
 *  @ingroup RLE header
 */
void cont_end_ppdu_extract_alpdu_frag(const unsigned char cont_end_ppdu[],
                                      const size_t ppdu_len,
                                      const unsigned char *alpdu_frag[],
                                      size_t *const alpdu_frag_len);

/**
 *  @brief         Extract signel SDU from ALPDU.
 *
 *  @param[in]     alpdu_frag      the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_frag_len  the length of the ALPDU fragment.
 *  @param[out]    ptype           the protocol type extracted from the ALPDU header.
 *  @param[out]    comp_ptype      the compressed protocol type extracted from the ALPDU header
 *  @param[out]    sdu_frag        the fragment of SDU extracted.
 *  @param[out]    sdu_frag_len    the length of the SDU fragment.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int signal_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                  const size_t alpdu_frag_len,
                                  uint16_t *ptype,
                                  uint8_t *comp_ptype,
                                  const unsigned char *sdu_frag[],
                                  size_t *const sdu_frag_len);

/**
 *  @brief         Extract SDU from supressed ALPDU.
 *
 *  @param[in]     alpdu_frag      the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_frag_len  the length of the ALPDU fragment.
 *  @param[out]    ptype           the protocol type extracted from the ALPDU header.
 *  @param[out]    comp_ptype      the compressed protocol type extracted from the ALPDU header
 *  @param[out]    sdu_frag        the fragment of SDU extracted.
 *  @param[out]    sdu_frag_len    the length of the SDU fragment.
 *  @param[out]    rle_conf        the RLE configuration (for suppressed protocol type).
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int suppr_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                 const size_t alpdu_frag_len,
                                 uint16_t *ptype,
                                 uint8_t *comp_ptype,
                                 const unsigned char *sdu_frag[],
                                 size_t *const sdu_frag_len,
                                 const struct rle_config *const rle_conf);

/**
 *  @brief         Extract SDU fragment from uncompressed ALPDU.
 *
 *
 *  @param[in]     alpdu_frag      the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_frag_len  the length of the ALPDU fragment.
 *  @param[out]    ptype           the protocol type extracted from the ALPDU header.
 *  @param[out]    comp_ptype      the compressed protocol type extracted from the ALPDU header
 *  @param[out]    sdu_frag        the fragment of SDU extracted.
 *  @param[out]    sdu_frag_len    the length of the SDU fragment.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int uncomp_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                  const size_t alpdu_frag_len,
                                  uint16_t *ptype,
                                  uint8_t *comp_ptype,
                                  const unsigned char *sdu_frag[],
                                  size_t *const sdu_frag_len);

/**
 *  @brief         Extract SDU fragment from compressed ALPDU.
 *
 *
 *  @param[in]     alpdu_frag      the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_frag_len  the length of the ALPDU fragment.
 *  @param[out]    ptype           the protocol type extracted from the ALPDU header.
 *  @param[out]    comp_ptype      the compressed protocol type extracted from the ALPDU header
 *  @param[out]    sdu_frag        the fragment of SDU extracted.
 *  @param[out]    sdu_frag_len    the length of the SDU fragment.
 *  @param[out]    alpdu_hdr_len   the length of the ALPDU header
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int comp_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                const size_t alpdu_frag_len,
                                uint16_t *ptype,
                                uint8_t *comp_ptype,
                                const unsigned char *sdu_frag[],
                                size_t *const sdu_frag_len,
                                size_t *const alpdu_hdr_len);

/**
 *  @brief         Set the PPDU length field of a PPDU header.
 *
 *
 *  @param[in,out] ppdu_hdr          the PPDU header.
 *  @param[in]     ppdu_len          the PPDU length field value.
 *
 *  @ingroup RLE header
 */
static inline void rle_ppdu_hdr_set_ppdu_len(rle_ppdu_hdr_t *const ppdu_hdr,
                                             const uint16_t ppdu_len);

/**
 *  @brief         Get the PPDU length field of a PPDU header.
 *
 *  @param[in,out] ppdu_hdr          the PPDU header.
 *
 *  @return        the PPDU length field value.
 *
 *  @ingroup RLE header
 */
static inline uint16_t rle_ppdu_hdr_get_ppdu_length(const rle_ppdu_hdr_t *const ppdu_hdr);

/**
 *  @brief         Set the total length field of a start PPDU header.
 *
 *
 *  @param[in,out] ppdu_hdr             the PPDU header.
 *  @param[in]     total_len            the PPDU length field value.
 *
 *  @ingroup RLE header
 */
static inline void rle_ppdu_hdr_start_set_total_len(rle_ppdu_hdr_start_t *const ppdu_hdr,
                                                    const uint16_t total_len);

/**
 *  @brief         Get the total length field of a start PPDU header.
 *
 *  @param[in,out] ppdu_hdr             the PPDU header.
 *
 *  @return        the PPDU total length field value.
 *
 *  @ingroup RLE header
 */
static inline uint16_t rle_ppdu_hdr_start_get_total_len(const rle_ppdu_hdr_start_t *const ppdu_hdr);

/**
 *  @brief         Get if SDU in PPDU is signal.
 *
 *  @param[in,out] hdr                  the PPDU header.
 *
 *  @return        the PPDU total length field value.
 *
 *  @ingroup RLE header
 */
static inline bool rle_start_ppdu_hdr_get_is_signal(const rle_ppdu_hdr_start_t *const hdr);

/**
 *  @brief         Get if SDU in PPDU is signal.
 *
 *  @param[in,out] hdr                  the PPDU header.
 *
 *  @return        1 if signal, else 0.
 *
 *  @ingroup RLE header
 */
static inline bool rle_start_ppdu_hdr_get_is_suppressed(const rle_ppdu_hdr_start_t *const hdr);

/**
 *  @brief         Get if ALPDU in PPDU use CRC.
 *
 *  @param[in,out] hdr                  the PPDU header.
 *
 *  @return        1 if CRC, else 0.
 *
 *  @ingroup RLE header
 */
static inline int rle_start_ppdu_hdr_get_use_crc(const rle_ppdu_hdr_start_t *const hdr);

/**
 *  @brief         Get the fragment ID linked to a start PPDU.
 *
 *  @param[in,out] hdr                  the PPDU header.
 *
 *  @return        the fragment id.
 *
 *  @ingroup RLE header
 */
static inline uint8_t rle_start_ppdu_hdr_get_frag_id(const rle_ppdu_hdr_start_t *const hdr);

/**
 *  @brief         Get the fragment ID linked to a cont/end PPDU.
 *
 *  @param[in,out] hdr                  the PPDU header.
 *
 *  @return        the fragment id.
 *
 *  @ingroup RLE header
 */
static inline uint8_t rle_cont_end_ppdu_hdr_get_frag_id(const rle_ppdu_hdr_cont_end_t *const hdr);

/**
 *  @brief         Get the type of the PPDU fragment.
 *
 *  @param[in,out] hdr                  the PPDU header.
 *
 *  @return        the type of the PPDU fragment.
 *
 *  @ingroup RLE header
 */
static inline int rle_ppdu_get_fragment_type(const rle_ppdu_hdr_t *const hdr);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static inline void rle_ppdu_hdr_set_ppdu_len(rle_ppdu_hdr_t *const ppdu_hdr,
                                             const uint16_t ppdu_len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	ppdu_hdr->common.rle_packet_length_1 = ((ppdu_len & 0x7ff) >> 5) & 0x3f;
	ppdu_hdr->common.rle_packet_length_2 = ppdu_len & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	ppdu_hdr->common.rle_packet_length = ppdu_len;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return;
}

static inline uint16_t rle_ppdu_hdr_get_ppdu_length(const rle_ppdu_hdr_t *const ppdu_hdr)
{
	uint16_t ppdu_length = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	ppdu_length = ((ppdu_hdr->common.rle_packet_length_1 & 0x3f) << 5) & 0x7ff;
	ppdu_length |= ppdu_hdr->common.rle_packet_length_2 & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	ppdu_length = ppdu_hdr->common.rle_packet_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif

	return ppdu_length;
}

static inline void rle_ppdu_hdr_start_set_total_len(rle_ppdu_hdr_start_t *const ppdu_hdr,
                                                    const uint16_t total_len)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	ppdu_hdr->total_len_1 = ((total_len & 0xfff) >> 5) & 0x7f;
	ppdu_hdr->total_len_2 = total_len & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	ppdu_hdr->total_len = total_len;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return;
}

static inline uint16_t rle_ppdu_hdr_start_get_total_len(const rle_ppdu_hdr_start_t *const ppdu_hdr)
{
	uint16_t total_len = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	total_len = ((ppdu_hdr->total_len_1 & 0x7f) << 5) & 0xfff;
	total_len |= ppdu_hdr->total_len_2 & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	total_len = ppdu_hdr->total_len;
#else
#error "Please fix <asm/byteorder.h>"
#endif

	return total_len;
}

static inline bool rle_comp_ppdu_hdr_get_is_signal(const rle_ppdu_hdr_comp_t *const hdr)
{
	return !!(hdr->label_type == RLE_LT_PROTO_SIGNAL);
}

static inline bool rle_comp_ppdu_hdr_get_is_suppressed(const rle_ppdu_hdr_comp_t *const hdr)
{
	return !!(hdr->proto_type_supp == RLE_T_PROTO_TYPE_SUPP);
}

static inline bool rle_start_ppdu_hdr_get_is_signal(const rle_ppdu_hdr_start_t *const hdr)
{
	return !!(hdr->label_type == RLE_LT_PROTO_SIGNAL);
}

static inline bool rle_start_ppdu_hdr_get_is_suppressed(const rle_ppdu_hdr_start_t *const hdr)
{
	return !!(hdr->proto_type_supp == RLE_T_PROTO_TYPE_SUPP);
}

static inline int rle_start_ppdu_hdr_get_use_crc(const rle_ppdu_hdr_start_t *const hdr)
{
	return hdr->use_crc;
}

static inline uint8_t rle_start_ppdu_hdr_get_frag_id(const rle_ppdu_hdr_start_t *const hdr)
{
	return hdr->frag_id;
}

static inline uint8_t rle_cont_end_ppdu_hdr_get_frag_id(const rle_ppdu_hdr_cont_end_t *const hdr)
{
	return hdr->frag_id;
}

static inline int rle_ppdu_get_fragment_type(const rle_ppdu_hdr_t *const hdr)
{
	int type_rle_frag;

	if (hdr->common.start_ind) {
		if (hdr->common.end_ind) {
			type_rle_frag = RLE_PDU_COMPLETE;
		} else {
			type_rle_frag = RLE_PDU_START_FRAG;
		}
	} else {
		if (hdr->common.end_ind) {
			type_rle_frag = RLE_PDU_END_FRAG;
		} else {
			type_rle_frag = RLE_PDU_CONT_FRAG;
		}
	}

	return type_rle_frag;
}


#endif /* __HEADER_H__ */

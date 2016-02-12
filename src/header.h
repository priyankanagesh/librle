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
/*-------------------------------- PROTECTED STRUCTS AND TYPEDEFS --------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Stubs for visibility */
struct rle_ctx_management;

/** Stubs for visibility */
struct rle_configuration;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** * RLE PPDU start header */
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
typedef struct rle_ppdu_header_start rle_ppdu_header_start_t;

/** RLE PPDU complete header */
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
typedef struct rle_ppdu_header_comp rle_ppdu_header_comp_t;

/** RLE PPDU continuation or end header */
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

/** RLE PPDU contininuation or end header definition. */
typedef struct rle_ppdu_header_cont_end rle_ppdu_header_cont_end_t;

/** RLE PPDU header.  */
union rle_ppdu_header {
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
	rle_ppdu_header_start_t    start;
	rle_ppdu_header_cont_end_t cont;
	rle_ppdu_header_cont_end_t end;
	rle_ppdu_header_comp_t     comp;
} __attribute__ ((packed));

/** RLE PPDU header definition. */
typedef union rle_ppdu_header rle_ppdu_header_t;


/** RLE uncompressed ALPDU header. */
struct rle_alpdu_header_uncompressed {
	uint16_t proto_type;
} __attribute__ ((packed));

/** RLE uncompressed ALPDU header definition. */
typedef struct rle_alpdu_header_uncompressed rle_alpdu_header_uncompressed_t;


/** RLE compressed supported ALPDU header. */
struct rle_alpdu_header_compressed_supported {
	uint8_t proto_type;
} __attribute__ ((packed));

/** RLE compressed supported ALPDU header definition. */
typedef struct rle_alpdu_header_compressed_supported rle_alpdu_header_compressed_supported_t;


/** RLE compressed fallback ALPDU header. */
struct rle_alpdu_header_compressed_fallback {
	rle_alpdu_header_compressed_supported_t compressed;
	rle_alpdu_header_uncompressed_t uncompressed;
} __attribute__ ((packed));

/** RLE compressed fallback ALPDU header definition. */
typedef struct rle_alpdu_header_compressed_fallback rle_alpdu_header_compressed_fallback_t;

/** RLE ALPDU header. */
union rle_alpdu_header {
	rle_alpdu_header_uncompressed_t uncompressed;
	rle_alpdu_header_compressed_supported_t compressed_supported;
	rle_alpdu_header_compressed_fallback_t compressed_fallback;
} __attribute__ ((packed));

/** RLE ALPDU header definition. */
typedef union rle_alpdu_header rle_alpdu_header_t;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief         create and push ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     rle_conf             the RLE configuration
 *
 *  @return C_ERROR if KO
 *                C_OK if OK
 *
 *  @ingroup RLE header
 */
int push_alpdu_header(struct rle_fragmentation_buffer *const f_buff,
                      const struct rle_configuration *const rle_conf);

/**
 *  @brief         create and push PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] f_buff               the fragmentation buffer in use.
 *  @param[in]     rle_conf             the RLE configuration
 *  @param[in,out] rle_ctx              the RLE context if needed (NULL if not).
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int push_ppdu_header(struct rle_fragmentation_buffer *const f_buff,
                     const struct rle_configuration *const rle_conf,
                     const size_t ppdu_length, struct rle_ctx_management *const rle_ctx);

/**
 *  @brief         Extract ALPDU fragment from complete PPDU.
 *
 *
 *  @param[in]     comp_ppdu            the complete PPDU.
 *  @param[in]     ppdu_len             the length of the complete PPDU.
 *  @param[out]    alpdu_fragment       the ALPDU fragment extracted.
 *  @param[out]    alpdu_fragment_len   the length of the ALPDU fragment extracted.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int comp_ppdu_extract_alpdu_fragment(const unsigned char comp_ppdu[], const size_t ppdu_len,
                                     const unsigned char *alpdu_fragment[],
                                     size_t *alpdu_fragment_len);

/**
 *  @brief         Extract ALPDU fragment from start PPDU.
 *
 *
 *  @param[in]     start_ppdu           the complete PPDU.
 *  @param[in]     ppdu_len             the length of the complete PPDU.
 *  @param[out]    alpdu_fragment       the ALPDU fragment extracted.
 *  @param[out]    alpdu_fragment_len   the length of the ALPDU fragment extracted.
 *  @param[out]    alpdu_total_len      the length of the full ALPDU.
 *  @param[out]    is_crc_used          wether CRC is used or not.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int start_ppdu_extract_alpdu_fragment(const unsigned char start_ppdu[], const size_t ppdu_len,
                                      const unsigned char *alpdu_fragment[],
                                      size_t *const alpdu_fragment_len,
                                      size_t *const alpdu_total_len, int *const is_crc_used);

/**
 *  @brief         Extract ALPDU fragment from cont or end PPDU.
 *
 *
 *  @param[in]     cont_end_ppdu        the cont or end PPDU.
 *  @param[in]     ppdu_len             the length of the complete PPDU.
 *  @param[out]    alpdu_fragment       the ALPDU fragment extracted.
 *  @param[out]    alpdu_fragment_len   the length of the ALPDU fragment extracted.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int cont_end_ppdu_extract_alpdu_fragment(const unsigned char cont_end_ppdu[], const size_t ppdu_len,
                                         const unsigned char *alpdu_fragment[],
                                         size_t *const alpdu_fragment_len);

/**
 *  @brief         Extract signel SDU from ALPDU.
 *
 *  @param[in]     alpdu_fragment       the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_fragment_len   the length of the ALPDU fragment.
 *  @param[out]    protocol_type        the protocol type extracted from the ALPDU header.
 *  @param[out]    sdu_fragment         the fragment of SDU extracted.
 *  @param[out]    sdu_fragment_len     the length of the SDU fragment.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
void signal_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                       const size_t alpdu_fragment_len, uint16_t *protocol_type,
                                       const unsigned char *sdu_fragment[],
                                       size_t *const sdu_fragment_len);

/**
 *  @brief         Extract SDU from supressed ALPDU.
 *
 *  @param[in]     alpdu_fragment       the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_fragment_len   the length of the ALPDU fragment.
 *  @param[out]    protocol_type        the protocol type extracted from the ALPDU header.
 *  @param[out]    sdu_fragment         the fragment of SDU extracted.
 *  @param[out]    sdu_fragment_len     the length of the SDU fragment.
 *  @param[out]    rle_conf             the RLE configuration (for suppressed protocol type).
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
int suppressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                          const size_t alpdu_fragment_len, uint16_t *protocol_type,
                                          const unsigned char *sdu_fragment[],
                                          size_t *const sdu_fragment_len,
                                          const struct rle_configuration *const rle_conf);

/**
 *  @brief         Extract SDU fragment from uncompressed ALPDU.
 *
 *
 *  @param[in]     alpdu_fragment       the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_fragment_len   the length of the ALPDU fragment.
 *  @param[out]    protocol_type        the protocol type extracted from the ALPDU header.
 *  @param[out]    sdu_fragment         the fragment of SDU extracted.
 *  @param[out]    sdu_fragment_len     the length of the SDU fragment.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
void uncompressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                             const size_t alpdu_fragment_len,
                                             uint16_t *protocol_type,
                                             const unsigned char *sdu_fragment[],
                                             size_t *const sdu_fragment_len);

/**
 *  @brief         Extract SDU fragment from compressed ALPDU.
 *
 *
 *  @param[in]     alpdu_fragment       the ALPDU fragment containing the ALPDU header.
 *  @param[in]     alpdu_fragment_len   the length of the ALPDU fragment.
 *  @param[out]    protocol_type        the protocol type extracted from the ALPDU header.
 *  @param[out]    sdu_fragment         the fragment of SDU extracted.
 *  @param[out]    sdu_fragment_len     the length of the SDU fragment.
 *  @param[out]    sdu_total_len        the total length of the SDU.
 *
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup RLE header
 */
void compressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                           const size_t alpdu_fragment_len, uint16_t *protocol_type,
                                           const unsigned char *sdu_fragment[],
                                           size_t *const sdu_fragment_len,
                                           size_t *const sdu_total_len);

/**
 *  @brief         Set the PPDU length field of a PPDU header.
 *
 *
 *  @param[in,out] ppdu_header          the PPDU header.
 *  @param[in]     ppdu_length          the PPDU length field value.
 *
 *  @ingroup RLE header
 */
static inline void rle_ppdu_header_set_ppdu_length(rle_ppdu_header_t *const ppdu_header,
                                                   const uint16_t ppdu_length);

/**
 *  @brief         Get the PPDU length field of a PPDU header.
 *
 *  @param[in,out] ppdu_header          the PPDU header.
 *
 *  @return        the PPDU length field value.
 *
 *  @ingroup RLE header
 */
static inline uint16_t rle_ppdu_header_get_ppdu_length(const rle_ppdu_header_t *const ppdu_header);

/**
 *  @brief         Set the total length field of a start PPDU header.
 *
 *
 *  @param[in,out] ppdu_header          the PPDU header.
 *  @param[in]     total_length         the PPDU length field value.
 *
 *  @ingroup RLE header
 */
static inline void rle_ppdu_header_start_set_total_length(
        rle_ppdu_header_start_t *const ppdu_header, const uint16_t total_length);

/**
 *  @brief         Get the total length field of a start PPDU header.
 *
 *  @param[in,out] ppdu_header          the PPDU header.
 *
 *  @return        the PPDU total length field value.
 *
 *  @ingroup RLE header
 */
static inline uint16_t rle_ppdu_header_start_get_total_length(
        const rle_ppdu_header_start_t *const ppdu_header);

/**
 *  @brief         Get if SDU in PPDU is signal.
 *
 *  @param[in,out] header               the PPDU header.
 *
 *  @return        the PPDU total length field value.
 *
 *  @ingroup RLE header
 */
static inline int rle_start_ppdu_header_get_is_signal(const rle_ppdu_header_start_t *const header);

/**
 *  @brief         Get if SDU in PPDU is signal.
 *
 *  @param[in,out] header               the PPDU header.
 *
 *  @return        1 if signal, else 0.
 *
 *  @ingroup RLE header
 */
static inline int rle_start_ppdu_header_get_is_suppressed(
        const rle_ppdu_header_start_t *const header);

/**
 *  @brief         Get if ALPDU in PPDU use CRC.
 *
 *  @param[in,out] header               the PPDU header.
 *
 *  @return        1 if CRC, else 0.
 *
 *  @ingroup RLE header
 */
static inline int rle_start_ppdu_header_get_use_crc(const rle_ppdu_header_start_t *const header);

/**
 *  @brief         Get the fragment ID linked to a start PPDU.
 *
 *  @param[in,out] header               the PPDU header.
 *
 *  @return        the fragment id.
 *
 *  @ingroup RLE header
 */
static inline uint8_t rle_start_ppdu_header_get_fragment_id(
        const rle_ppdu_header_start_t *const header);

/**
 *  @brief         Get the fragment ID linked to a cont/end PPDU.
 *
 *  @param[in,out] header               the PPDU header.
 *
 *  @return        the fragment id.
 *
 *  @ingroup RLE header
 */
static inline uint8_t rle_cont_end_ppdu_header_get_fragment_id(
        const rle_ppdu_header_cont_end_t *const header);

/**
 *  @brief         Get the type of the PPDU fragment.
 *
 *  @param[in,out] header               the PPDU header.
 *
 *  @return        the type of the PPDU fragment.
 *
 *  @ingroup RLE header
 */
static inline int rle_ppdu_get_fragment_type(const rle_ppdu_header_t *const header);


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static inline void rle_ppdu_header_set_ppdu_length(rle_ppdu_header_t *const ppdu_header,
                                                   const uint16_t ppdu_length)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	ppdu_header->common.rle_packet_length_1 = ((ppdu_length & 0x7ff) >> 5) & 0x3f;
	ppdu_header->common.rle_packet_length_2 = ppdu_length & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	ppdu_header->common.rle_packet_length = ppdu_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return;
}

static inline uint16_t rle_ppdu_header_get_ppdu_length(const rle_ppdu_header_t *const ppdu_header)
{
	uint16_t ppdu_length = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	ppdu_length = ((ppdu_header->common.rle_packet_length_1 & 0x3f) << 5) & 0x7ff;
	ppdu_length |= ppdu_header->common.rle_packet_length_2 & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	ppdu_length = ppdu_header->common.rle_packet_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif

	return ppdu_length;
}

static inline void rle_ppdu_header_start_set_total_length(
        rle_ppdu_header_start_t *const ppdu_header, const uint16_t total_length)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	ppdu_header->total_length_1 = ((total_length & 0xfff) >> 5) & 0x7f;
	ppdu_header->total_length_2 = total_length & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	ppdu_header->total_length = total_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	return;
}

static inline uint16_t rle_ppdu_header_start_get_total_length(
        const rle_ppdu_header_start_t *const ppdu_header)
{
	uint16_t total_length = 0;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	total_length = ((ppdu_header->total_length_1 & 0x7f) << 5) & 0xfff;
	total_length |= ppdu_header->total_length_2 & 0x1f;
#elif __BYTE_ORDER == __BIG_ENDIAN
	total_length = ppdu_header->total_length;
#else
#error "Please fix <asm/byteorder.h>"
#endif

	return total_length;
}

static inline int rle_comp_ppdu_header_get_is_signal(const rle_ppdu_header_comp_t *const header)
{
	return header->label_type == RLE_LT_PROTO_SIGNAL;
}

static inline int rle_comp_ppdu_header_get_is_suppressed(const rle_ppdu_header_comp_t *const header)
{
	return ((header->proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
	        (header->label_type == RLE_LT_IMPLICIT_PROTO_TYPE));
}

static inline int rle_start_ppdu_header_get_is_signal(const rle_ppdu_header_start_t *const header)
{
	return header->label_type == RLE_LT_PROTO_SIGNAL;
}

static inline int rle_start_ppdu_header_get_is_suppressed(
        const rle_ppdu_header_start_t *const header)
{
	return ((header->proto_type_supp == RLE_T_PROTO_TYPE_SUPP) ||
	        (header->label_type == RLE_LT_IMPLICIT_PROTO_TYPE));
}

static inline int rle_start_ppdu_header_get_use_crc(const rle_ppdu_header_start_t *const header)
{
	return header->use_crc;
}

static inline uint8_t rle_start_ppdu_header_get_fragment_id(
        const rle_ppdu_header_start_t *const header)
{
	return header->frag_id;
}

static inline uint8_t rle_cont_end_ppdu_header_get_fragment_id(
        const rle_ppdu_header_cont_end_t *const header)
{
	return header->frag_id;
}

static inline int rle_ppdu_get_fragment_type(const rle_ppdu_header_t *const header)
{
	int type_rle_frag;

	if (header->common.start_ind) {
		if (header->common.end_ind) {
			type_rle_frag = RLE_PDU_COMPLETE;
		} else {
			type_rle_frag = RLE_PDU_START_FRAG;
		}
	} else {
		if (header->common.end_ind) {
			type_rle_frag = RLE_PDU_END_FRAG;
		} else {
			type_rle_frag = RLE_PDU_CONT_FRAG;
		}
	}

	return type_rle_frag;
}


#endif /* __HEADER_H__ */

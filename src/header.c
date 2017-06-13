/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file   header.c
 * @brief  RLE encapsulation functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_transmitter.h"
#include "constants.h"
#include "fragmentation_buffer.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"
#include "header.h"
#include "crc.h"

#include "rle.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>

#else

#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_HEADER


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PRIVATE FUNCTIONS --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief         create and push uncompressed ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the SDU protocol_type.
 *
 *  @ingroup
 */
static void push_uncompressed_alpdu_header(struct rle_frag_buf *const frag_buf,
                                           const uint16_t protocol_type);

/**
 *  @brief         create and push compressed supported ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the compressed SDU protocol_type.
 *
 *  @ingroup
 */
static void push_compressed_supported_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                   const uint8_t protocol_type);

/**
 *  @brief         create and push compressed fallback ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     protocol_type        the SDU protocol_type.
 *
 *  @ingroup
 */
static void push_compressed_fallback_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                  const uint16_t protocol_type);

/**
 *  @brief         create and push COMPLETE PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf                   the fragmentation buffer in use.
 *  @param[in]     alpdu_label_type         the ALPDU label type field.
 *  @param[in]     protocol_type_suppressed the protocol type suppressed field.
 *
 *  @ingroup
 */
static void push_comp_ppdu_header(struct rle_frag_buf *const frag_buf,
                                  const uint8_t alpdu_label_type,
                                  const uint8_t protocol_type_suppressed);

/**
 *  @brief         create and push START PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf                   the fragmentation buffer in use.
 *  @param[in]     frag_id                  the fragmentation context ID.
 *  @param[in]     alpdu_label_type         the ALPDU label type field.
 *  @param[in]     protocol_type_suppressed the protocol type suppressed field.
 *  @param[in]     use_alpdu_crc            the use ALPDU CRC field.
 *
 *  @ingroup
 */
static void push_start_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id,
                                   const uint8_t alpdu_label_type,
                                   const uint8_t protocol_type_suppressed,
                                   const bool use_alpdu_crc);

/**
 *  @brief         create and push CONT PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @ingroup
 */
static void push_cont_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id);

/**
 *  @brief         create and push END PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @ingroup
 */
static void push_end_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id);

/**
 * @brief Get uncompressed protocol type from the first 4 bits of the SDU
 *
 * @param sdu      The SDU bytes
 * @param sdu_len  The length of the SDU
 * @param[out] pt  The uncompressed protocol type in case of success
 * @return         true in case of success, false if SDU was too short
 */
static bool get_uncomp_protocol_type_from_sdu(const uint8_t *const sdu,
                                              const size_t sdu_len,
                                              uint16_t *const pt)
	__attribute__((warn_unused_result, nonnull(1, 3)));


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PRIVATE FUNCTIONS CODE ------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static void push_uncompressed_alpdu_header(struct rle_frag_buf *const frag_buf,
                                           const uint16_t protocol_type)
{
	rle_alpdu_header_uncompressed_t **p_alpdu_header;

	PRINT_RLE_DEBUG("prepend a 2-byte ALPDU header with an uncompressed protocol type");

	p_alpdu_header = (rle_alpdu_header_uncompressed_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**p_alpdu_header));
	(*p_alpdu_header)->proto_type = protocol_type;
}

static void push_compressed_supported_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                   const uint8_t protocol_type)
{
	rle_alpdu_header_compressed_supported_t **p_alpdu_header;

	PRINT_RLE_DEBUG("prepend a 1-byte ALPDU header with a compressed protocol type");

	p_alpdu_header = (rle_alpdu_header_compressed_supported_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**p_alpdu_header));
	(*p_alpdu_header)->proto_type = protocol_type;
}

static void push_compressed_fallback_alpdu_header(struct rle_frag_buf *const frag_buf,
                                                  const uint16_t protocol_type)
{
	rle_alpdu_header_compressed_fallback_t **p_alpdu_header;

	PRINT_RLE_DEBUG("prepend a 3-byte ALPDU header with an unknown compressed protocol "
	                "type");

	p_alpdu_header = (rle_alpdu_header_compressed_fallback_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**p_alpdu_header));
	(*p_alpdu_header)->compressed.proto_type = RLE_PROTO_TYPE_FALLBACK;
	(*p_alpdu_header)->uncompressed.proto_type = protocol_type;
}

static void push_comp_ppdu_header(struct rle_frag_buf *const frag_buf,
                                  const uint8_t alpdu_label_type,
                                  const uint8_t protocol_type_suppressed)
{
	uint16_t ppdu_length_field;
	rle_ppdu_header_comp_t **p_ppdu_header;

	PRINT_RLE_DEBUG("prepend a 2-byte PPDU COMP header");

	p_ppdu_header = (rle_ppdu_header_comp_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;

	(*p_ppdu_header)->start_ind = 1;
	(*p_ppdu_header)->end_ind = 1;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->label_type = alpdu_label_type;
	(*p_ppdu_header)->proto_type_supp = protocol_type_suppressed;
}

static void push_start_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id,
                                   const uint8_t alpdu_label_type,
                                   const uint8_t protocol_type_suppressed,
                                   const bool use_alpdu_crc)
{
	uint16_t ppdu_length_field;
	uint16_t total_length_field;
	rle_ppdu_header_start_t **p_ppdu_header;

	PRINT_RLE_DEBUG("prepend a 4-byte PPDU START header");

	p_ppdu_header = (rle_ppdu_header_start_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;
	total_length_field = frag_buf_get_alpdu_header_len(frag_buf) + frag_buf_get_sdu_len(frag_buf) +
	                     frag_buf_get_alpdu_trailer_len(frag_buf);

	(*p_ppdu_header)->start_ind = 1;
	(*p_ppdu_header)->end_ind = 0;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->frag_id = frag_id;
	(*p_ppdu_header)->use_crc = (use_alpdu_crc ? 1 : 0);
	rle_ppdu_header_start_set_total_length(*p_ppdu_header, total_length_field);
	(*p_ppdu_header)->label_type = alpdu_label_type;
	(*p_ppdu_header)->proto_type_supp = protocol_type_suppressed;
}

static void push_cont_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id)
{
	uint16_t ppdu_length_field;
	rle_ppdu_header_cont_end_t **p_ppdu_header;

	PRINT_RLE_DEBUG("prepend a 2-byte PPDU CONT header");

	p_ppdu_header = (rle_ppdu_header_cont_end_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;

	(*p_ppdu_header)->start_ind = 0;
	(*p_ppdu_header)->end_ind = 0;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->frag_id = frag_id;
}

static void push_end_ppdu_header(struct rle_frag_buf *const frag_buf, const uint8_t frag_id)
{
	uint16_t ppdu_length_field;
	rle_ppdu_header_cont_end_t **p_ppdu_header;

	PRINT_RLE_DEBUG("prepend a 2-byte PPDU END header");

	p_ppdu_header = (rle_ppdu_header_cont_end_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**p_ppdu_header));

	ppdu_length_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;

	(*p_ppdu_header)->start_ind = 0;
	(*p_ppdu_header)->end_ind = 1;
	rle_ppdu_header_set_ppdu_length((rle_ppdu_header_t *)*p_ppdu_header,
	                                ppdu_length_field);
	(*p_ppdu_header)->frag_id = frag_id;
}

static bool get_uncomp_protocol_type_from_sdu(const uint8_t *const sdu,
                                              const size_t sdu_len,
                                              uint16_t *const pt)
{
	uint8_t ip_version;

	if (sdu_len < 1) {
		/* the protocol type cannot be deduced from the IP payload */
		PRINT_RLE_ERROR("SDU is too short to deduce IP version from the first IP "
		                "byte: %zu bytes available, 1 byte required at least\n",
		                sdu_len);
		goto error;
	}

	ip_version = (sdu[0] >> 4) & 0x0f;

	if (ip_version == 4) {
		*pt = RLE_PROTO_TYPE_IPV4_UNCOMP;
	} else if (ip_version == 6) {
		*pt = RLE_PROTO_TYPE_IPV6_UNCOMP;
	} else {
		PRINT_RLE_ERROR("unsupported IP Version %u\n", ip_version);
		goto error;
	}

	PRINT_RLE_DEBUG("IP version %u detected, uncompressed protocol type is 0x%04x",
	                ip_version, *pt);

	return true;

error:
	return false;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS CODE-------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int is_eth_vlan_ip_frame(const uint8_t *const sdu, const size_t sdu_len)
{
	const size_t eth_vlan_hdr_min_len = sizeof(struct ether_header) + sizeof(struct vlan_hdr);
	uint8_t compressed_ptype = RLE_PROTO_TYPE_FALLBACK;

	if (sdu_len <= eth_vlan_hdr_min_len) {
		/* the protocol type of short Ethernet/VLAN frames cannot be compressed */
		PRINT_RLE_DEBUG("frame is not Ethernet/VLAN/IPv4/6 (too short VLAN frame)");
		goto error;
	}

	/* retrieve the Ethernet protocol type */
	{
		const struct ether_header *const eth_hdr = (struct ether_header *) sdu;
		const uint16_t eth_proto_type = ntohs(eth_hdr->ether_type);

		const struct vlan_hdr *const vlan_hdr = (struct vlan_hdr *) (eth_hdr + 1);
		const uint16_t vlan_proto_type = ntohs(vlan_hdr->tpid);

		const uint8_t *const vlan_payload = (uint8_t *) (vlan_hdr + 1);
		const uint8_t ip_version = (vlan_payload[0] >> 4) & 0x0f;

		if (eth_proto_type != RLE_PROTO_TYPE_VLAN_UNCOMP) {
			/* unexpected protocol type in Ethernet frame: it should be VLAN */
			PRINT_RLE_DEBUG("frame is not Ethernet/VLAN/IPv4/6 (malformed VLAN)");
			goto error;
		}

		/* embedded IPv4 or IPv6 use a special compressed protocol type that indicates
		 * to the RLE receiver that the protocol field of the VLAN header is suppressed */
		if ((vlan_proto_type == RLE_PROTO_TYPE_IPV4_UNCOMP && ip_version == 4) ||
		    (vlan_proto_type == RLE_PROTO_TYPE_IPV6_UNCOMP && ip_version == 6)) {
			PRINT_RLE_DEBUG("frame is Ethernet/VLAN/IPv4/6");
			compressed_ptype = RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD;
		} else {
			PRINT_RLE_DEBUG("frame is Ethernet/VLAN but not Ethernet/VLAN/IPv4/6");
			compressed_ptype = RLE_PROTO_TYPE_VLAN_COMP;
		}
	}

error:
	return compressed_ptype;
}

void push_alpdu_header(struct rle_frag_buf *const frag_buf,
                       const struct rle_config *const rle_conf)
{
	uint16_t protocol_type;

	PRINT_RLE_DEBUG("prepend a ALPDU header");

	protocol_type = frag_buf->sdu_info.protocol_type;

	/* ALPDU: 4 cases, len € {0,1,2,3} */

	/* don't fill ALPDU ptype field if given ptype is equal to the default one and suppression is
	 * active, or if given ptype is for signalling packet */
	if (!ptype_is_omissible(protocol_type, rle_conf, frag_buf)) {
		const uint16_t net_protocol_type = ntohs(protocol_type);

		/* suppression is not possible, is compression enabled? */
		if (!rle_conf->use_compressed_ptype) {
			/* No compression, no suppression, ALPDU len = 2 */
			push_uncompressed_alpdu_header(frag_buf, net_protocol_type);
		} else {
			/* No suppression, compression is enabled */
			uint8_t compressed_ptype;

			/* is protocol type compressible? */
			if (rle_header_ptype_is_compressible(protocol_type) == C_OK) {
				compressed_ptype = rle_header_ptype_compression(protocol_type, frag_buf);
			} else {
				compressed_ptype = RLE_PROTO_TYPE_FALLBACK;
			}

			if (compressed_ptype == RLE_PROTO_TYPE_FALLBACK) {
				/* protocol type is NOT compressible, prepend the 3-byte ALDPU before the SDU */
				push_compressed_fallback_alpdu_header(frag_buf, net_protocol_type);

			} else {
				/* protocol type is compressible, ALPDU len = 1 */

				/* special case if the payload is VLAN with embedded IPv4 or IPv6:
				 *  - the RLE transmitter shall suppress the protocol field of the VLAN header,
				 *  - the RLE receiver shall detect IPv4/IPv6 with the 4 first bits of the
				 *    embedded payload. */
				if (protocol_type == RLE_PROTO_TYPE_VLAN_UNCOMP &&
				    compressed_ptype == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
					PRINT_RLE_DEBUG("omit the protocol field of the VLAN header making SDU 2 bytes "
					                "less (%zu bytes in total)",frag_buf_get_sdu_len(frag_buf) - sizeof(protocol_type));
					memmove(frag_buf->sdu.start + sizeof(protocol_type), frag_buf->sdu.start,
					        sizeof(struct ether_header) + sizeof(struct vlan_hdr) - sizeof(protocol_type));
					frag_buf_sdu_push(frag_buf, -(sizeof(protocol_type)));
				}

				/* prepend the 1-byte ALDPU before the SDU */
				push_compressed_supported_alpdu_header(frag_buf, compressed_ptype);
			}
		}
	} else {
		/* protocol type is omitted, ALDPU len == 0 */
		PRINT_RLE_DEBUG("prepend a 0-byte ALPDU header with protocol type omitted");

		/* special case if the payload is VLAN with embedded IPv4 or IPv6:
		 *  - the RLE transmitter shall suppress the protocol field of the VLAN header,
		 *  - the RLE receiver shall detect IPv4/IPv6 with the 4 first bits of the
		 *    embedded payload. */
		if (protocol_type == RLE_PROTO_TYPE_VLAN_UNCOMP &&
		    rle_conf->implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
			PRINT_RLE_DEBUG("omit the protocol field of the VLAN header making SDU 2 bytes "
			                "less (%zu bytes in total)", 
			                frag_buf_get_sdu_len(frag_buf) - sizeof(protocol_type));
			memmove(frag_buf->sdu.start + sizeof(protocol_type), frag_buf->sdu.start,
			        sizeof(struct ether_header) + sizeof(struct vlan_hdr) - sizeof(protocol_type));
			frag_buf_sdu_push(frag_buf, -(sizeof(protocol_type)));
		}
	}
}

bool push_ppdu_header(struct rle_frag_buf *const frag_buf,
                      const struct rle_config *const rle_conf,
                      const size_t ppdu_length,
                      struct rle_ctx_management *const rle_ctx)
{
	size_t max_alpdu_fragment_len = ppdu_length;
	const size_t remain_alpdu_len = frag_buf_get_remaining_alpdu_length(frag_buf);
	const bool use_alpdu_crc =
		(rle_conf->allow_alpdu_sequence_number ? false : !!rle_conf->allow_alpdu_crc);

	PRINT_RLE_DEBUG("");

	if (frag_buf_is_fragmented(frag_buf)) {
		/* ALPDU is fragmented, use CONT or END PPDU */

		/* RLE context needed if ALPDU is fragmented */
		assert(rle_ctx != NULL);

		if (ppdu_length <= sizeof(rle_ppdu_header_cont_end_t)) {
			/* buffer is too small for the smallest PPDU CONT or END fragment plus 1 byte of payload:
			 * sending 0 byte of payload is useless, and even a problem: a CONT PPDU with 0 byte of
			 * payload may be confused with padding */
			goto error;
		}

		max_alpdu_fragment_len -= sizeof(rle_ppdu_header_cont_end_t);

		/* Determine whether a END PPDU is possible or not: a END PPDU is possible only if all
		 * remaining ALPDU bytes may fit into the available room after the END PPDU header
		 *
		 * If END PPDU is not possible, use a CONT PPDU. The RLE reassembler does not support
		 * when the ALPDU trailer (CRC or seqnum) is fragmented. The seqnum fits into one
		 * single byte, so it cannot be fragmented. The CRC fits into 32 bits. So, if the RLE
		 * transmitter is configured for CRC, we should avoid to fragment the last 4 bytes of
		 * the ALPDU.
		 * Note: the `remain_alpdu_len` contain the ALPDU trailer length */
		if (remain_alpdu_len <= max_alpdu_fragment_len) {
			/* END PPDU is possible: put all remaining bytes into the PPDU payload, then build
			 * the END PPDU header before the payload */
			frag_buf_ppdu_put(frag_buf, remain_alpdu_len);
			push_end_ppdu_header(frag_buf, rle_ctx->frag_id);

		} else {
			/* CONT PPDU is required: determine whether the trailer is fully contained in the
			 * next PPDU fragment or not ; if not, the trailer would be fragmented, so make
			 * the CONT PPDU fragment smaller to avoid the trailer fragmentation */

			const size_t trailer_len = (use_alpdu_crc ? RLE_CRC_SIZE : 0);
			const size_t alpdu_overflow_len = remain_alpdu_len - max_alpdu_fragment_len;

			if (alpdu_overflow_len < trailer_len) {
				/* the number of ALPDU bytes that will be put in the next fragments is smaller
				 * than the ALPDU trailer, so the current CONT PPDU contains some bytes of the
				 * trailer, so make the PPDU fragment shorter */

				size_t trailer_len_in_cur_ppdu = trailer_len - alpdu_overflow_len;
				size_t alpdu_fragment_len = max_alpdu_fragment_len - trailer_len_in_cur_ppdu;

				/* do not build CONT PPDU with 0 byte of ALPDU: sending 0 byte of payload is useless,
				 * and even a problem: a CONT PPDU with 0 byte of payload may be confused with padding */
				if (alpdu_fragment_len == 0) {
					goto error;
				}

				frag_buf_ppdu_put(frag_buf, alpdu_fragment_len);
				push_cont_ppdu_header(frag_buf, rle_ctx->frag_id);

			} else {
				/* the ALPDU trailer will be fully transmitted in one of the next fragments,
				 * there is no risk of trailer fragmentation, so use the full room of the buffer */
				frag_buf_ppdu_put(frag_buf, max_alpdu_fragment_len);
				push_cont_ppdu_header(frag_buf, rle_ctx->frag_id);
			}
		}

	} else {
		const bool protocol_type_suppressed = (frag_buf_get_alpdu_header_len(frag_buf) == 0);
		const uint8_t alpdu_label_type =
			get_alpdu_label_type(frag_buf->sdu_info.protocol_type,
			                     protocol_type_suppressed,
			                     rle_conf->type_0_alpdu_label_size);

		max_alpdu_fragment_len -= sizeof(rle_ppdu_header_comp_t);

		if (remain_alpdu_len > max_alpdu_fragment_len) {
			/* Start PPDU */

			const size_t ppdu_and_alpdu_hdrs_len =
				sizeof(rle_ppdu_header_start_t) + frag_buf_get_alpdu_header_len(frag_buf);

			/* RLE context needed if ALPDU is fragmented */
			if (!rle_ctx) {
				PRINT_RLE_ERROR("RLE context needed.");
				goto error;
			}

			if (ppdu_length < (ppdu_and_alpdu_hdrs_len + 1)) {
				/* buffer is too small for the smallest PPDU START fragment: the buffer shall be large
				 * enough for the PPDU START header, the full ALDPU header and at least one byte of
				 * ALPDU because the fragmentation of the ALPDU header is not supported by the RLE
				 * reassembler yet */
				goto error;
			}

			push_alpdu_trailer(frag_buf, rle_conf, rle_ctx);

			frag_buf_ppdu_put(frag_buf, ppdu_length - sizeof(rle_ppdu_header_start_t));

			push_start_ppdu_header(frag_buf, rle_ctx->frag_id, alpdu_label_type,
			                       protocol_type_suppressed, use_alpdu_crc);

		} else {
			/* Complete PPDU */
			if (ppdu_length < sizeof(rle_ppdu_header_comp_t)) {
				goto error;
			}

			frag_buf_ppdu_put(frag_buf, ppdu_length - sizeof(rle_ppdu_header_comp_t));

			push_comp_ppdu_header(frag_buf, alpdu_label_type, protocol_type_suppressed);
		}
	}

	frag_buf_set_cur_pos(frag_buf);

	return true;

error:
	return false;
}

void comp_ppdu_extract_alpdu_fragment(unsigned char comp_ppdu[],
                                      const size_t ppdu_len,
                                      unsigned char **alpdu_fragment,
                                      size_t *alpdu_fragment_len)
{
	PRINT_RLE_DEBUG("extract ALPDU from a %zu-byte PPDU COMP", ppdu_len);

	*alpdu_fragment = comp_ppdu + sizeof(rle_ppdu_header_comp_t);
	*alpdu_fragment_len = ppdu_len - sizeof(rle_ppdu_header_comp_t);

	PRINT_RLE_DEBUG("%zu-byte ALPDU extracted from PPDU COMP", (*alpdu_fragment_len));
}

void start_ppdu_extract_alpdu_fragment(unsigned char start_ppdu[],
                                       const size_t ppdu_len,
                                       unsigned char *alpdu_fragment[],
                                       size_t *const alpdu_fragment_len,
                                       size_t *const alpdu_total_len,
                                       int *const is_crc_used)
{
	const rle_ppdu_header_start_t *const start_ppdu_header =
	        (rle_ppdu_header_start_t *)start_ppdu;

	PRINT_RLE_DEBUG("extract ALPDU fragment from a %zu-byte PPDU START",
	                ppdu_len);

	*alpdu_fragment = start_ppdu + sizeof(rle_ppdu_header_start_t);
	*alpdu_fragment_len = ppdu_len - sizeof(rle_ppdu_header_start_t);
	*alpdu_total_len = rle_ppdu_header_start_get_total_length(start_ppdu_header);
	*is_crc_used = start_ppdu_header->use_crc;

	assert(ppdu_len == (sizeof(rle_ppdu_header_start_t) + (*alpdu_fragment_len)));

	PRINT_RLE_DEBUG("%zu-byte ALPDU fragment extracted from PPDU START (ALPDU total "
	                "length = %zu bytes)", (*alpdu_fragment_len),
	                (*alpdu_total_len));
}

void cont_end_ppdu_extract_alpdu_fragment(const unsigned char cont_end_ppdu[], const size_t ppdu_len,
                                          const unsigned char *alpdu_fragment[],
                                          size_t *const alpdu_fragment_len)
{
	PRINT_RLE_DEBUG("extract ALPDU fragment from a %zu-byte PPDU CONT/END",
	                ppdu_len);

	*alpdu_fragment = cont_end_ppdu + sizeof(rle_ppdu_header_cont_end_t);
	*alpdu_fragment_len = ppdu_len - sizeof(rle_ppdu_header_cont_end_t);

	PRINT_RLE_DEBUG("%zu-byte ALPDU fragment extracted from PPDU CONT/END",
	                (*alpdu_fragment_len));
}

int signal_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                      const size_t alpdu_fragment_len,
                                      uint16_t *protocol_type,
                                      uint8_t *comp_protocol_type,
                                      const unsigned char *sdu_fragment[],
                                      size_t *const sdu_fragment_len)
{
	*protocol_type = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
	*comp_protocol_type = RLE_PROTO_TYPE_SIGNAL_COMP;
	*sdu_fragment = alpdu_fragment;
	*sdu_fragment_len = alpdu_fragment_len;

	return 0;
}

int suppressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                          const size_t alpdu_fragment_len,
                                          uint16_t *protocol_type,
                                          uint8_t *comp_protocol_type,
                                          const unsigned char *sdu_fragment[],
                                          size_t *const sdu_fragment_len,
                                          const struct rle_config *const rle_conf)
{
	int status = 0;
	const uint8_t default_ptype = rle_conf->implicit_protocol_type;

	PRINT_RLE_DEBUG("extract SDU from a %zu-byte ALPDU with protocol type omitted",
	                alpdu_fragment_len);

	*comp_protocol_type = default_ptype;
	*sdu_fragment = alpdu_fragment;
	*sdu_fragment_len = alpdu_fragment_len;
	PRINT_RLE_DEBUG("%zu-byte SDU with implicit protocol type 0x%02x extracted from "
	                "ALPDU", (*sdu_fragment_len), default_ptype);

	if (default_ptype == RLE_PROTO_TYPE_IP_COMP) {
		PRINT_RLE_DEBUG("implicit protocol type 0x%02x requires to detect IP version "
		                "from SDU", default_ptype);
		if (!get_uncomp_protocol_type_from_sdu(*sdu_fragment, *sdu_fragment_len, protocol_type)) {
			PRINT_RLE_ERROR("failed to get uncompressed protocol type from the "
			                "first 4 bits of SDU\n");
			status = 1;
			goto out;
		}
	} else {
		*protocol_type = rle_header_ptype_decompression(default_ptype);
	}

	PRINT_RLE_DEBUG("implicit protocol type 0x%02x decompressed to 0x%04x",
	                default_ptype, (*protocol_type));

out:
	return status;
}

int uncompressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                            const size_t alpdu_fragment_len,
                                            uint16_t *protocol_type,
                                            uint8_t *comp_protocol_type,
                                            const unsigned char *sdu_fragment[],
                                            size_t *const sdu_fragment_len)
{
	int status = 0;
	const rle_alpdu_header_uncompressed_t *const uncompressed_alpdu_header =
	        (rle_alpdu_header_uncompressed_t *)alpdu_fragment;

	PRINT_RLE_DEBUG("extract SDU from a %zu-byte ALPDU with protocol type uncompressed",
	                alpdu_fragment_len);

	if (alpdu_fragment_len < sizeof(rle_alpdu_header_uncompressed_t)) {
		PRINT_RLE_ERROR("Invalid alpdu fragment len: %zu\n", alpdu_fragment_len);
		status = 1;
		goto out;
	}
	*comp_protocol_type = RLE_PROTO_TYPE_FALLBACK;
	*protocol_type = htons(uncompressed_alpdu_header->proto_type);
	*sdu_fragment = alpdu_fragment + sizeof(rle_alpdu_header_uncompressed_t);
	*sdu_fragment_len = alpdu_fragment_len - sizeof(rle_alpdu_header_uncompressed_t);

	PRINT_RLE_DEBUG("%zu-byte SDU with uncompressed protocol type 0x%04x extracted "
	                "from ALPDU", (*sdu_fragment_len), (*protocol_type));

out:
	return status;
}

int compressed_alpdu_extract_sdu_fragment(const unsigned char alpdu_fragment[],
                                          const size_t alpdu_fragment_len,
                                          uint16_t *protocol_type,
                                          uint8_t *comp_protocol_type,
                                          const unsigned char *sdu_fragment[],
                                          size_t *const sdu_fragment_len,
                                          size_t *const alpdu_hdr_len)
{
	const rle_alpdu_header_t *const alpdu_header = (rle_alpdu_header_t *)alpdu_fragment;
	int status = 0;

	PRINT_RLE_DEBUG("extract SDU from a %zu-byte ALPDU with protocol type compressed",
	                alpdu_fragment_len);

	if (alpdu_fragment_len < 1) {
		PRINT_RLE_ERROR("ALPDU fragment smaller (%zu) than the ALPDU header with compressed "
		                "protocol type\n", alpdu_fragment_len);
		status = 1;
		goto out;
	}
	*comp_protocol_type = alpdu_header->compressed_supported.proto_type;
	PRINT_RLE_DEBUG("SDU got compressed protocol type 0x%02x", 
	                (*comp_protocol_type));

	if ((*comp_protocol_type) == RLE_PROTO_TYPE_FALLBACK) {
		if (alpdu_fragment_len < sizeof(alpdu_header->compressed_fallback)) {
			PRINT_RLE_ERROR("Alpdu fragment smaller (%zu) than a header (%zu)\n",
			                alpdu_fragment_len,
			                sizeof(alpdu_header->compressed_fallback));
			status = 1;
			goto out;
		}
		*protocol_type = htons(alpdu_header->compressed_fallback.uncompressed.proto_type);
		*sdu_fragment = alpdu_fragment + sizeof(alpdu_header->compressed_fallback);
		*sdu_fragment_len = alpdu_fragment_len - sizeof(alpdu_header->compressed_fallback);
		if (alpdu_hdr_len) {
			*alpdu_hdr_len = sizeof(alpdu_header->compressed_fallback);
		}
		PRINT_RLE_DEBUG("%zu-byte SDU with uncompressed protocol type 0x%04x extracted "
		                "from ALPDU", (*sdu_fragment_len), (*protocol_type));

	} else {
		if (alpdu_fragment_len < sizeof(alpdu_header->compressed_supported)) {
			PRINT_RLE_ERROR("Alpdu fragment smaller (%zu) than a header (%zu)\n",
			                alpdu_fragment_len,
			                sizeof(alpdu_header->compressed_supported));
			status = 1;
			goto out;
		}
		*sdu_fragment = alpdu_fragment + sizeof(alpdu_header->compressed_supported);
		*sdu_fragment_len = alpdu_fragment_len - sizeof(alpdu_header->compressed_supported);
		if (alpdu_hdr_len) {
			*alpdu_hdr_len = sizeof(alpdu_header->compressed_supported);
		}

		/* determine the Ethertype of the payload */
		if ((*comp_protocol_type) == RLE_PROTO_TYPE_IP_COMP) {
			/* compressed protocol type 0x30 may indicate IPv4 or IPv6, disambiguation
			 * is performed by checking the first 4 bits of the SDU */
			PRINT_RLE_DEBUG("compressed protocol type 0x%02x requires to detect IP "
			                "version from SDU", *comp_protocol_type);
			if (!get_uncomp_protocol_type_from_sdu(*sdu_fragment, *sdu_fragment_len, protocol_type)) {
				PRINT_RLE_ERROR("failed to get uncompressed protocol type from the "
				                "first 4 bits of SDU\n");
				status = 1;
				goto out;
			}
		} else {
			*protocol_type = rle_header_ptype_decompression(*comp_protocol_type);
		}

		PRINT_RLE_DEBUG("%zu-byte SDU with uncompressed protocol type 0x%04x extracted "
		                "from ALPDU", (*sdu_fragment_len), (*protocol_type));
	}

out:
	return status;
}

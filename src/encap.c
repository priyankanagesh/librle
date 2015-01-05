/**
 * @file   encap.c
 * @author Aurelien Castanie
 * @date   Mon Aug  6 14:15:24 CEST 2012
 *
 * @brief  RLE encapsulation functions
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include "encap.h"
#include "constants.h"
#include "rle_ctx.h"
#include "zc_buffer.h"
#include "rle_conf.h"

#define MODULE_NAME "ENCAP"

static int create_header(struct rle_ctx_management *rle_ctx,
			struct rle_configuration *rle_conf,
			void *data_buffer, size_t data_length,
			uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	size_t size_header = RLE_COMPLETE_HEADER_SIZE;
	size_t ptype_length = 0;
	uint8_t proto_type_supp = RLE_T_PROTO_TYPE_NO_SUPP;

	/* map RLE header to the already allocated buffer */
	struct zc_rle_header_complete *rle_hdr =
		(struct zc_rle_header_complete *)rle_ctx->buf;

	/* don't fill ALPDU ptype field if given ptype
	 * is equal to the default one
	 * or if given ptype is for signalling packet */
	if ((protocol_type != rle_conf_get_default_ptype(rle_conf)) &&
			((protocol_type != RLE_PROTO_TYPE_SIGNAL_COMP) ||
			 (protocol_type != RLE_PROTO_TYPE_SIGNAL_UNCOMP))) {
		/* remap a complete header with ptype field */
		struct rle_header_complete_w_ptype *rle_c_hdr =
			(struct rle_header_complete_w_ptype *)&rle_hdr->header;

		if (rle_conf_get_ptype_compression(rle_conf)) {
			rle_c_hdr->ptype_c_s.proto_type = (uint8_t)protocol_type;
			ptype_length = RLE_PROTO_TYPE_FIELD_SIZE_COMP;
		} else {
			rle_c_hdr->ptype_u_s.proto_type = protocol_type;
			ptype_length = RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP;
		}
	} else {
		/* no protocol type in this packet */
		proto_type_supp = RLE_T_PROTO_TYPE_SUPP;
	}

	/* update total header size */
	size_header += ptype_length;

	/* initialize payload pointers */
	rle_hdr->ptrs.start				= NULL;
	rle_hdr->ptrs.end				= NULL;
	/* fill RLE complete header */
	rle_hdr->header.head.b.start_ind		= 1;
	rle_hdr->header.head.b.end_ind			= 1;
	rle_hdr->header.head.b.rle_packet_length	= data_length;
	SET_PROTO_TYPE_SUPP(rle_hdr->header.head.b.LT_T_FID, proto_type_supp);

	/* fill label_type field accordingly to the
	 * given protocol type (signal or implicit/indicated
	 * by the NCC */
	if ((protocol_type == RLE_PROTO_TYPE_SIGNAL_COMP) ||
			(protocol_type == RLE_PROTO_TYPE_SIGNAL_UNCOMP))
		SET_LABEL_TYPE(rle_hdr->header.head.b.LT_T_FID, RLE_LT_PROTO_SIGNAL); /* RCS2 requirement */
	else
		SET_LABEL_TYPE(rle_hdr->header.head.b.LT_T_FID, RLE_LT_IMPLICIT_PROTO_TYPE);

	/* update rle configuration */
	rle_conf_set_ptype_suppression(rle_conf, proto_type_supp);

	/* set start & end PDU data pointers */
	rle_hdr->ptrs.start = (char *)data_buffer;
	rle_hdr->ptrs.end = (char *)((char *)data_buffer + data_length);
	/* update rle context */
	rle_ctx_set_end_address(rle_ctx,
				(char *)((char *)rle_ctx->buf + size_header));
	rle_ctx_set_is_fragmented(rle_ctx, C_FALSE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_nb_frag_pdu(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, C_FALSE);
	rle_ctx_set_pdu_length(rle_ctx, data_length);
	rle_ctx_set_remaining_pdu_length(rle_ctx, data_length);
	/* RLE packet length is the sum of packet label,
	 * protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx,
				(data_length + ptype_length));
	rle_ctx_set_proto_type(rle_ctx, protocol_type);
	uint8_t label_type = GET_LABEL_TYPE(rle_hdr->header.head.b.LT_T_FID);
	rle_ctx_set_label_type(rle_ctx, label_type);
	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO update

	return C_OK;
}

int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *pdu_buffer, size_t pdu_length,
		uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	if (encap_check_pdu_validity(pdu_buffer,
				pdu_length,
				protocol_type) == C_ERROR) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		return C_ERROR;
	}

	if (create_header(rle_ctx, rle_conf,
			pdu_buffer, pdu_length,
			protocol_type) == C_ERROR) {
		rle_ctx_incr_counter_dropped(rle_ctx);
		return C_ERROR;
	}

	/* set PDU buffer address to the rle_ctx ptr */
	rle_ctx->pdu_buf = pdu_buffer;

	return C_OK;
}

int encap_check_pdu_validity(void *pdu_buffer,
		size_t pdu_length,
		uint16_t protocol_type)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	if ((protocol_type == RLE_PROTO_TYPE_ARP) ||
			(protocol_type == RLE_PROTO_TYPE_SIGNAL_COMP) ||
			(protocol_type == RLE_PROTO_TYPE_SIGNAL_UNCOMP))
		return C_OK;

	uint16_t total_length = 0;

	if ((protocol_type == RLE_PROTO_TYPE_IP_COMP) ||
			(protocol_type == RLE_PROTO_TYPE_IPV4_UNCOMP)) {
		/* PDU is IPv4 packet */
		struct iphdr *ip_hdr = (struct iphdr *)pdu_buffer;

		/* check ip version validity */
		if (ip_hdr->version != IP_VERSION_4) {
			PRINT("ERROR %s %s:%s:%d: expecting IP version 4,"
				       " version [%d] not supported ihl [%d]\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					ip_hdr->version,
					ip_hdr->ihl);
			return C_ERROR;
		}

		/* check PDU size */
		total_length = ntohs(ip_hdr->tot_len);

		if (pdu_length != total_length) {
			PRINT("ERROR %s %s:%s:%d: PDU length inconherency,"
				       " size [%d] given size [%zu]\n",
				       MODULE_NAME,
					__FILE__, __func__, __LINE__,
					total_length, pdu_length);
			return C_ERROR;
		}

		if (total_length > RLE_MAX_PDU_SIZE) {
			PRINT("ERROR %s %s:%s:%d: PDU too large for RL Encapsulation,"
				       " size [%d]\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					total_length);
			return C_ERROR;
		}

		return C_OK;
	}

	if (protocol_type == RLE_PROTO_TYPE_IPV6_UNCOMP) {
		/* PDU is IPv6 packet */
		struct ip6_hdr *ip_hdr = (struct ip6_hdr *)pdu_buffer;

		uint8_t ip_version = (ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_flow >> 28);

		/* check ip version validity */
		if (ip_version != IP_VERSION_6) {
			PRINT("ERROR %s %s:%s:%d: expecting IP version 6,"
					" version [%d] not supported\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					ip_version);
			return C_ERROR;
		}

		/* check PDU size */
		total_length = (ntohs(ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) + 4);

		if (pdu_length != total_length) {
			PRINT("ERROR %s %s:%s:%d: PDU length inconherency,"
					" size [%d] given size [%zu]\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					total_length, pdu_length);
			return C_ERROR;
		}

		return C_OK;
	}

	if ((protocol_type == RLE_PROTO_TYPE_SACH_COMP) ||
			(protocol_type == RLE_PROTO_TYPE_SACH_UNCOMP)) {
		/* PDU is a compressed IP-SACH packet */

		/* TODO */

		return C_OK;
	}

	PRINT("ERROR %s %s:%s:%d: Unknown PDU type [0x%0x]\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			protocol_type);

	return C_ERROR;
}

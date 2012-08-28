/**
 * @file   encap.c
 * @author Aurelien Castanie
 * @date   Mon Aug  6 14:15:24 CEST 2012
 *
 * @brief  RLE encapsulation functions
 *
 *
 */

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include "encap.h"
#include "constants.h"
#include "rle_ctx.h"
#include "zc_buffer.h"
#include "rle_conf.h"

static int create_header(struct rle_ctx_management *rle_ctx,
			struct rle_configuration *rle_conf,
			void *data_buffer, size_t data_length,
			uint16_t protocol_type)
{
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
	rle_hdr->header.head.b.proto_type_supp		= proto_type_supp;

	/* fill label_type field accordingly to the
	 * given protocol type (signal or implicit/indicated
	 * by the NCC */
	if ((protocol_type == RLE_PROTO_TYPE_SIGNAL_COMP) ||
			(protocol_type == RLE_PROTO_TYPE_SIGNAL_UNCOMP))
		rle_hdr->header.head.b.label_type = RLE_LT_PROTO_SIGNAL; /* RCS2 requirement */
	else
		rle_hdr->header.head.b.label_type = RLE_LT_IMPLICIT_PROTO_TYPE;

	/* set start & end PDU data pointers */
	rle_hdr->ptrs.start = (int *)data_buffer;
	rle_hdr->ptrs.end = (int *)(data_buffer + data_length);
	/* update rle context */
	rle_ctx_set_end_address(rle_ctx,
				(int *)(rle_ctx->buf + size_header));
	rle_ctx_set_is_fragmented(rle_ctx, C_FALSE);
	rle_ctx_set_frag_counter(rle_ctx, 1);
	rle_ctx_set_use_crc(rle_ctx, C_FALSE);
	rle_ctx_set_pdu_length(rle_ctx, data_length);
	rle_ctx_set_remaining_pdu_length(rle_ctx, data_length);
	/* RLE packet length is the sum of packet label,
	 * protocol type & payload length */
	rle_ctx_set_rle_length(rle_ctx,
				(data_length + ptype_length));
	rle_ctx_set_proto_type(rle_ctx, protocol_type);
	rle_ctx_set_label_type(rle_ctx, rle_hdr->header.head.b.label_type);
	rle_ctx_set_qos_tag(rle_ctx, 0); // TODO update

	return C_OK;
}

int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx,
		struct rle_configuration *rle_conf,
		void *data_buffer, size_t data_length,
		uint16_t protocol_type)
{
	if (encap_check_pdu_validity(data_buffer, data_length) == C_ERROR)
		return C_ERROR;

	if (create_header(rle_ctx, rle_conf,
			data_buffer, data_length,
			protocol_type) == C_ERROR)
		return C_ERROR;

	/* set PDU buffer address to the rle_ctx ptr */
	rle_ctx->pdu_buf = data_buffer;

	return C_OK;
}

int encap_check_pdu_validity(void *data_buffer, size_t data_length)
{
/*        struct iphdr *ip_hdr = (struct iphdr *)data_buffer;*/
	struct ip *ip = (struct ip *)data_buffer;

/*        int ip_len = ntohs(ip->ip_len); // TODO use data_length ?*/

	/* check PDU size */
	if (data_length > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s:%s:%d: PDU invalid length for RLE, size [%d]\n",
				__FILE__, __func__, __LINE__, ip->ip_len);
		return C_ERROR;
	}

	/* check ip version validity */
	if ((ip->ip_v != IP_VERSION_4) && (ip->ip_v != IP_VERSION_6)) {
		PRINT("ERROR %s:%s:%d: expecting IP version 4 or 6, version [%d] not supported\n",
				__FILE__, __func__, __LINE__, ip->ip_v);
		return C_ERROR;
	}

	return C_OK;
}


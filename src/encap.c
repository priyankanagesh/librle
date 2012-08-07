/**
 * @file   encap.c
 * @author Aurelien Castanie
 * @date   Mon Aug  6 14:15:24 CEST 2012
 *
 * @brief  Definition of RLE encapsulation structure, functions and variables
 *
 *
 */

#include <netinet/ip.h>
#include <arpa/inet.h>
#include "encap.h"
#include "constants.h"
#include "rle_ctx.h"
#include "zc_buffer.h"

static int create_header(struct rle_ctx_management *rle_ctx,
			void *data_buffer)
{
	/* map RLE header to the already allocated buffer */
	zc_rle_header_complete *rle_hdr = (zc_rle_header_complete *)rle_ctx->buf;

	/* retrieve PDU IP header to get some information */
	struct iphdr *ip_hdr = (struct iphdr *)data_buf;

	/* fill RLE complete header */
	rle_hdr->header.head.start_ind = 1;
	rle_hdr->header.head.end_ind = 1;
	rle_hdr->header.head.rle_packet_length = ntohs(ip_hdr->tot_len);
	rle_hdr->header.head.label_type = RLE_LT_IMPLICIT_PROTO_TYPE; // TODO set the good LT from NCC
	rle_hdr->header.head.proto_type_supp = RLE_T_PROTO_TYPE_NO_SUPP;
	rle_hdr->header.proto_type = RLE_PROTO_TYPE_IP; // TODO set the good T from NCC

	/* set start & end PDU data pointers */
	rle_hdr->ptrs->start = (int *)rle_ctx->buf;
	rle_hdr->ptrs->end = (int *)(rle_ctx->buf + ntohs(ip_hdr->tot_len));

	return C_OK;
}

void encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx,
		void *data_buffer, size_t data_length)
{
	if (encap_check_pdu_validity(data_buffer) == C_ERROR)
		return;

	create_header(rle_ctx);
}

int encap_check_pdu_validity(void *data_buffer)
{
	struct iphdr *ip_hdr = (struct iphdr *)data_buf;

	int ip_len = ntohs(ip_hdr->tot_len);

	/* check PDU size */
	if (ip_len > RLE_MAX_PDU_SIZE) {
		printf("ERROR %s:%s:%d: PDU too large for RLE encapsulation, size [%d]\n",
				__FILE__, __func__, __LINE__, ip_hdr->tot_len);
		return C_ERROR;
	}

	/* check ip version validity */
	if ((ip_hdr->version != IP_VERSION_4) && (ip_hdr->version != IP_VERSION_6)) {
		printf("ERROR %s:%s:%d: expecting IP version 4 or 6, version [%d] not supported\n",
				__FILE__, __func__, __LINE__, ip_hdr->version);
		return C_ERROR;
	}

	return C_OK;
}


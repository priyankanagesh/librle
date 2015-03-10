#include <stdio.h>
#include <pcap.h>
#include <string.h>

#ifndef __KERNEL__

#include <netinet/if_ether.h>

#else

#include <linux/if_ether.h>

#endif

#include "test_common.h"
#include "constants.h"
#include "rle_ctx.h"

static int run_test_encap_deencap(char *pcap_file_name, int nb_fragment_id);

/* burst payload size */
static int burst_size = 0;
/* stat counters */
static uint64_t test_pcap_counter = 0L;
static uint64_t test_pcap_total_sent_size = 0L;

static int run_test_encap_deencap(char *pcap_file_name, int nb_fragment_id)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	uint32_t link_len_src;
	struct pcap_pkthdr header;
	unsigned char *packet;
	int i;
	void *buffer[RLE_MAX_FRAG_NUMBER] = { NULL };
	int ret_recv = C_ERROR;
	int test_retval = C_ERROR;
	unsigned char *burst_buffer = NULL;
	uint16_t protocol_type = 0;

	/* clear RLE statistics */
	clear_tx_stats();
	clear_rx_stats();

	PRINT("INFO: TEST ENCAPSULATION - DEENCAPSULATION WITH NO FRAGMENTATION, %d FRAG_ID\n",
	      nb_fragment_id);

	burst_buffer = malloc(FAKE_BURST_MAX_SIZE);
	if (burst_buffer == NULL) {
		PRINT("Error while allocating memory for burst\n");
		return C_ERROR;
	}

	for (i = 0; i < nb_fragment_id; i++) {
		buffer[i] = malloc(RLE_MAX_PDU_SIZE);
		if (buffer[i] == NULL) {
			PRINT("Error while allocating memory\n");
			goto close_fake_burst;
		}
	}

	/* open the source dump file */
	handle = pcap_open_offline(pcap_file_name, errbuf);
	if (handle == NULL) {
		PRINT("failed to open the source pcap file\n");
		goto close_rle;
	}

	/* link layer in the source dump must be supported */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB &&
	    link_layer_type_src != DLT_LINUX_SLL &&
	    link_layer_type_src != DLT_RAW) {
		PRINT("link layer type %d not supported in source dump (supported = "
		      "%d, %d, %d)\n", link_layer_type_src, DLT_EN10MB, DLT_LINUX_SLL,
		      DLT_RAW);
		goto close_input;
	}

	if (link_layer_type_src == DLT_EN10MB) {
		link_len_src = ETHER_HDR_LEN;
	} else if (link_layer_type_src == DLT_LINUX_SLL) {
		link_len_src = LINUX_COOKED_HDR_LEN;
	} else { /* DLT_RAW */
		link_len_src = 0;
	}

	/* open the comparison dump file */
/*        cmp_handle = pcap_open_offline(filename, errbuf);*/
/*        if(cmp_handle == NULL)*/
/*        {*/
/*                DEBUG(verbose, "failed to open the comparison pcap file: %s\n", errbuf);*/
/*                goto close_input;*/
/*                return -1;*/
/*        }*/

	/* link layer in the comparison dump must be supported */
/*        link_layer_type_cmp = pcap_datalink(cmp_handle);*/
/*        if(link_layer_type_cmp != DLT_EN10MB &&*/
/*                        link_layer_type_cmp != DLT_LINUX_SLL &&*/
/*                        link_layer_type_cmp != DLT_RAW)*/
/*        {*/
/*                DEBUG(verbose, "link layer type %d not supported in comparison dump "*/
/*                                "(supported = %d, %d, %d)\n", link_layer_type_cmp, DLT_EN10MB,*/
/*                                DLT_LINUX_SLL, DLT_RAW);*/
/*                goto close_comparison;*/
/*                return -1;*/
/*        }*/

/*        if(link_layer_type_cmp == DLT_EN10MB)*/
/*                link_len_cmp = ETHER_HDR_LEN;*/
/*        else if(link_layer_type_cmp == DLT_LINUX_SLL)*/
/*                link_len_cmp = LINUX_COOKED_HDR_LEN;*/
/*        else |+ DLT_RAW +|*/
/*                link_len_cmp = 0;*/

	/* for each packet in the dump */
	int nb_frag_id = 0;
	while (((packet =
	                 (unsigned char *)pcap_next(handle,
	                                            &header)) !=
	        NULL) && nb_frag_id < nb_fragment_id) {
		unsigned char *in_packet = NULL;
		unsigned char *out_packet = NULL;
		int out_ptype = 0;
		uint32_t out_pkt_length = 0;
		size_t in_size;

		/* check Ethernet frame length */
/*                if(header.len <= link_len_src || header.len != header.caplen) {*/
/*                        DEBUG(verbose, "packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",*/
/*                                        counter, header.len, header.caplen);*/
/*                        goto release_lib;*/
/*                }*/

		in_packet = packet + link_len_src;
		in_size = header.len - link_len_src;
		out_packet = malloc(in_size);

		rle_conf_set_crc_check(transmitter->rle_conf, C_TRUE);
		rle_conf_set_crc_check(receiver->rle_conf[nb_frag_id], C_TRUE);

		/* If the proto type is not set, we set it here from the 12th and 13th octets of the Ethernet
		 *        * header.. */
		if (protocol_type == 0) {
			protocol_type =
			        ntohs(*((uint16_t *)((void *)(packet + ETHER_PTYPE_POS *
			                                      sizeof(char)))));
		}

		/* Encapsulate the input packets, use in_packet and in_size as
		 * input */
		if (rle_transmitter_encap_data(transmitter, in_packet, in_size,
		                               protocol_type) == C_ERROR) {
			PRINT("ERROR while encapsulating data\n");
		}

		/* recopy RLE packet from zc buffer to a normal buffer, we know it's a complete packet */
		/* map and copy header to normal buffer */
/*                struct rle_header_complete *rle_header = (struct rle_header_complete *)transmitter->rle_ctx_man[nb_frag_id].buf;*/
/*                memcpy((void *)buffer[nb_frag_id], (const void *)rle_header, sizeof(struct rle_header_complete));*/
/*                |+ copy RLE packet data +|*/
/*                int header_offset = sizeof(struct rle_header_complete);*/
/*                size_t rle_packet_length = rle_header->head.b.rle_packet_length;*/
/*                void *ptr_to_payload = (void *)(transmitter->rle_ctx_man[nb_frag_id].buf + header_offset);*/
/*                memcpy((void *)(buffer[nb_frag_id] + header_offset), (const void *)(ptr_to_payload), rle_packet_length);*/

/*                |+ for testing purpose, remap header of buffer +|*/
/*                struct rle_header_complete *rle_header_test = (struct rle_header_complete *)buffer[nb_frag_id];*/

/*                uint8_t label_type = GET_LABEL_TYPE(rle_header_test->head.b.LT_T_FID);*/
/*                uint8_t proto_type_supp = GET_LABEL_TYPE(rle_header_test->head.b.LT_T_FID);*/
/*                PRINT("DEBUG -> buffer[%d] header S [%d] E [%d] RLE_PL [%d] LT [%d] T [%d] PTYPE []\n",*/
/*                                nb_frag_id,*/
/*                                rle_header_test->head.b.start_ind, rle_header_test->head.b.end_ind,*/
/*                                rle_header_test->head.b.rle_packet_length,*/
/*                                label_type,*/
/*                                proto_type_supp);*/

		/* test fragmentation */
		int remaining_pdu_size = in_size;
		size_t ptype_size = 0;

		if (!rle_conf_get_ptype_suppression(transmitter->rle_conf)) {
			if (rle_conf_get_ptype_compression(transmitter->rle_conf)) {
				ptype_size = 1;
				/* TODO 0xFF case */
			} else {
				ptype_size = 2;
			}
		}

		burst_size = in_size + RLE_COMPLETE_HEADER_SIZE + ptype_size;

		if (opt_verbose_flag) {
			PRINT("INFO PDU size = %zu burst size = %d\n", in_size, burst_size);
		}

		for (;; ) {
			if (rle_transmitter_get_queue_state(transmitter, nb_frag_id) == C_TRUE) {
				break;
			}

			if (remaining_pdu_size <= 0) {
				break;
			}

			if (rle_transmitter_get_packet(transmitter, burst_buffer, burst_size,
			                               nb_frag_id, protocol_type)
			    != C_OK) {
				PRINT("ERROR while creating RLE fragment\n");
				break;
			}

			if (opt_verbose_flag) {
				PRINT(
				        "DEBUG Remaining size to send = [%d] burst size = [%d] burst addr [%p]\n",
				        remaining_pdu_size, burst_size, burst_buffer);
			}

			ret_recv = rle_receiver_deencap_data(receiver, burst_buffer, burst_size);

			if ((ret_recv != C_OK) && (ret_recv != C_REASSEMBLY_OK)) {
				PRINT("ERROR while receiving RLE\n");
			} else {
				break;
			}

			remaining_pdu_size = rle_transmitter_get_queue_size(transmitter, nb_frag_id);
		}

		if (ret_recv != C_ERROR) {
			/* retrieve reassembled PDU */
			test_retval = rle_receiver_get_packet(receiver, nb_frag_id,
			                                      out_packet, &out_ptype,
			                                      &out_pkt_length);
		}

		if (opt_verbose_flag) {
			PRINT("DEBUG in_size %zu out_pkt_length %u\n", in_size, out_pkt_length);
		}

		if (in_size == out_pkt_length && memcmp(in_packet, out_packet, in_size) == 0) {
			if (opt_verbose_flag) {
				PRINT("Packets are equals\n");
			}

			test_retval = C_OK;
			if (opt_verbose_flag) {
				rle_ctx_dump(&transmitter->rle_ctx_man[nb_frag_id],
				             transmitter->rle_conf);
			}
		} else {
			if (opt_verbose_flag) {
				PRINT("Packets are differents\n");
			}

			compare_packets((char *)in_packet, (char *)out_packet, in_size,
			                out_pkt_length);
			test_retval = C_ERROR;
		}

		nb_frag_id++;

		free(out_packet);
		out_packet = NULL;
	}

close_input:
	pcap_close(handle);
close_rle:
	for (i = 0; i < nb_fragment_id; i++) {
		free((void *)buffer[i]);
		buffer[i] = NULL;
	}
close_fake_burst:
	free(burst_buffer);
	burst_buffer = NULL;

	print_tx_stats();
	print_rx_stats();

	if (test_retval == C_OK) {
		PRINT("SUCCESS\n");
	} else {
		PRINT("FAILURE\n");
	}

	PRINT("------------------------------------------------\n");

	return test_retval;
}

int init_test_encap_deencap(char *pcap_file_name, int nb_fragment_id)
{
	int ret = 0;

	ret = create_rle_modules();

	if (ret != 0) {
		return ret;
	}

	ret = run_test_encap_deencap(pcap_file_name, nb_fragment_id);

	if (ret != C_OK) {
		PRINT("ERROR in test rle\n");
	}

	/* clear pcap stats */
	test_pcap_counter = 0L;
	test_pcap_total_sent_size = 0L;

	destroy_rle_modules();

	return ret;
}

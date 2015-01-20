#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#ifndef __KERNEL__

#include <netinet/if_ether.h>

#else

#include <linux/if_ether.h>

#endif

#include "test_common.h"
#include "constants.h"
#include "rle_ctx.h"
#include "header.h"
#include "trailer.h"

static int run_test_frag_rea(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int trailer_mode);

/* burst payload size */
static uint32_t burst_size = 0;
/* stat counters */
static uint64_t test_pcap_counter = 0L;
static uint64_t test_pcap_total_sent_size = 0L;

static int run_test_frag_rea(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int trailer_mode)
{
	if (pcap_file_name == NULL)
		return C_ERROR;

	clear_stats();

	char trailer_type[64];
	PRINT("INFO: TEST FRAGMENTATION - REASSEMBLY WITH %d FRAG_ID\n",
			nb_fragment_id);

	if (trailer_mode == ENABLE_CRC)
		snprintf(trailer_type, 64, "%s", "CRC32 trailer\n");
	else if (trailer_mode == ENABLE_SEQ)
		snprintf(trailer_type, 64, "%s", "Next Sequence Number trailer\n");

	PRINT("INFO: %s", trailer_type);

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

	unsigned char *burst_buffer = malloc(FAKE_BURST_MAX_SIZE);
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
	if(handle == NULL)
	{
		PRINT("failed to open the source pcap file\n");
		goto close_rle;
	}

	/* link layer in the source dump must be supported */
	link_layer_type_src = pcap_datalink(handle);
	if(link_layer_type_src != DLT_EN10MB &&
			link_layer_type_src != DLT_LINUX_SLL &&
			link_layer_type_src != DLT_RAW)
	{
		PRINT("link layer type %d not supported in source dump (supported = "
				"%d, %d, %d)\n", link_layer_type_src, DLT_EN10MB, DLT_LINUX_SLL,
				DLT_RAW);
		goto close_input;
	}

	if(link_layer_type_src == DLT_EN10MB)
		link_len_src = ETHER_HDR_LEN;
	else if(link_layer_type_src == DLT_LINUX_SLL)
		link_len_src = LINUX_COOKED_HDR_LEN;
	else /* DLT_RAW */
		link_len_src = 0;

	/* for each packet in the dump */
	int nb_frag_id = 0;
	int use_crc = 0;

	size_t size_end_header = RLE_END_HEADER_SIZE;
	size_t size_trailer = 0;

	/* Set trailer type to use: Next Sequence Number or CRC32 */
	if (trailer_mode == ENABLE_CRC) {
		size_trailer = RLE_CRC32_FIELD_SIZE;
		use_crc = C_TRUE;
	} else {
		size_trailer = RLE_SEQ_NO_FIELD_SIZE;
		use_crc = C_FALSE;
	}

/*        while(((packet = (unsigned char *)pcap_next(handle, &header)) != NULL) && nb_frag_id < nb_fragment_id)*/
	while(((packet = (unsigned char *)pcap_next(handle, &header)) != NULL)) {
		unsigned char *in_packet;
		unsigned char *out_packet;
		int out_ptype = 0;
		uint32_t out_pkt_length = 0;
		size_t in_size;

		test_pcap_counter++;

		/* check Ethernet frame length */
		if(header.len <= link_len_src || header.len != header.caplen) {
			PRINT("ERROR Packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
					test_pcap_counter, header.len, header.caplen);
			goto close_input;
		}

		in_packet = packet + link_len_src;
		in_size = header.len - link_len_src;
		out_packet = malloc(in_size);

		test_pcap_total_sent_size += in_size;

		rle_conf_set_crc_check(transmitter->rle_conf, use_crc);
		rle_conf_set_crc_check(receiver->rle_conf[nb_frag_id], use_crc);

		uint16_t protocol_type = param_ptype;
		if (rle_transmitter_encap_data(transmitter, in_packet, in_size, protocol_type) == C_ERROR) {
			PRINT("ERROR while encapsulating data\n");
		}

		/* test fragmentation */
		uint32_t remaining_pdu_size = in_size;

		if (opt_verbose_flag)
			PRINT("INFO: PDU number %zu size to send = %zu\n", test_pcap_counter, in_size);

		for (;;) {
			if ((rle_transmitter_get_queue_state(transmitter, nb_frag_id) == C_TRUE) &&
					(ret_recv == C_REASSEMBLY_OK)) {
				if (opt_verbose_flag)
					PRINT("INFO: Received all fragments of PDU number %zu\n",
							test_pcap_counter);
				rle_transmitter_free_context(transmitter, nb_frag_id);
				break;
			}

			/* arbitrary burst payload size */
			/* add a little bit a randomness for
			 * burst available length */
			int r = rand() % 20;
			if ((uint16_t)(param_bsize + r) >= burst_size)
				burst_size = param_bsize;
			else
				burst_size = param_bsize + r;

			/* burst size computation depends on remaining PDU size
			 * to send, because it's not in libRLE role to pad burst unused space
			 * (and it leads to error in PDU comparison)
			 * so for RLE END packet we try to give an perfectly sized burst */
			if ((remaining_pdu_size <= 0) && (ret_recv == C_REASSEMBLY_OK))
				break;

			if ((remaining_pdu_size - burst_size) <= 0)
				burst_size = remaining_pdu_size;

			if ((burst_size >= remaining_pdu_size) ||
					(remaining_pdu_size <= (size_end_header + size_trailer))) {
				burst_size = remaining_pdu_size +
					size_end_header +
					size_trailer; //HDR + TRL END
			}

			if (in_size < burst_size) {
				burst_size = in_size;
			}

			if (rle_transmitter_get_packet(transmitter, burst_buffer, burst_size, nb_frag_id, protocol_type)
					!= C_OK) {
				PRINT("ERROR while creating RLE fragment\n");
				break;
			}

			if (opt_verbose_flag)
				PRINT("INFO: Remaining PDU size to send = [%5d] burst size = [%4d]\n", remaining_pdu_size, burst_size);

			ret_recv = rle_receiver_deencap_data(receiver, burst_buffer, burst_size);

			if ((ret_recv != C_OK) && (ret_recv != C_REASSEMBLY_OK))
				PRINT("ERROR while receiving RLE\n");

			remaining_pdu_size = rle_transmitter_get_queue_size(transmitter, nb_frag_id);
		}

		if (ret_recv != C_ERROR) {
			/* retrieve reassembled PDU */
			test_retval = rle_receiver_get_packet(receiver, nb_frag_id,
					out_packet, &out_ptype, &out_pkt_length);
		}

		if (opt_verbose_flag)
			PRINT("INFO: Size PDU sent [%zu]  Size PDU refragmented [%u]\n", in_size, out_pkt_length);

		if (in_size == out_pkt_length && memcmp(in_packet, out_packet, in_size) == 0) {
			test_retval = C_OK;
			rle_receiver_free_context(receiver, nb_frag_id);
			if (opt_verbose_flag) {
				PRINT("INFO: Packets are EQUALS\n");
				rle_ctx_dump(&transmitter->rle_ctx_man[nb_frag_id],
						transmitter->rle_conf);
			}
		} else {
			PRINT("INFO: Packets are DIFFERENTS\n");
			compare_packets((char *)in_packet, (char *)out_packet, in_size, out_pkt_length);
			test_retval = C_ERROR;
		}

/*                nb_frag_id++;*/

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

	PRINT("INFO: TEST WITH %d FRAG_ID\n",
			nb_fragment_id);
	PRINT("INFO: Test status from PCAP file:\n"
		       "\tTotal size before encapsulation \t%10lu\n"
		       "\tTotal sent packets \t\t\t%10lu\n"
		       "\tAverage size per packet \t\t%10.2f\n",
		       test_pcap_total_sent_size,
		       test_pcap_counter,
		       (float)(test_pcap_total_sent_size/test_pcap_counter));

	print_stats();

	if (test_retval == C_OK)
		PRINT("SUCCESS\n");
	else
		PRINT("FAILURE\n");

	PRINT("------------------------------------------------\n");

	return test_retval;
}

int init_test_frag_rea(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int use_crc)
{
	int ret = 0;

	ret = create_rle_modules();

	if (ret != 0)
		return ret;

	ret = run_test_frag_rea(pcap_file_name, param_ptype,
			param_bsize,
			nb_fragment_id, use_crc);

	if (ret != C_OK) {
		PRINT("ERROR in test rle\n");
	}

	destroy_rle_modules();

	return ret;
}


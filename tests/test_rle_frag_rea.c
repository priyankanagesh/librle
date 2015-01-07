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
#include "rle_transmitter.h"
#include "rle_receiver.h"
#include "header.h"
#include "trailer.h"

#define LINUX_COOKED_HDR_LEN  16
#define FAKE_BURST_MAX_SIZE 512

static int test_1(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int trailer_mode);

static int test_frag_rea(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int use_crc);

enum options {
	DISABLE_FRAGMENTATION = 0,
	ENABLE_FRAGMENTATION,
	DISABLE_CRC,
	ENABLE_CRC,
	DISABLE_SEQ,
	ENABLE_SEQ /* 5 */
};

/* burst payload size */
static uint32_t burst_size = 0;
static int crc_flag = 0;
static int seq_flag = 0;
static uint64_t test_pcap_counter = 0L;
static uint64_t test_pcap_total_sent_size = 0L;
static uint64_t TX_total_sent_size = 0L;
static uint64_t TX_total_sent_pkt = 0L;
static uint64_t TX_total_lost_pkt = 0L;
static uint64_t TX_total_drop_pkt = 0L;

static int verbose = C_FALSE;

/* RLE modules */
static struct transmitter_module *transmitter = NULL;
static struct receiver_module *receiver = NULL;

static int test_1(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int trailer_mode)
{
	if (pcap_file_name == NULL)
		return C_ERROR;

	char trailer_type[64];
	PRINT("INFO: TEST FRAGMENTATION WITH %d FRAG_ID\n",
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

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
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
	while(((packet = (unsigned char *)pcap_next(handle, &header)) != NULL))
	{
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

		if (verbose)
			PRINT("INFO: PDU number %zu size to send = %zu\n", test_pcap_counter, in_size);

		for (;;) {
			if ((rle_transmitter_get_queue_state(transmitter, nb_frag_id) == C_TRUE) &&
					(ret_recv == C_REASSEMBLY_OK)) {
				if (verbose)
					PRINT("INFO: Received all fragments of PDU number %zu\n",
							test_pcap_counter);
				rle_transmitter_free_context(transmitter, nb_frag_id);
				break;
			}

			/* arbitrary burst payload size */
			/* add a little bit a randomness for
			 * burst available length */
			int r = rand() % 20;
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

			if (verbose)
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

		if (verbose)
			PRINT("INFO: Size PDU sent [%zu]  Size PDU refragmented [%u]\n", in_size, out_pkt_length);

		if (in_size == out_pkt_length && memcmp(in_packet, out_packet, in_size) == 0) {
			test_retval = C_OK;
			rle_receiver_free_context(receiver, nb_frag_id);
			if (verbose) {
				PRINT("INFO: Packets are EQUALS\n");
				rle_ctx_dump(&transmitter->rle_ctx_man[nb_frag_id],
						transmitter->rle_conf);
			}
		} else {
			if (verbose) {
				PRINT("INFO: Packets are DIFFERENTS\n");
				compare_packets((char *)in_packet, (char *)out_packet, in_size, out_pkt_length);
			}
			test_retval = C_ERROR;
		}

/*                nb_frag_id++;*/

		free(out_packet);
		out_packet = NULL;
	}

close_input:
	pcap_close(handle);
close_rle:
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
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

	TX_total_sent_size += rle_transmitter_get_counter_bytes(transmitter);
	TX_total_sent_pkt += rle_transmitter_get_counter_ok(transmitter);
	TX_total_lost_pkt += rle_transmitter_get_counter_lost(transmitter);
	TX_total_drop_pkt += rle_transmitter_get_counter_dropped(transmitter);

	PRINT("INFO: TX status:\n"
			"\tTX total sent size \t\t\t%10lu\n"
			"\tTX total sent packets \t\t\t%10lu\n"
			"\tTX total lost packets \t\t\t%10lu\n"
			"\tTX total dropped packets \t\t%10lu\n"
			"\tTX average size per packet \t\t%10.2f\n",
			TX_total_sent_size,
			TX_total_sent_pkt,
			TX_total_lost_pkt,
			TX_total_drop_pkt,
			(float)(TX_total_sent_size/TX_total_sent_pkt));

	if (test_retval == C_OK)
		PRINT("SUCCESS\n");
	else
		PRINT("FAILURE\n");

	return test_retval;
}


static int test_frag_rea(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int use_crc)
{
	transmitter = rle_transmitter_new();

	if (transmitter == NULL) {
		PRINT("ERROR while creating a new RLE transmitter\n");
		return -1;
	}

	receiver = rle_receiver_new();

	if (receiver == NULL) {
		PRINT("ERROR while creating a new RLE receiver\n");
		return -1;
	}

	int ret = test_1(pcap_file_name, param_ptype,
			param_bsize,
			nb_fragment_id, use_crc);

	if (ret != C_OK) {
		PRINT("ERROR in test rle\n");
	}

	rle_transmitter_destroy(transmitter);
	rle_receiver_destroy(receiver);

	return 0;
}

static void print_usage(char *basename)
{
	PRINT("%s -v -b BURST_SIZE -p PROTOCOL_TYPE -f PCAP_FILENAME"
			" -c -s\n",
			basename);
	PRINT("\t-v (verbose mode with RLE context dumps)\n"
			"\t-b BURST_SIZE in Bytes (valid values between 4 and 512 Bytes)\n"
			"\t-p PROTOCOL_TYPE (uncompressed protocol type in hexa)\n"
			"\t-f PCAP_FILENAME (valid pcap file corresponding to PROTOCOL_TYPE)\n"
			"\t-c (Use CRC32 trailer)\n"
			"\t-s (Use Next Sequence Number trailer) - DEFAULT\n");
}

int main(int argc, char *argv[])
{
	char *param_file_name = NULL;
	uint32_t param_protocol_type = 0;
	uint16_t param_burst_size = 0;
	int ret = C_ERROR;
	int opt = 0;
	crc_flag = DISABLE_CRC;
	seq_flag = DISABLE_SEQ;
	int trailer_opt = 0;

	if (argc < 4) {
		PRINT("ERROR missing parameters\n");
		print_usage(argv[0]);
		goto exit_ret;
	} else {
		while ((opt = getopt (argc, argv, "b:p:f:csv")) != -1) {
			switch (opt) {
			case 'b':
				param_burst_size = atoi(optarg);
				if ((param_burst_size > FAKE_BURST_MAX_SIZE) ||
						(param_burst_size < RLE_START_MANDATORY_HEADER_SIZE)) {
					PRINT("ERROR fake burst size parameter is invalid\n");
					goto exit_ret;
				}
				break;
			case 'p':
				param_protocol_type = (uint32_t)strtol(optarg, NULL, 16);
				if (param_protocol_type > 0xffff) {
					PRINT("ERROR protocol type parameter is invalid\n");
					goto exit_ret;
				}
				break;
			case 'f':
				param_file_name = optarg;
				break;
			case 'c':
				crc_flag = ENABLE_CRC;
				trailer_opt++;
				break;
			case 's':
				seq_flag = ENABLE_SEQ;
				trailer_opt++;
				break;
			case 'v':
				verbose = C_TRUE;
				break;
			default:
				print_usage(argv[0]);
				ret = C_ERROR;
				goto exit_ret;
			}
		}

		/* trailer mode fallback */
		if (crc_flag == DISABLE_CRC && seq_flag == DISABLE_SEQ) {
			seq_flag = ENABLE_SEQ;
			trailer_opt++;
		}

		PRINT("TEST with protocol type 0x%0x\n"
				" burst size %d\n"
				" pcap file %s\n",
				param_protocol_type,
				param_burst_size,
				param_file_name);

		int trailer_mode = 0;
		/* tests not done */
		int crc_test = C_FALSE;
		int seq_test = C_FALSE;

		while ((trailer_opt > 0) && ((crc_test != C_TRUE) || (seq_test != C_TRUE))) {
			if (crc_flag == ENABLE_CRC && !crc_test) {
				crc_test = C_TRUE;
				trailer_mode = crc_flag;
			} else if (seq_flag == ENABLE_SEQ && !seq_test) {
				seq_test = C_TRUE;
				trailer_mode = seq_flag;
			}

			/* Test on multiple queue */
			ret = test_frag_rea(param_file_name,
					param_protocol_type,
					param_burst_size,
					RLE_MAX_FRAG_NUMBER,
					trailer_mode);

			trailer_opt--;
		}
	}

exit_ret:
	return ret;
}

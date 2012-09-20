#include <stdio.h>
#include <pcap.h>
#include <string.h>

#ifndef __KERNEL__

#include <netinet/if_ether.h>

#else

#include <linux/if_ether.h>

#endif

#include "constants.h"
#include "rle_ctx.h"
#include "rle_transmitter.h"
#include "rle_receiver.h"
#include "header.h"
#include "trailer.h"

#define LINUX_COOKED_HDR_LEN  16
#define FAKE_BURST_MAX_SIZE 4096
#define DISABLE_FRAGMENTATION 0
#define ENABLE_FRAGMENTATION 1
#define DISABLE_CRC 0
#define ENABLE_CRC 1

/* burst payload size */
static int burst_size = 0;

/* RLE modules */
static struct transmitter_module *transmitter = NULL;
static struct receiver_module *receiver = NULL;

void compare_packets(char *pkt1, char *pkt2, int size1, int size2)
{
	int j = 0;
	int i = 0;
	int k = 0;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

	for(i = 0; i < size1; i++)
	{
		if(pkt1[i] != pkt2[i])
		{
			sep1 = '#';
			sep2 = '#';
		}
		else
		{
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

		/* make the output human readable */
		if(j >= 3 || (i + 1) >= size1)
		{
			for(k = 0; k < 4; k++)
			{
				if(k < (j + 1))
					PRINT("-> %s  ", str1[k]);
				else /* fill the line with blanks if nothing to print */
					PRINT("        ");
			}

			PRINT("      ");

			for(k = 0; k < (j + 1); k++)
				PRINT("--> %s  ", str2[k]);

			PRINT("\n");

			j = 0;
		}
		else
		{
			j++;
		}
	}
}

int test_1(char *pcap_file_name, int nb_fragment_id, int use_crc)
{
	if (pcap_file_name == NULL)
		return C_ERROR;

	char trailer_type[64];
	PRINT("INFO: TEST FRAGMENTATION WITH %d FRAG_ID\n",
			nb_fragment_id);

	if (use_crc == ENABLE_CRC)
		snprintf(trailer_type, 64, "%s", "CRC32 trailer\n");
	else
		snprintf(trailer_type, 64, "%s", "Next Sequence Number trailer\n");

	PRINT("INFO: %s", trailer_type);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	uint32_t link_len_src;
	struct pcap_pkthdr header;
	unsigned char *packet;
	int i;
	long unsigned int counter;
	void *buffer[RLE_MAX_FRAG_NUMBER];
	int ret_recv = C_ERROR;
	int test_retval = C_ERROR;


	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		buffer[i] = malloc(RLE_MAX_PDU_SIZE);
		if (buffer[i] == NULL) {
			PRINT("Error while allocating memory\n");
			return -1;
		}
	}

	unsigned char *burst_buffer = malloc(FAKE_BURST_MAX_SIZE);
	if (burst_buffer == NULL) {
		PRINT("Error while allocating memory for burst\n");
		return -1;
	}

	/* open the source dump file */
	handle = pcap_open_offline(pcap_file_name, errbuf);
	if(handle == NULL)
	{
		PRINT("failed to open the source pcap file\n");
		return -1;
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
		return -1;
	}

	if(link_layer_type_src == DLT_EN10MB)
		link_len_src = ETHER_HDR_LEN;
	else if(link_layer_type_src == DLT_LINUX_SLL)
		link_len_src = LINUX_COOKED_HDR_LEN;
	else /* DLT_RAW */
		link_len_src = 0;

	/* for each packet in the dump */
	counter = 0;
	int nb_frag_id = 0;

	size_t size_end_header = RLE_END_HEADER_SIZE;
	size_t size_trailer = 0;

	if (use_crc == ENABLE_CRC)
		size_trailer = RLE_CRC32_FIELD_SIZE;
	else
		size_trailer = RLE_SEQ_NO_FIELD_SIZE;

	while(((packet = (unsigned char *)pcap_next(handle, &header)) != NULL) && nb_frag_id < nb_fragment_id)
	{
		unsigned char *in_packet;
		unsigned char *out_packet;
		int out_ptype = 0;
		uint32_t out_pkt_length = 0;
		size_t in_size;

		counter++;

		/* check Ethernet frame length */
		if(header.len <= link_len_src || header.len != header.caplen) {
			PRINT("ERROR Packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",
					counter, header.len, header.caplen);
			goto close_input;
		}

		in_packet = packet + link_len_src;
		in_size = header.len - link_len_src;
		out_packet = malloc(in_size);

		/* Set trailer type to use: Next Sequence Number or CRC32 */
		rle_conf_set_crc_check(transmitter->rle_conf, use_crc);
		rle_conf_set_crc_check(receiver->rle_conf[nb_frag_id], use_crc);

		uint16_t protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP;
		if (rle_transmitter_encap_data(transmitter, in_packet, in_size, protocol_type) == C_ERROR) {
			PRINT("ERROR while encapsulating data\n");
		}

		/* test fragmentation */
		int remaining_pdu_size = in_size;

		PRINT("INFO: PDU size to send = %zu\n", in_size);

		/* STEP 1: START packet payload size = 0
		 * -> TEST OPTIONAL DATA FIELD */
		burst_size = RLE_START_MANDATORY_HEADER_SIZE;

		ret_recv = rle_transmitter_get_packet(transmitter, burst_buffer, burst_size, nb_frag_id, protocol_type);
		if (ret_recv < C_OK) {
			PRINT("ERROR while creating RLE fragment\n");
			break;
		}

		ret_recv = rle_receiver_deencap_data(receiver, burst_buffer, burst_size);

		if ((ret_recv != C_OK) && (ret_recv != C_REASSEMBLY_OK)) {
			PRINT("ERROR while receiving RLE\n");
			break;
		}

		/* STEP 2: Make a CONTINUATION packet with full
		 * PDU */
		burst_size = remaining_pdu_size + RLE_CONT_HEADER_SIZE;

		ret_recv = rle_transmitter_get_packet(transmitter, burst_buffer, burst_size, nb_frag_id, protocol_type);
		if (ret_recv < C_OK) {
			PRINT("ERROR while creating RLE fragment\n");
			break;
		}

		ret_recv = rle_receiver_deencap_data(receiver, burst_buffer, burst_size);

		if ((ret_recv != C_OK) && (ret_recv != C_REASSEMBLY_OK)) {
			PRINT("ERROR while receiving RLE\n");
			break;
		}

		/* STEP 3: END packet payload size = 0
		 * -> TEST OPTIONAL DATA FIELD */
		burst_size = size_end_header +
				size_trailer; //HDR + TRL END
		ret_recv = rle_transmitter_get_packet(transmitter, burst_buffer, burst_size, nb_frag_id, protocol_type);
		if (ret_recv < C_OK) {
			PRINT("ERROR while creating RLE fragment\n");
			break;
		}

		ret_recv = rle_receiver_deencap_data(receiver, burst_buffer, burst_size);

		if ((ret_recv != C_OK) && (ret_recv != C_REASSEMBLY_OK)) {
			PRINT("ERROR while receiving RLE\n");
			break;
		}

		if (ret_recv >= C_OK) {
			/* retrieve reassembled PDU */
			test_retval = rle_receiver_get_packet(receiver, nb_frag_id,
					out_packet, &out_ptype, &out_pkt_length);

			PRINT("INFO: Size PDU sent [%zu]  Size PDU refragmented [%u]\n", in_size, out_pkt_length);
			if (in_size == out_pkt_length && memcmp(in_packet, out_packet, in_size) == 0) {
				PRINT("INFO: Packets are EQUALS\n");
				test_retval = C_OK;
				rle_ctx_dump(&transmitter->rle_ctx_man[nb_frag_id],
						transmitter->rle_conf);
			} else {
				PRINT("INFO: Packets are DIFFERENTS\n");
				compare_packets((char *)in_packet, (char *)out_packet, in_size, out_pkt_length);
				test_retval = C_ERROR;
			}

			nb_frag_id++;

			free(out_packet);
			out_packet = NULL;
		} else {
			free(out_packet);
			out_packet = NULL;
			break;
		}
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
return_ret:

	PRINT("INFO: TEST WITH %d FRAG_ID\n",
			nb_fragment_id);

	if (test_retval == C_OK)
		PRINT("SUCCESS\n");
	else
		PRINT("FAILURE\n");

	return test_retval;
}


int test_frag_rea(char *pcap_file_name, int nb_fragment_id, int use_crc)
{
	transmitter = rle_transmitter_new();

	if (transmitter == NULL) {
		PRINT("ERROR while creating a new RLE transmitter\n");
		return -1;
	}

	receiver = rle_receiver_new();

	if (receiver == NULL) {
		PRINT("ERROR while creating a new RLE receiver\n");
		rle_transmitter_destroy(transmitter);
		return -1;
	}

	int ret = test_1(pcap_file_name, nb_fragment_id, use_crc);

	if (ret != C_OK) {
		PRINT("ERROR in test rle\n");
	}

	rle_transmitter_destroy(transmitter);
	rle_receiver_destroy(receiver);

	return ret;
}

int main(int argc, char *argv[])
{
	char *file_name = NULL;
	int ret = C_ERROR;

	if (argc < 2) {
		PRINT("ERROR no test file provided\n");
		goto exit_ret;
	} else {
		file_name = argv[1];
		/* Test with Next Sequence Number
		 * trailer */
		ret = test_frag_rea(file_name,
				1,
				DISABLE_CRC);

	}

	if (ret == C_OK) {
		/* Test on multiple queue
		 * with Next Sequence Number
		 * trailer */
		ret = test_frag_rea(file_name,
				RLE_MAX_FRAG_NUMBER,
				DISABLE_CRC);
	}

	if (ret == C_OK) {
		/* Test on multiple queue
		 * with CRC32 trailer */
		ret = test_frag_rea(file_name,
				RLE_MAX_FRAG_NUMBER,
				ENABLE_CRC);
	}

exit_ret:
	return ret;
}

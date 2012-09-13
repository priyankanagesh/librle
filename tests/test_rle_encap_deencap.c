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

#define LINUX_COOKED_HDR_LEN  16
#define FAKE_BURST_MAX_SIZE 4096
#define DISABLE_FRAGMENTATION 0
#define ENABLE_FRAGMENTATION 1

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

int test_1(char *pcap_file_name, int nb_fragment_id)
{
	if (pcap_file_name == NULL)
		return C_ERROR;

	PRINT("\n--------------------------------------------------\n");
	PRINT("--------------------------------------------------\n");
	PRINT("--- TEST ENCAPSULATION NO FRAG WITH %d FRAG_ID ---\n",
			nb_fragment_id);
	PRINT("--------------------------------------------------\n");
	PRINT("--------------------------------------------------\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	pcap_t *cmp_handle;
	int link_layer_type_src;
	int link_layer_type_cmp;
	uint32_t link_len_src;
	uint32_t link_len_cmp;
	struct pcap_pkthdr header;
	struct pcap_pkthdr cmp_header;
	unsigned char *packet;
	unsigned char *cmp_packet;
	int is_failure = 1;
	unsigned long counter;
	int pkt_nbr = 0;
	int rcv_pkt_nbr = 0;
	uint8_t label[6];
	uint8_t rcv_label[6];
	uint8_t label_type;
	uint16_t protocol;
	int i;
	int qos_idx;
	int status;
	uint8_t qos = 0;
	unsigned long pdu_counter;
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
	if(handle == NULL) {
		PRINT("failed to open the source pcap file\n");
		return -1;
	}

	/* link layer in the source dump must be supported */
	link_layer_type_src = pcap_datalink(handle);
	if(link_layer_type_src != DLT_EN10MB &&
			link_layer_type_src != DLT_LINUX_SLL &&
			link_layer_type_src != DLT_RAW) {
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
	counter = 0;
	pdu_counter = 0;
	int nb_frag_id = 0;
	while(((packet = (unsigned char *)pcap_next(handle, &header)) != NULL) && nb_frag_id < nb_fragment_id)
	{
		unsigned char *in_packet;
		unsigned char *out_packet;
		int out_ptype = 0;
		uint32_t out_pkt_length = 0;
		size_t in_size;

		counter++;

		/* check Ethernet frame length */
/*                if(header.len <= link_len_src || header.len != header.caplen) {*/
/*                        DEBUG(verbose, "packet #%lu: bad PCAP packet (len = %d, caplen = %d)\n",*/
/*                                        counter, header.len, header.caplen);*/
/*                        goto release_lib;*/
/*                }*/

		in_packet = packet + link_len_src;
		in_size = header.len - link_len_src;
		out_packet = malloc(in_size);

		/* Encapsulate the input packets, use in_packet and in_size as
		   input */
		for(i=0 ; i<6 ; i++)
			label[i] = i;

		rle_conf_set_crc_check(transmitter->rle_conf, C_TRUE);
		rle_conf_set_crc_check(receiver->rle_conf[nb_frag_id], C_TRUE);

		uint16_t protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP;
		if (rle_transmitter_encap_data(transmitter, in_packet, in_size, protocol_type) == C_ERROR) {
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
		size_t original_pdu_size = in_size;
		int remaining_pdu_size = in_size;
		size_t sent_pdu_size = 0;

		burst_size = in_size + RLE_COMPLETE_HEADER_SIZE;

		PRINT("INFO PDU size = %d burst size = %d\n", in_size, burst_size);

		for (;;) {
			if (rle_transmitter_get_queue_state(transmitter, nb_frag_id) == C_TRUE)
				break;

			if (remaining_pdu_size <= 0)
				break;

/*                        if ((remaining_pdu_size - burst_size) < 0)*/
/*                                burst_size = remaining_pdu_size;*/
/*                        else*/
				remaining_pdu_size = rle_transmitter_get_queue_size(transmitter, nb_frag_id);

/*                        if (burst_size > remaining_pdu_size) {*/
/*                                burst_size = remaining_pdu_size + 2 + 4; //HDR + TRL END*/
/*                        }*/

			if (rle_transmitter_get_packet(transmitter, burst_buffer, burst_size, nb_frag_id, protocol_type)
					!= C_OK) {
				PRINT("ERROR while creating RLE fragment\n");
				break;
			}


			PRINT("DEBUG Remaining size to send = [%d] burst size = [%d] burst addr [%p]\n", remaining_pdu_size, burst_size, burst_buffer);

			ret_recv = rle_receiver_deencap_data(receiver, burst_buffer, burst_size);

			if ((ret_recv != C_OK) && (ret_recv != C_REASSEMBLY_OK))
				PRINT("ERROR while receiving RLE\n");
			else
				break;
		}

		if (ret_recv != C_ERROR) {
			/* retrieve reassembled PDU */
			test_retval = rle_receiver_get_packet(receiver, nb_frag_id,
					out_packet, &out_ptype, &out_pkt_length);
			PRINT("INFO rle_receiver_get_packet returned %d\n",
					test_retval);
		}

		PRINT("DEBUG in_size %zu out_pkt_length %u\n", in_size, out_pkt_length);
		if (in_size == out_pkt_length && memcmp(in_packet, out_packet, in_size) == 0) {
			PRINT("\n-------------- Packets are EQUALS ------------------\n");
			test_retval = C_OK;
			rle_ctx_dump(&transmitter->rle_ctx_man[nb_frag_id],
					transmitter->rle_conf);
		} else {
			PRINT("\n-------------- Packets are differents --------------\n");
			compare_packets((char *)in_packet, (char *)out_packet, in_size, out_pkt_length);
			test_retval = C_ERROR;
		}

		burst_size = 50;

		nb_frag_id++;

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
return_ret:

	if (test_retval == C_OK) {
		PRINT("\n--------------------------------------------------\n");
		PRINT("--------------------------------------------------\n");
		PRINT("--- TEST ENCAPSULATION NO FRAG WITH %d FRAG_ID ---\n",
				nb_fragment_id);
		PRINT("----------------        OK       -----------------\n");
		PRINT("--------------------------------------------------\n");
		PRINT("--------------------------------------------------\n");
	}

	return test_retval;
}


int test_encap_deencap(char *pcap_file_name, int nb_fragment_id)
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

	int ret = test_1(pcap_file_name, nb_fragment_id);

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
		ret = test_encap_deencap(file_name, 1);

		if (ret == C_OK)
			ret = test_encap_deencap(file_name, RLE_MAX_FRAG_NUMBER);
	}

exit_ret:
	return ret;
}

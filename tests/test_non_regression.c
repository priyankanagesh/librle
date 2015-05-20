/**
 * @file   test_non_regression.c
 * @brief  Body file used for the non regression tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

/* system includes */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#if HAVE_ARPA_INET_H == 1
#include <arpa/inet.h>         /* for ntohs() on Linux */
#endif
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <netinet/in.h>

#include <pcap/pcap.h>
#include <pcap.h>

#include <rle.h>

/** The program version */
#define TEST_VERSION  "RLE non-regression test application, version 1.0.1\n"


/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** A simple minimum macro */
#define min(x, y) \
        (((x) < (y)) ? (x) : (y))

/** Burst size for fragmentation in the test. */
#define BURST_SIZE 14

/* prototypes of private functions */
static void usage(void);
static int test_encap_and_decap(const bool ignore_malformed, const char *const src_filename);
static int encap_decap(struct rle_transmitter *const transmitter,
                       struct rle_receiver *const receiver, const size_t *const packets_length,
                       const unsigned char *const *const packets, const size_t number_of_packets,
                       const size_t link_len_src);

static int compare_packets(const unsigned char *const pkt1, const int pkt1_size,
                           const unsigned char *const pkt2,
                           const int pkt2_size);

static char *str_encap_error(const enum rle_encap_status status);
static char *str_frag_error(const enum rle_frag_status status);
static char *str_pack_error(const enum rle_pack_status status);
static char *str_decap_error(const enum rle_decap_status status);

/** Whether the application runs in verbose mode or not */
static int is_verbose = 0;

#define printf_verbose(x ...) do { \
		if (is_verbose) { printf(x); } \
} while (0)

/**
 * @brief Main function for the RLE test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure,
 *              \li 77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	char *src_filename = NULL;
	bool ignore_malformed = false;
	int status = 1;
	int args_used;

	/* set to quiet mode by default */
	is_verbose = 0;

	/* parse program arguments, print the help message in case of failure */
	if (argc <= 1) {
		usage();
		goto error;
	}

	for (argc--, argv++; argc > 0; argc -= args_used, argv += args_used) {
		args_used = 1;

		if (!strcmp(*argv, "-v")) {
			/* print version */
			printf(TEST_VERSION);
			goto error;
		} else if (!strcmp(*argv, "-h")) {
			/* print help */
			usage();
			goto error;
		} else if (!strcmp(*argv, "--verbose")) {
			/* enable verbose mode */
			is_verbose = 1;
		} else if (!strcmp(*argv, "--ignore-malformed")) {
			/* do not exit with error code if malformed packets are found */
			ignore_malformed = true;
		} else if (src_filename == NULL) {
			/* get the name of the file that contains the packets to
			 * encapsulate/decapsulate */
			src_filename = argv[0];
		} else {
			/* do not accept more than one filename without option name */
			usage();
			goto error;
		}
	}

	/* the source filename is mandatory */
	if (src_filename == NULL) {
		fprintf(stderr, "FLOW is a mandatory parameter\n\n");
		usage();
		goto error;
	}

	/* test RLE encap/decap with the packets from the file */
	status = test_encap_and_decap(ignore_malformed, src_filename);

	printf("=== exit test with code %d\n", status);
error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "RLE non-regression tool:  test the RLE library with a flow\n"
	        "                          of IP packets\n"
	        "\n"
	        "usage: test_non_regression [OPTIONS] FLOW\n"
	        "\n"
	        "with:\n"
	        "  FLOW                    The flow of Ethernet frames to test\n"
	        "                          (in PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -v                      Print version information and exit\n"
	        "  -h                      Print this usage and exit\n"
	        "  --ignore-malformed      Ignore malformed packets for test\n"
	        "  --verbose               Run the test in verbose mode\n");
}


/**
 * @brief Encapsulate, fragmente, pack and and decapsulate one IP packet with the
 *        given transmitter and receiver.
 *
 * @param transmitter       The transmitter to use.
 * @param receiver          The receiver to use.
 * @param packets_length    Lenght of the packets to encapsulate/decapsulate.
 * @param packets           The packets to encapsulate/decapsulate (link layer included)
 * @param number_of_packets The number of packets.
 * @param link_len_src      The length of the link layer header before IP data
 * @param ignore_malformed  Whether to handle malformed packets as fatal for test
 * @return                  1 if the process is successful
 *                          2 if the process is not successful, but due to a misuse of the RLE lib.
 *                          0 if the decapsulated packet doesn't match the
 *                          original one
 *                          -1 if an error occurs while transmitting
 *                          -2 if an error occurs while receiving
 *                          -3 if the link layer is not Ethernet
 */
static int encap_decap(struct rle_transmitter *const transmitter,
                       struct rle_receiver *const receiver, const size_t *const packets_length,
                       const unsigned char *const *const packets, const size_t number_of_packets,
                       const size_t link_len_src)
{
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	/*static const size_t number_of_packets = 2;*/
	size_t packet_iterator = 0;
	struct rle_sdu sdus_in[number_of_packets];

	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		sdus_in[packet_iterator].buffer = (unsigned char *)packets[packet_iterator] +
		                                  link_len_src;
		sdus_in[packet_iterator].size = packets_length[packet_iterator] - link_len_src;
	}
	;

	const size_t fpdu_length = 5000; /* Arbitrarly */
	unsigned char fpdu[fpdu_length];

	memset((void *)fpdu, '\0', fpdu_length);


	struct rle_sdu sdus_out[number_of_packets];
	const size_t sdu_out_buf_length = 5000;
	uint8_t sdu_out_buf[number_of_packets][sdu_out_buf_length];

	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		memset((void *)sdu_out_buf[packet_iterator], '\0', sdu_out_buf_length);
		sdus_out[packet_iterator].buffer = sdu_out_buf[packet_iterator] + link_len_src;
	}

	const size_t burst_size = BURST_SIZE;
	const size_t label_size = 3;
	size_t current_label_length = label_size; /* Arbitrarly */
	const unsigned char label[3] = { 0x00, 0x01, 0x02 };
	const unsigned char *labelp = label;
	size_t fpdu_current_pos = 0;
	size_t fpdu_remaining_size = fpdu_length;

	size_t sdus_nr = 0;
	unsigned char label_out[label_size];

	int status = 1;


	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		sdus_in[packet_iterator].protocol_type =
		        ntohs(*(uint16_t *)((void *)(packets[packet_iterator] + (ETHER_HDR_LEN - 2))));

		{
			const uint16_t sdu_in_ptype = sdus_in[packet_iterator].protocol_type;
			const uint8_t sdu_in_ip_version =
			        (sdus_in[packet_iterator].buffer[0] >> 4) & 0x0f;
			switch (sdu_in_ptype) {
			case 0x0800:
				if (sdu_in_ip_version != 0x04) {
					printf_verbose(
					        "Invalid: IP version in IPv4 packet is %d, expected: %d.",
					        sdu_in_ip_version, 0x04);
					goto exit;
				}
				break;
			case 0x86dd:
				if (sdu_in_ip_version != 0x06) {
					printf_verbose(
					        "Invalid: IP version in IPv6 packet is %d, expected: %d.",
					        sdu_in_ip_version, 0x04);
					goto exit;
				}
				break;
			default:
				break;
			}
		}


		{
			printf_verbose("=== %zu-byte SDU\n", sdus_in[packet_iterator].size);
			unsigned char *p_buffer;
			for (p_buffer = sdus_in[packet_iterator].buffer;
			     p_buffer < sdus_in[packet_iterator].buffer +
			     sdus_in[packet_iterator].size;
			     ++p_buffer) {
				printf_verbose(
				        "%02x%s", *p_buffer,
				        (p_buffer - sdus_in[packet_iterator].buffer) % 16 ==
				        15 ? "\n" : " ");
			}
			printf_verbose("\n");
		}
	}

	size_t current_packet_no = 0;
	for (packet_iterator = 0;
	     packet_iterator < number_of_packets;
	     packet_iterator = current_packet_no) {
		const size_t max_frag_id = min(number_of_packets - current_packet_no, 8);
		uint8_t frag_id;
		int all_contexts_emptied = 0;

		current_packet_no += max_frag_id;

		for (frag_id = 0; frag_id < max_frag_id; ++frag_id) {
			printf_verbose("\n=== packet #%zu:\n", packet_iterator + frag_id + 1);
			/* Encapsulate the IP packet into a RLE packet */
			printf_verbose("=== RLE encapsulation: start\n");
			ret_encap = rle_encapsulate(transmitter, sdus_in[packet_iterator + frag_id],
			                            frag_id);

			switch (ret_encap) {
			case RLE_ENCAP_OK:
				printf_verbose("=== RLE encapsulation: success\n");
				break;
			case RLE_ENCAP_ERR_NULL_TRMT:
			case RLE_ENCAP_ERR_SDU_TOO_BIG:
				printf_verbose(
				        "=== RLE encapsulation: misuse\n"
				        "    %s\n", str_encap_error(ret_encap));
				status = 2;
				goto exit;
			case RLE_ENCAP_ERR:
			default:
				printf_verbose("=== RLE encapsulation: failure\n");
				status = -1;
				goto exit;
			}
		}

		while (!all_contexts_emptied) {
			frag_id = 0;
			all_contexts_emptied = 1;
			for (frag_id = 0; frag_id < max_frag_id; ++frag_id) {
				if (rle_transmitter_stats_get_queue_size(transmitter,
				                                         frag_id) != 0) {
					unsigned char ppdu[burst_size];
					size_t ppdu_length = 0;
					all_contexts_emptied = 0;

					printf_verbose("=== RLE fragmentation: start\n");
					ret_frag =
					        rle_fragment(transmitter, frag_id, burst_size, ppdu,
					                     &ppdu_length);

					switch (ret_frag) {
					case RLE_FRAG_OK:
						printf_verbose(
						        "=== RLE fragmentation: success. "
						        "burst_size: %zu, remaining alpdu: %zu.\n",
						        burst_size,
						        rle_transmitter_stats_get_queue_size(
						                transmitter,
						                frag_id));
						printf_verbose("=== %zu-byte PPDU\n", ppdu_length);
						{
							unsigned char *ppdu_it;
							for (ppdu_it = ppdu;
							     ppdu_it < ppdu + ppdu_length;
							     ++ppdu_it) {
								printf_verbose(
								        "%02x%s", *ppdu_it,
								        (ppdu_it - ppdu) % 16 ==
								        15 ? "\n" : " ");
							}
							printf_verbose("\n");
						}
						break;
					case RLE_FRAG_ERR_NULL_TRMT:
					case RLE_FRAG_ERR_INVALID_SIZE:
					case RLE_FRAG_ERR_BURST_TOO_SMALL:
					case RLE_FRAG_ERR_CONTEXT_IS_NULL:
						printf_verbose(
						        "=== RLE fragmentation: misuse\n"
						        "    %s\n", str_frag_error(ret_frag));
						status = 2;
						goto exit;
					case RLE_FRAG_ERR:
					default:
						printf_verbose("=== RLE encapsulation: failure\n");
						status = -1;
						goto exit;
					}

					assert(ppdu_length <= burst_size);

					printf_verbose("=== RLE packing: start\n");
					ret_pack =
					        rle_pack(ppdu, ppdu_length, labelp,
					                 current_label_length,
					                 fpdu,
					                 &fpdu_current_pos,
					                 &fpdu_remaining_size);

					switch (ret_pack) {
					case RLE_PACK_OK:
						printf_verbose("=== RLE packing: success\n");
						printf_verbose(
						        "===> %zu-byte FPDU (max %zu bytes)\n",
						        fpdu_current_pos,
						        fpdu_length);
						break;
					case RLE_PACK_ERR_FPDU_TOO_SMALL:
					case RLE_PACK_ERR_INVALID_LAB:
					case RLE_PACK_ERR_INVALID_PPDU:
						printf_verbose(
						        "=== RLE packing: misuse\n"
						        "    %s\n", str_pack_error(ret_pack));
						status = 2;
						goto exit;
					case RLE_PACK_ERR:
					default:
						printf_verbose("=== RLE packing: failure\n");
						status = -1;
						goto exit;
					}

					labelp = NULL;
					current_label_length = 0;

					{
						printf_verbose("\n");
						printf_verbose("=== %zu-byte FPDU:\n",
						               fpdu_current_pos);
						size_t it = 0;
						for (it = 0; it < fpdu_current_pos; ++it) {
							printf_verbose("%02x%s", fpdu[it],
							               it % 16 == 15 ? "\n" : " ");
						}
						printf_verbose("\n");
					}
				}
			}
		}
	}

	/* decapsulate the FPDU */
	printf_verbose("=== RLE decapsulation: start\n");
	ret_decap =
	        rle_decapsulate(receiver, (const unsigned char *)fpdu, fpdu_length, sdus_out,
	                        number_of_packets, &sdus_nr, label_out, label_size);
	switch (ret_decap) {
	case RLE_DECAP_OK:
		printf_verbose("=== RLE decapsulation: success\n");
		break;
	case RLE_DECAP_ERR_NULL_RCVR:
	case RLE_DECAP_ERR_INV_FPDU:
	case RLE_DECAP_ERR_INV_PL:
	case RLE_DECAP_ERR_INV_SDUS:
		printf_verbose("=== RLE decapsulation: misuse\n"
		               "    %s\n", str_decap_error(ret_decap));
		status = 2;
		goto exit;
	case RLE_DECAP_ERR:
	default:
		printf_verbose("=== RLE decapsulation: failure\n");
		status = -2;
		goto exit;
	}

	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		printf_verbose("%zu-byte decapsuled SDU:\n", sdus_out[packet_iterator].size);
		size_t it = 0;
		for (it = 0; it < sdus_out[packet_iterator].size; ++it) {
			printf_verbose("%02x%s", sdus_out[packet_iterator].buffer[it],
			               it % 16 == 15 ? "\n" : " ");
		}
		printf_verbose("\n");
	}

	/* compare the decapsulated packet with the original one */
	printf_verbose("=== IP comparison: start\n");
	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		if (!compare_packets(packets[packet_iterator] + link_len_src,
		                     packets_length[packet_iterator] - link_len_src,
		                     sdus_out[packet_iterator].buffer,
		                     sdus_out[packet_iterator].size)) {
			printf_verbose("=== IP comparison: failure\n");
			status = 0;
			goto exit;
		} else {
			printf_verbose("=== IP comparison: success\n");
		}
	}

exit:
	printf_verbose("\n");
	return status;
}


/**
 * @brief Test the RLE library with a flow of IP packets going through
 *        encapsulation, fragmentation, packing and decapsulation
 *
 * @param ignore_malformed     Whether to handle malformed packets as fatal for test
 * @param src_filename         The name of the PCAP file that contains the
 *                             IP packets
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_encap_and_decap(const bool ignore_malformed, const char *const src_filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	unsigned char *packet;

	int counter;

	struct rle_transmitter *transmitter;
	struct rle_receiver *receiver;

	int ret;
	size_t nb_bad = 0, nb_ok = 0, err_transmition = 0, err_reception = 0, nb_ref = 0, nb_inv =
	        0;
	int status = 1;

	/* Configuration for uncompressed protocol type */
	struct rle_context_configuration conf_uncomp = {
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	/* Configuration for compressed protocol type */
	struct rle_context_configuration conf_comp = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 1,
		.use_ptype_omission = 0
	};

	/* Configuration for omitted protocol type */
	struct rle_context_configuration conf_omitted = {
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	/* Ditto for IPv4 and v6 */
	struct rle_context_configuration conf_omitted_ip = {
		.implicit_protocol_type = 0x30,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	/* Configuration for non omitted protocol type in omission conf */
	struct rle_context_configuration conf_not_omitted = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	/* Configuration for uncompressed protocol type with CRC */
	struct rle_context_configuration conf_uncomp_crc = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 1,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	/* Configuration for compressed protocol type with CRC */
	struct rle_context_configuration conf_comp_crc = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 1,
		.use_compressed_ptype = 1,
		.use_ptype_omission = 0
	};

	/* Configuration for omitted IPv4 protocol type with CRC */
	struct rle_context_configuration conf_omitted_crc = {
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 1,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	/* Ditto for IPv4 and v6 */
	struct rle_context_configuration conf_omitted_ip_crc = {
		.implicit_protocol_type = 0x30,
		.use_alpdu_crc = 1,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	/* Configuration for non omitted protocol type in omission conf with CRC */
	struct rle_context_configuration conf_not_omitted_crc = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 1,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	/* Configurations */
	struct rle_context_configuration *confs[] = {
		&conf_uncomp,
		&conf_comp,
		&conf_omitted,
		&conf_omitted_ip,
		&conf_not_omitted,
		&conf_uncomp_crc,
		&conf_comp_crc,
		&conf_omitted_crc,
		&conf_omitted_ip_crc,
		&conf_not_omitted_crc,
		NULL
	};

	printf("=== initialization:\n");

	/* open the source dump file */
	handle = pcap_open_offline(src_filename, errbuf);
	if (handle == NULL) {
		printf("failed to open the source pcap file: %s\n", errbuf);
		status = 0;
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB) {
		printf("link layer type %d not supported in source dump (supported = "
		       "%d)\n", link_layer_type_src, DLT_EN10MB);
		status = 0;
		goto close_input;
	} else {
		link_len_src = ETHER_HDR_LEN;
	}

	printf("\n");

	/* for each packet in the dump */
	unsigned char **packets = malloc(sizeof(unsigned char *));
	size_t *packets_length = malloc(sizeof(size_t));
	counter = 0;
	while ((packet = (unsigned char *)pcap_next(handle, &header)) != NULL) {
		/* check Ethernet frame length */
		if (header.len <= link_len_src || header.len != header.caplen) {
			printf("bad PCAP packet (len = %d, caplen = %d)\n", header.len,
			       header.caplen);
			status = 0;
			goto free_alloc;
		}
		counter++;
		void *realloc_ret;
		realloc_ret = realloc((void *)packets, counter * sizeof(unsigned char *));
		if (realloc_ret == NULL) {
			printf("failed to copy the packets.\n");
			goto free_alloc;
		} else {
			packets = realloc_ret;
		}
		realloc_ret = realloc((void *)packets_length, counter * sizeof(size_t));
		if (realloc_ret == NULL) {
			printf("failed to copy the packets length.\n");
			goto free_alloc;
		} else {
			packets_length = realloc_ret;
		}
		packets_length[counter - 1] = header.len;

		packets[counter - 1] = calloc(packets_length[counter - 1], sizeof(unsigned char));
		if (packets[counter - 1] == NULL) {
			printf("failed to copy a packet.\n");
			goto free_alloc;
		}

		memcpy((void *)packets[counter - 1], (const void *)packet,
		       packets_length[counter - 1]);
	}

	/* Configuration iterator */
	struct rle_context_configuration **conf;
	size_t counter_confs = 0;

	/* We launch the test on each configuration. All the cases then are test. */
	for (conf = confs; *conf; ++conf) {
		++counter_confs;

		/* create the transmitter */
		transmitter = rle_transmitter_new(**conf);
		if (transmitter == NULL) {
			printf("failed to create the transmitter.\n");
			goto destroy_modules;
		}

		/* create the receiver */
		receiver = rle_receiver_new(**conf);
		if (receiver == NULL) {
			printf("failed to create the receiver.\n");
			goto destroy_modules;
		}

		/* Encapsulate & decapsulate from transmitter to receiver. */
		printf("=== test: \n");
		printf("===\tnumber of packets:   %d\n", counter);
		printf("===\timplicit ptype:      0x%02x\n", (**conf).implicit_protocol_type);
		printf("===\tALPDU protection:    %s\n", (**conf).use_alpdu_crc ? "CRC" : "SeqNo");
		printf("===\tptype compression:   %s\n",
		       (**conf).use_compressed_ptype ? "On" : "Off");
		printf("===\tptype ommission:     %s\n", (**conf).use_ptype_omission ? "On" : "Off");

		ret =
		        encap_decap(transmitter, receiver, (const size_t *const)packets_length,
		                    (const unsigned char *const *const)packets,
		                    (const size_t)counter,
		                    link_len_src);

		printf("=== statistics: \n");
		printf("===\ttransmitter ok:      %lu\n",
		       (unsigned long)rle_transmitter_stats_get_counter_ok(transmitter));
		printf("===\ttransmitter bytes:   %lu\n",
		       (unsigned long)rle_transmitter_stats_get_counter_bytes(transmitter));
		printf("===\ttransmitter dropped: %lu\n",
		       (unsigned long)rle_transmitter_stats_get_counter_dropped(transmitter));
		printf("===\treceiver ok:         %lu\n",
		       (unsigned long)rle_receiver_stats_get_counter_ok(receiver));
		printf("===\treceiver bytes:      %lu\n",
		       (unsigned long)rle_receiver_stats_get_counter_bytes(receiver));
		printf("===\treceiver lost:       %lu\n",
		       (unsigned long)rle_receiver_stats_get_counter_lost(receiver));
		printf("===\treceiver dropped:    %lu\n",
		       (unsigned long)rle_receiver_stats_get_counter_dropped(receiver));
		printf("\n");

		if (ret == -1) {
			err_transmition++;
			/* break; */
		} else if (ret == -2) {
			err_reception++;
			/* break; */
		} else if (ret == 0) {
			nb_ref++;
		} else if (ret == 1) {
			nb_ok++;
		} else if (ret == 2) {
			nb_inv++;
		} else {
			nb_bad++;
		}

		/* destroy the transmitter and the receiver. */
destroy_modules:
		if (transmitter != NULL) {
			rle_transmitter_destroy(transmitter);
			transmitter = NULL;
		}
		if (receiver != NULL) {
			rle_receiver_destroy(receiver);
			receiver = NULL;
		}
	}

	/* show the encapsulation/decapsulation results. */
	printf("=== summary:\n");
	printf("===\tFPDU processed:       %zu\n", counter_confs);
	printf("===\tmalformed:            %zu\n", nb_bad);
	printf("===\tinvalid:              %zu\n", nb_inv);
	printf("===\ttransmition_failed:   %zu\n", err_transmition);
	printf("===\treception_failed:     %zu\n", err_reception);
	printf("===\tmatches:              %zu\n", nb_ok);
	printf("\n");

	printf("=== shutdown:\n");
	if (err_transmition == 0 && err_reception == 0 &&
	    (ignore_malformed || nb_bad == 0) && nb_ref == 0 &&
	    (nb_ok + nb_bad + nb_inv) == counter_confs) {
		/* test is successful */
		status = 0;
	}

free_alloc:
	if (packets != NULL) {
		size_t packet_iterator;
		for (packet_iterator = 0; packet_iterator < (size_t)counter; ++packet_iterator) {
			if (packets[packet_iterator] != NULL) {
				free(packets[packet_iterator]);
			}
		}
		free(packets);
		packets = NULL;
	}
	if (packets_length != NULL) {
		free(packets_length);
		packets_length = NULL;
	}
close_input:
	pcap_close(handle);
error:
	return status;
}


/**
 * @brief Compare two network packets and print differences if any
 *
 * @param pkt1      The first packet
 * @param pkt1_size The size of the first packet
 * @param pkt2      The second packet
 * @param pkt2_size The size of the second packet
 * @return          Whether the packets are equal or not
 */
static int compare_packets(const unsigned char *const pkt1, const int pkt1_size,
                           const unsigned char *const pkt2,
                           const int pkt2_size)
{
	int valid = 1;
	int min_size;
	int i, j, k;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

	/* do not compare more than the shortest of the 2 packets */
	min_size = min(pkt1_size, pkt2_size);

	/* do not compare more than 180 bytes to avoid huge output */
	min_size = min(180, min_size);

	/* if packets are equal, do not print the packets */
	if (pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0) {
		goto skip;
	}

	/* packets are different */
	valid = 0;

	printf("------------------------------ Compare ------------------------------\n");
	printf("--------- reference ----------         ----------- new --------------\n");

	if (pkt1_size != pkt2_size) {
		printf("packets have different sizes (%d != %d), compare only the %d "
		       "first bytes\n", pkt1_size, pkt2_size, min_size);
	}

	j = 0;
	for (i = 0; i < min_size; i++) {
		if (pkt1[i] != pkt2[i]) {
			sep1 = '#';
			sep2 = '#';
		} else {
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

		/* make the output human readable */
		if (j >= 3 || (i + 1) >= min_size) {
			for (k = 0; k < 4; k++) {
				if (k < (j + 1)) {
					printf("%s  ", str1[k]);
				} else { /* fill the line with blanks if nothing to print */
					printf("        ");
				}
			}

			printf("       ");

			for (k = 0; k < (j + 1); k++) {
				printf("%s  ", str2[k]);
			}

			printf("\n");

			j = 0;
		} else {
			j++;
		}
	}

	printf("----------------------- packets are different -----------------------\n");

skip:
	return valid;
}


/**
 * @brief     show the encapsulation error linked to the encapsulation status.
 *
 * @param[in] status          the encapsulation status.
 *
 * @return    a printable encapsulation error.
 */
static char *str_encap_error(const enum rle_encap_status status)
{
	switch (status) {
	case RLE_ENCAP_OK:
		return "[RLE_ENCAP_OK] no error detected.";
	case RLE_ENCAP_ERR:
		return "[RLE_ENCAP_ERR] Default error. SDU should be dropped.";
	case RLE_ENCAP_ERR_NULL_TRMT:
		return "[RLE_ENCAP_ERR_NULL_TRMT] The transmitter is NULL.";
	case RLE_ENCAP_ERR_SDU_TOO_BIG:
		return "[RLE_ENCAP_ERR_SDU_TOO_BIG] SDU too big to be encapsulated.";
	default:
		return "[Unknwon status]";
	}
}


/**
 * @brief     show the fragmentation error linked to the fragmentation status.
 *
 * @param[in] status          the fragmentation status.
 *
 * @return    a printable fragmentation error.
 */
static char *str_frag_error(const enum rle_frag_status status)
{
	switch (status) {
	case RLE_FRAG_OK:
		return "[RLE_FRAG_OK] no error detected.";
	case RLE_FRAG_ERR:
		return "[RLE_FRAG_ERR] SDU should be dropped.";
	case RLE_FRAG_ERR_NULL_TRMT:
		return "[RLE_FRAG_ERR_NULL_TRMT] The transmitter is NULL.";
	case RLE_FRAG_ERR_BURST_TOO_SMALL:
		return "[RLE_FRAG_ERR_BURST_TOO_SMALL] Burst size is too small.";
	case RLE_FRAG_ERR_CONTEXT_IS_NULL:
		return "[RLE_FRAG_ERR_CONTEXT_IS_NULL] Context is NULL, ALPDU may be empty.";
	case RLE_FRAG_ERR_INVALID_SIZE:
		return "[RLE_FRAG_ERR_INVALID_SIZE] Remaining data size may be invalid in End PPDU.";
	default:
		return "[Unknwon status]";
	}
}


/**
 * @brief     show the packing error linked to the packing status.
 *
 * @param[in] status          the packing status.
 *
 * @return    a printable packing error.
 */
static char *str_pack_error(const enum rle_pack_status status)
{
	switch (status) {
	case RLE_PACK_OK:
		return "[RLE_PACK_OK] no error detected.";
	case RLE_PACK_ERR:
		return "[RLE_PACK_ERR] SDUs should be dropped.";
	case RLE_PACK_ERR_FPDU_TOO_SMALL:
		return "[RLE_PACK_ERR_FPDU_TOO_SMALL] FPDU is too small for the current PPDU. No drop.";
	case RLE_PACK_ERR_INVALID_PPDU:
		return "[RLE_PACK_ERR_INVALID_PPDU] Current PPDU is invalid, maybe NULL or bad size.";
	case RLE_PACK_ERR_INVALID_LAB:
		return "[RLE_PACK_ERR_INVALID_LAB] Current label is invalid, maybe NULL or bad size.";
	default:
		return "[Unknwon status]";
	}
}


/**
 * @brief     show the decapsulation error linked to the decapsulation status.
 *
 * @param[in] status          the decapsulation status.
 *
 * @return    a printable decapsulation error.
 */
static char *str_decap_error(const enum rle_decap_status status)
{
	switch (status) {
	case RLE_DECAP_OK:
		return "[RLE_DECAP_OK] no error detected.";
	case RLE_DECAP_ERR:
		return "[RLE_DECAP_ERR] SDUs should be dropped.";
	case RLE_DECAP_ERR_NULL_RCVR:
		return "[RLE_DECAP_ERR_NULL_RCVR] The receiver is NULL.";
	case RLE_DECAP_ERR_ALL_DROP:
		return "[RLE_DECAP_ERR_ALL_DROP] All current SDUs were dropped. Some may be lost.";
	case RLE_DECAP_ERR_SOME_DROP:
		return "[RLE_DECAP_ERR_SOME_DROP] Some SDUs were dropped. Some may be lost.";
	case RLE_DECAP_ERR_INV_FPDU:
		return "[RLE_DECAP_ERR_INV_FPDU] Invalid FPDU. Maybe Null or bad size.";
	case RLE_DECAP_ERR_INV_SDUS:
		return "[RLE_DECAP_ERR_INV_SDUS] Given preallocated SDUs array is invalid.";
	case RLE_DECAP_ERR_INV_PL:
		return "[RLE_DECAP_ERR_INV_PL] Given preallocated payload label array is invalid.";
	default:
		return "[Unknwon status]";
	}
}

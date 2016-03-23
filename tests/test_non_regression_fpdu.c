/**
 * @file   test_non_regression_fpdu.c
 * @brief  Body file used for the FPDU non regression tests.
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
#include <arpa/inet.h>         /* for ntohs() on Linux */
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <netinet/in.h>

#include <pcap/pcap.h>
#include <pcap.h>

#include <rle.h>

/** The program version */
#define TEST_VERSION  "RLE FPDU non-regression test application, version 0.0.1\n"


/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/* prototypes of private functions */
static void usage(void);
static int test_decap_fpdus(const bool ignore_malformed, const char *const src_filename);
static int decap_fpdus(struct rle_receiver *const receiver, const size_t *const fpdus_lengths,
                       const unsigned char *const *const fpdus, const size_t number_of_fpdus,
                       const size_t link_len_src);


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
	status = test_decap_fpdus(ignore_malformed, src_filename);

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
	        "RLE FPDU non-regression tool:  test the RLE library with a flow\n"
	        "                               of FPDUs\n"
	        "\n"
	        "usage: test_non_regression_fpdu [OPTIONS] FLOW\n"
	        "\n"
	        "with:\n"
	        "  FLOW                    The flow of FPDU to test\n"
	        "                          (in PCAP format, with Ethernet linklayer)\n"
	        "\n"
	        "options:\n"
	        "  -v                      Print version information and exit\n"
	        "  -h                      Print this usage and exit\n"
	        "  --ignore-malformed      Ignore malformed packets for test\n"
	        "  --verbose               Run the test in verbose mode\n");
}


/**
 * @brief Decapsulate FPDUs with the given receiver.
 *
 * @param receiver          The receiver to use.
 * @param fpdus_lengths     Lenght of the packets to encapsulate/decapsulate.
 * @param fpdus             The packets to encapsulate/decapsulate (link layer included)
 * @param number_of_fpdus   The number of packets.
 * @param link_len_src      The length of the link layer header before IP data
 * @return                  1 if the process is successful
 *                          2 if the process is not successful, but due to a misuse of the RLE lib.
 *                          -2 if an error occurs while receiving
 */
static int decap_fpdus(struct rle_receiver *const receiver, const size_t *const fpdus_lengths,
                       const unsigned char *const *const fpdus, const size_t number_of_fpdus,
                       const size_t link_len_src)
{
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	size_t packet_iterator = 0;

	const size_t max_number_of_packets = 100;

	struct rle_sdu sdus_out[max_number_of_packets];
	const size_t sdu_out_buf_length = 4088;
	uint8_t sdu_out_buf[max_number_of_packets][sdu_out_buf_length];

	for (packet_iterator = 0; packet_iterator < max_number_of_packets; ++packet_iterator) {
		memset((void *)sdu_out_buf[packet_iterator], '\0', sdu_out_buf_length);
		sdus_out[packet_iterator].buffer = sdu_out_buf[packet_iterator] + link_len_src;
	}

	const size_t label_size = 3;
	unsigned char label[label_size];

	size_t sdus_nr = 0;

	int status = 1;

	size_t fpdu_iterator;

	size_t total_sdu = 0;

	printf_verbose("\n=== %zu FPDU%s to decapsulate:\n", number_of_fpdus,
	               number_of_fpdus == 1 ? "" : "s");
	for (fpdu_iterator = 0; fpdu_iterator < number_of_fpdus; ++fpdu_iterator) {
		const unsigned char *const fpdu = fpdus[fpdu_iterator];
		const size_t fpdu_length = fpdus_lengths[fpdu_iterator];

		size_t buffer_iterator;
		printf_verbose("=== FPDU n°%zu:\n", fpdu_iterator + 1);
		for (buffer_iterator = 0; buffer_iterator < fpdu_length; ++buffer_iterator) {
			printf_verbose("%02x%s", fpdu[buffer_iterator],
			               buffer_iterator % 16 == 15 ? "\n" : " ");
		}
		printf_verbose("\n\n");
	}

	for (fpdu_iterator = 0; fpdu_iterator < number_of_fpdus; ++fpdu_iterator) {
		/* decapsulate the FPDU */
		const unsigned char *const fpdu = fpdus[fpdu_iterator];
		const size_t fpdu_length = fpdus_lengths[fpdu_iterator];

		printf_verbose("=== RLE decapsulation: start\n");
		ret_decap =
		        rle_decapsulate(receiver, (const unsigned char *)fpdu, fpdu_length,
		                        &sdus_out[total_sdu],
		                        max_number_of_packets, &sdus_nr, label,
		                        label_size);

		total_sdu += sdus_nr;

		switch (ret_decap) {
		case RLE_DECAP_OK:
			printf_verbose("=== RLE decapsulation: success\n");
			break;
		case RLE_DECAP_ERR_NULL_RCVR:
		case RLE_DECAP_ERR_INV_FPDU:
		case RLE_DECAP_ERR_INV_PL:
		case RLE_DECAP_ERR_INV_SDUS:
			printf_verbose(
			        "=== RLE decapsulation: misuse\n"
			        "    %s\n", ret_decap == RLE_DECAP_ERR_NULL_RCVR ?
			        "RLE_DECAP_ERR_NULL_RCVR" : ret_decap ==
			        RLE_DECAP_ERR_INV_FPDU ?
			        "RLE_DECAP_ERR_INV_FPDU" : ret_decap ==
			        RLE_DECAP_ERR_INV_PL ?
			        "RLE_DECAP_ERR_INV_PL" : "RLE_DECAP_ERR_INV_SDUS");
			status = 2;
			goto exit;
		case RLE_DECAP_ERR_SOME_DROP:
		case RLE_DECAP_ERR_ALL_DROP:
			printf_verbose(
			        "=== RLE decapsulation: error with drop\n"
			        "    %s\n", ret_decap == RLE_DECAP_ERR_SOME_DROP ?
			        "RLE_DECAP_ERR_SOME_DROP:" : "RLE_DECAP_ERR_ALL_DROP");
			status = 2;
			goto exit;
		case RLE_DECAP_ERR:
		default:
			printf_verbose("=== RLE decapsulation: misc. failure\n");
			status = 2;
			goto exit;
		}
	}
	printf_verbose("\n");

	for (packet_iterator = 0; packet_iterator < total_sdu; ++packet_iterator) {
		printf_verbose("%zu-byte decapsuled SDU:\n", sdus_out[packet_iterator].size);
		size_t it = 0;
		for (it = 0; it < sdus_out[packet_iterator].size; ++it) {
			printf_verbose("%02x%s", sdus_out[packet_iterator].buffer[it],
			               it % 16 == 15 ? "\n" : " ");
		}
		printf_verbose("\n\n");
	}

exit:
	printf_verbose("\n");
	return status;
}


/**
 * @brief Test the RLE library with a flow of FPDUs going through decapsulation
 *
 * @param ignore_malformed     Whether to handle malformed FPDU as fatal for test
 * @param src_filename         The name of the PCAP file that contains the FPDUs
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_decap_fpdus(const bool ignore_malformed, const char *const src_filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	unsigned char *fpdu;

	int counter;

	struct rle_receiver *receiver;

	int ret;
	size_t nb_bad = 0, nb_ok = 0, err_reception = 0, nb_inv = 0;
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

	/* Configurations */
	struct rle_context_configuration *confs[] = {
		&conf_uncomp,
		&conf_comp,
		&conf_omitted,
		&conf_omitted_ip,
		&conf_not_omitted,
		NULL
	};

	printf("=== initialization:\n");

	/* open the source dump file */
	handle = pcap_open_offline(src_filename, errbuf);
	if (handle == NULL) {
		printf("failed to open the source pcap file: %s\n", errbuf);
		status = ignore_malformed ? 0 : 77;
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB) {
		printf("link layer type %d not supported in source dump (supported = "
		       "%d)\n", link_layer_type_src, DLT_EN10MB);
		status = ignore_malformed ? 0 : 77;
		goto close_input;
	} else {
		link_len_src = ETHER_HDR_LEN;
	}

	printf("\n");

	/* for each fpdu in the dump */
	unsigned char **fpdus = malloc(sizeof(unsigned char *));

	if (fpdus == NULL) {
		printf("failed to allocate FPDUs.\n");
		status = 1;
		goto error;
	}

	size_t *fpdus_lengths = malloc(sizeof(size_t));

	if (fpdus_lengths == NULL) {
		printf("failed to allocate FPDUs lengths.\n");
		status = 1;
		goto free_alloc;
	}

	counter = 0;
	while ((fpdu = (unsigned char *)pcap_next(handle, &header)) != NULL) {
		/* check Ethernet frame length */
		if (header.len <= link_len_src || header.len != header.caplen) {
			printf("bad PCAP fpdu (len = %d, caplen = %d)\n", header.len,
			       header.caplen);
			status = ignore_malformed ? 0 : 77;
			goto free_alloc;
		}
		counter++;
		void *realloc_ret;
		realloc_ret = realloc((void *)fpdus, counter * sizeof(unsigned char *));
		if (realloc_ret == NULL) {
			printf("failed to copy the fpdus.\n");
			goto free_alloc;
		} else {
			fpdus = realloc_ret;
		}
		realloc_ret = realloc((void *)fpdus_lengths, counter * sizeof(size_t));
		if (realloc_ret == NULL) {
			printf("failed to copy the fpdus length.\n");
			goto free_alloc;
		} else {
			fpdus_lengths = realloc_ret;
		}
		fpdus_lengths[counter - 1] = header.len - link_len_src;

		fpdus[counter - 1] = calloc(fpdus_lengths[counter - 1], sizeof(unsigned char));
		if (fpdus[counter - 1] == NULL) {
			printf("failed to copy a fpdu.\n");
			goto free_alloc;
		}

		memcpy((void *)fpdus[counter - 1], (const void *)(fpdu + link_len_src),
		       fpdus_lengths[counter - 1]);
	}

	/* Configuration iterator */
	struct rle_context_configuration **conf;
	size_t counter_confs = 0;

	/* We launch the test on each configuration. All the cases then are test. */
	for (conf = confs; *conf; ++conf) {
		++counter_confs;

		/* create the receiver */
		receiver = rle_receiver_new(**conf);
		if (receiver == NULL) {
			printf("failed to create the receiver.\n");
			continue;
		}

		/* Encapsulate & decapsulate from transmitter to receiver. */
		printf("=== test: \n");
		printf("===\tnumber of fpdus:   %d\n", counter);
		printf("===\timplicit ptype:      0x%02x\n",
		       (**conf).implicit_protocol_type);
		printf("===\tALPDU protection:    %s\n",
		       (**conf).use_alpdu_crc ? "CRC" : "SeqNo");
		printf("===\tptype compression:   %s\n",
		       (**conf).use_compressed_ptype ? "On" : "Off");
		printf("===\tptype ommission:     %s\n",
		       (**conf).use_ptype_omission ? "On" : "Off");

		ret = decap_fpdus(receiver, (const size_t *const)fpdus_lengths,
		                  (const unsigned char *const *const)fpdus, (const size_t)counter,
		                  link_len_src);

		printf("=== statistics: \n");
		{
			u_int8_t frag_id;
			for (frag_id = 0; frag_id < 8; ++frag_id) {
				printf("===\tFrag ID %u\n", frag_id);
				printf("===\treceiver received:          %llu\n",
				       (long long unsigned int)rle_receiver_stats_get_counter_sdus_received(receiver, frag_id));
				printf("===\treceiver reassembled:       %llu\n",
						(long long unsigned int)rle_receiver_stats_get_counter_sdus_reassembled(receiver, frag_id));
				printf("===\treceiver lost:              %llu\n",
						(long long unsigned int)rle_receiver_stats_get_counter_sdus_lost(receiver, frag_id));
				printf("===\treceiver dropped:           %llu\n",
						(long long unsigned int)rle_receiver_stats_get_counter_sdus_dropped(receiver, frag_id));
				printf("===\treceiver bytes received:    %llu\n",
						(long long unsigned int)rle_receiver_stats_get_counter_bytes_received(receiver, frag_id));
				printf("===\treceiver bytes reassembled: %llu\n",
						(long long unsigned int)rle_receiver_stats_get_counter_bytes_reassembled(receiver, frag_id));
				printf("===\treceiver bytes dropped:     %llu\n",
						(long long unsigned int)rle_receiver_stats_get_counter_bytes_dropped(receiver, frag_id));
				printf("\n");
			}
		}

		if (ret == -2) {
			err_reception++;
			/* break; */
		} else if (ret == 1) {
			nb_ok++;
		} else if (ret == 2) {
			nb_inv++;
		} else {
			nb_bad++;
		}

		/* destroy the the receiver. */
		if (receiver != NULL) {
			rle_receiver_destroy(receiver);
			receiver = NULL;
		}
	}

	/* show the encapsulation/decapsulation results. */
	printf("=== summary:\n");
	printf("===\tDecapsulation processed: %zu\n", counter_confs);
	printf("===\tmalformed:               %zu\n", nb_bad);
	printf("===\tinvalid:                 %zu\n", nb_inv);
	printf("===\treception_failed:        %zu\n", err_reception);
	printf("===\tvalid:                   %zu\n", nb_ok);
	printf("\n");

	printf("=== shutdown:\n");
	if (err_reception == 0 && (ignore_malformed || nb_bad == 0) 
			&& (nb_ok + nb_bad + nb_inv) == counter_confs) {
		/* test is successful */
		status = 0;
	}

free_alloc:
	if (fpdus != NULL) {
		size_t fpdu_iterator;
		for (fpdu_iterator = 0;
		     fpdu_iterator < (size_t)counter;
		     ++fpdu_iterator) {
			if (fpdus[fpdu_iterator] != NULL) {
				free(fpdus[fpdu_iterator]);
			}
		}
		free(fpdus);
		fpdus = NULL;
	}
	if (fpdus_lengths != NULL) {
		free(fpdus_lengths);
		fpdus_lengths = NULL;
	}
close_input:
	pcap_close(handle);
error:
	return status;
}

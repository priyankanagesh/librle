/**
 * @file   test_perfs_fpdu.c
 * @brief  Body file used for the FPDU decapsulation performances test.
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

/* system includes */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <getopt.h>
#include <signal.h>

#include "../include/rle.h"

/** The program version */
#define TEST_VERSION  "RLE FPDU performances test application, version 0.0.1\n"

/** The device MTU */
#define DEV_MTU  0xffffU

/** The length (in bytes) of the Ethernet and IP header */
#define ETHER_HDR_LEN  14U
#define IP_HDR_LEN     20U

/** A simple minimum macro */
#define min(x, y) \
        (((x) < (y)) ? (x) : (y))

/** Max FPDU sizes for fragmentation in the test. */
#define MAX_FPDU_SIZE 599

/** Max number of SDUs. Arbitrarly choosen, may be too small or too large. */
#define MAX_SDUS_NB   10

/** Max SDU len. */
#define MAX_SDU_LEN   4088

/** Max Payload label */
#define MAX_PAYLOAD_LABEL_LEN 6

/** Default payload label */
#define DEFAULT_PAYLOAD_LABEL_LEN 3

/** Buffer preallocation */
static unsigned char sdu_buffers[MAX_SDUS_NB][MAX_SDU_LEN];
static struct rle_sdu sdus_out[MAX_SDUS_NB];
static unsigned char payload_label[MAX_PAYLOAD_LABEL_LEN];

static size_t payload_label_len = DEFAULT_PAYLOAD_LABEL_LEN;

/* prototypes of private functions */
static void usage(void);
static void test_interrupt(int signum);
static int test_decap(const char *const device_name);
static int decap(struct rle_receiver *const receiver, const size_t packet_length,
                 const unsigned char *const packet, const size_t link_len_src,
                 size_t *const delta_sdus);
static char *str_decap_error(const enum rle_decap_status status);

/** Whether the application runs in verbose mode or not */
static int is_verbose = 0;

#define printf_verbose(x ...) do { \
		if (is_verbose) { printf(x); } \
} while (0)

/** Whether to handle malformed packets as fatal for test or not */
static int ignore_malformed = 0;

/** Flag to stop the application */
static int stop_program = 0;

/** Counter for packet processed */
static size_t packets_counter = 0;

/**
 * @brief Main function for the RLE test program
 *
 * @param[in] argc The number of program arguments
 * @param[in] argv The program arguments
 * @return         The unix return code:
 *                 \li 0 in case of success,
 *                 \li 1 in case of failure,
 *                 \li 77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	char *device_name = NULL;
	int status = EXIT_FAILURE;

	/* parse program arguments, print the help message in case of failure */
	if (argc <= 1) {
		usage();
		goto error;
	}

	while (1) {
		int c;

		const char short_options[] = "vhp:";

		const struct option long_options[] = {
			{ "verbose", no_argument, &is_verbose, 1 },
			{ "ignore_malformed", no_argument, &ignore_malformed, 1 },
			{ "payload_label", required_argument, 0, 'p' },
			{ NULL, 0, NULL, 0 },
		};

		int option_index = 0;

		c = getopt_long(argc, argv, short_options, long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0) {
				break;
			}
			printf("option %s", long_options[option_index].name);
			if (optarg) {
				printf(" with arg %s", optarg);
			}
			printf("\n");
			break;

		case 'p': /* Payload Label length */
			printf("payload label length value `%s'\n", optarg);
			payload_label_len = atoi(optarg);
			if (payload_label_len > MAX_PAYLOAD_LABEL_LEN) {
				printf("ERROR: %zu Payload label length is too big. Maximum = %d octets.\n",
				       payload_label_len, MAX_PAYLOAD_LABEL_LEN);
				goto error;
			}
			break;

		case 'v': /* Version */
			printf(TEST_VERSION);
			status = EXIT_SUCCESS;
			goto error;

		case 'h': /* Help */
			usage();
			status = EXIT_SUCCESS;
			goto error;

		case '?':
		default:
			usage();
			goto error;
		}
	}

	/* Instead of reporting ‘--verbose’
	 *      and ‘--brief’ as they are encountered,
	 *           we report the final status resulting from them. */
	if (is_verbose) {
		puts("verbose flag is set");
	}

	if (optind != argc - 1) {
		fprintf(stderr, "FLOW is a mandatory parameter\n\n");
		usage();
		goto error;
	}

	device_name = argv[optind];

	signal(SIGINT, test_interrupt);
	signal(SIGTERM, test_interrupt);
	signal(SIGSEGV, test_interrupt);
	signal(SIGABRT, test_interrupt);
	{
		struct sigaction action;
		memset(&action, 0, sizeof(struct sigaction));
		action.sa_handler = SIG_IGN;
		sigaction(SIGHUP, &action, NULL);
	}

	/* test RLE encap with the packets from the file with a given burst size */
	status = test_decap(device_name);

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
	        "\n"
	        "RLE performances test tool:  test the RLE library with a network interface.\n"
	        "\n"
	        "usage: test_non_regression [OPTIONS] interface\n"
	        "\n"
	        "with:\n"
	        "\tinterface               The network interface to sniff.\n"
	        "\n"
	        "options:\n"
	        "\t-v                      Print version information and exit\n"
	        "\t-h                      Print this usage and exit\n"
	        "\t--ignore-malformed      Ignore malformed packets for test\n"
	        "\t--verbose               Run the test in verbose mode\n"
	        "\n");

	return;
}


/**
 * @brief Handle UNIX signals that interrupt the program
 *
 * @param[in] signum  The received signal
 */
static void test_interrupt(int signum)
{
	/* end the program with next captured packet */
	printf_verbose("signal %d catched\n", signum);
	stop_program = 1;

	/* for SIGSEGV/SIGABRT, close the PCAP dumps, print the last debug traces,
	 * then kill the program */
	if (signum == SIGSEGV || signum == SIGABRT) {
		if (signum == SIGSEGV) {
			printf_verbose("a segfault occurred at packet #%zu\n", packets_counter);
		} else {
			printf_verbose("an assertion failed at packet #%zu\n", packets_counter);
		}

		if (signum == SIGSEGV) {
			struct sigaction action;
			memset(&action, 0, sizeof(struct sigaction));
			action.sa_handler = SIG_DFL;
			sigaction(SIGSEGV, &action, NULL);
			raise(signum);
		}
	}

	return;
}


/**
 * @brief decapsulate SDUs with a given receiver.
 *
 * @param[in,out] receiver       The receiver to use.
 * @param[in]     packet_length  Lenght of the packet to encapsulate.
 * @param[in]     packet         The packet to encapsulate (link layer included)
 * @param[in]     link_len_src   The length of the link layer header before IP data
 * @param[out]    delta_sdus     Number of SDUs reassembled
 *
 * @return                   1 if the process is successful
 *                           2 if the process is not successful, but due to a misuse of the RLE lib.
 *                          -1 if an error occurs while transmitting
 *                          -3 if the link layer is not Ethernet
 */
static int decap(struct rle_receiver *const receiver, const size_t packet_length,
                 const unsigned char *const packet, const size_t link_len_src,
                 size_t *const delta_sdus)
{
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;
	unsigned char *const pl = payload_label_len ? payload_label : NULL;

	int status = 1;

	unsigned char *fpdu = (unsigned char *)packet + link_len_src + IP_HDR_LEN;
	const size_t fpdu_len = packet_length - link_len_src - IP_HDR_LEN;

	printf_verbose("=== %zu-byte FPDU\n", fpdu_len);

	ret_decap = rle_decapsulate(receiver, fpdu, fpdu_len, sdus_out, MAX_SDUS_NB, delta_sdus, pl,
	                            payload_label_len);

	switch (ret_decap) {
		case RLE_DECAP_OK:
			printf_verbose("=== RLE decapsulation: success\n");
			break;
		case RLE_DECAP_ERR_NULL_RCVR:
		case RLE_DECAP_ERR_INV_FPDU:
		case RLE_DECAP_ERR_INV_PL:
		case RLE_DECAP_ERR_INV_SDUS:
		default:
			printf_verbose("=== RLE decapsulation: %s\n", str_decap_error(ret_decap));
			status = 2;
			goto exit;
	}

exit:

	printf_verbose("\n");

	return status;
}


/**
 * @brief Test the RLE library with a flow of FPDU in IP packets going through decapsulation
 *
 * @param[in] device_name      The name of the interface listened
 *
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_decap(const char *const device_name)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	struct rle_receiver *receiver;

	int ret;
	size_t nb_bad = 0, nb_ok = 0, err_reception = 0, nb_ref = 0, nb_inv = 0;
	int status = 1;

	size_t it;
	size_t sdus_processed = 0;

	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x30,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 1,
		.use_ptype_omission = 1
	};

	receiver = rle_receiver_new(&conf);

	if (receiver == NULL) {
		printf("ERROR: receiver non initialized\n");
		goto error;
	}

	printf("=== initialization:\n");

	/* open the source dump file */
	handle = pcap_open_live(device_name, DEV_MTU, 0, 0, errbuf);
	if (handle == NULL) {
		printf("failed to open the source pcap file: %s\n", errbuf);
		status = EXIT_FAILURE;
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB) {
		printf("link layer type %d not supported in source dump (supported = %d)\n",
		       link_layer_type_src, DLT_EN10MB);
		status = EXIT_FAILURE;
		goto close_input;
	} else {
		link_len_src = ETHER_HDR_LEN;
	}

	printf("\n");

	printf("=== test: \n");
	printf("===\timplicit ptype:      0x%02x\n", conf.implicit_protocol_type);
	printf("===\tALPDU protection:    %s\n",     conf.use_alpdu_crc ?        "CRC" : "SeqNo");
	printf("===\tptype compression:   %s\n",     conf.use_compressed_ptype ? "On"  : "Off");
	printf("===\tptype ommission:     %s\n",     conf.use_ptype_omission ?   "On"  : "Off");

	stop_program = 0;

	printf("\nTest starting...\n");

	/* Initialize SDUs */
	for (it = 0; it < sizeof(sdus_out) / sizeof*(sdus_out); ++it) {
		sdus_out[it].buffer = sdu_buffers[it];
	}

	while (!stop_program) {
		size_t packet_length = 0;
		size_t delta_sdus_processed = 0;
		unsigned char *packet = (unsigned char *)pcap_next(handle, &header);

		if (packet == NULL) {
			/* no packet captured, re-try */
			continue;
		}

		++packets_counter;
		packet_length = header.len;

		printf_verbose("FPDU #%zu\n", packets_counter);

		ret = decap(receiver, (const size_t)packet_length, (const unsigned char *const)packet,
		            link_len_src, &delta_sdus_processed);

		sdus_processed += delta_sdus_processed;

		if (ret == -1) {
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
	}

	printf("\n");

	printf("=== statistics: \n");
	{
		struct rle_receiver_stats stats;
		u_int8_t frag_id;
		for (frag_id = 0; frag_id < 8; ++frag_id) {
			rle_receiver_stats_get_counters(receiver, frag_id, &stats);
			printf("===\tFrag ID %u\n", frag_id);
			printf("===\treceiver received:          %" PRIu64 "\n", stats.sdus_received);
			printf("===\treceiver reassembled:       %" PRIu64 "\n", stats.sdus_reassembled);
			printf("===\treceiver dropped:           %" PRIu64 "\n", stats.sdus_dropped);
			printf("===\treceiver bytes received:    %" PRIu64 "\n", stats.bytes_received);
			printf("===\treceiver bytes reassembled: %" PRIu64 "\n", stats.bytes_reassembled);
			printf("===\treceiver bytes dropped:     %" PRIu64 "\n", stats.bytes_dropped);
			printf("\n");
		}
	}

	/* show the encapsulation results. */
	printf("=== summary:\n");
	printf("===\tFPDU processed:       %zu\n", packets_counter);
	printf("===\tSDU processed:        %zu\n", sdus_processed);
	printf("===\tmalformed:            %zu\n", nb_bad);
	printf("===\tinvalid:              %zu\n", nb_inv);
	printf("===\treception_failed:     %zu\n", err_reception);
	printf("===\tvalid:                %zu\n", nb_ok);
	printf("\n");

	printf("=== shutdown:\n");
	if (err_reception == 0 &&
	    (ignore_malformed || nb_bad == 0) && nb_ref == 0 &&
	    (nb_ok + nb_bad + nb_inv) == packets_counter) {
		/* test is successful */
		status = 0;
	}

close_input:
	pcap_close(handle);
	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}
error:
	return status;
}


/**
 * @brief     show the decap error linked to the decap status.
 *
 * @param[in] status          the decap status.
 *
 * @return    a printable decap error.
 */
static char *str_decap_error(const enum rle_decap_status status)
{
	switch (status) {
	case RLE_DECAP_OK:
		return "[RLE_DECAP_OK] Ok. No error detected";
	case RLE_DECAP_ERR:
		return "[RLE_DECAP_ERR] Error. SDUs should be dropped.";
	case RLE_DECAP_ERR_NULL_RCVR:
		return "[RLE_DECAP_ERR_NULL_RCVR] Error. The receiver is NULL.";
	case RLE_DECAP_ERR_ALL_DROP:
		return "[RLE_DECAP_ERR_ALL_DROP] Error. All current SDUs were dropped. Some may be lost.";
	case RLE_DECAP_ERR_SOME_DROP:
		return "[RLE_DECAP_ERR_SOME_DROP] Error. Some SDUs were dropped. Some may be lost.";
	case RLE_DECAP_ERR_INV_FPDU:
		return "[RLE_DECAP_ERR_INV_FPDU] Invalid FPDU. Maybe Null or bad size.";
	case RLE_DECAP_ERR_INV_SDUS:
		return "[RLE_DECAP_ERR_INV_SDUS] Error. Given preallocated SDUs array is invalid.";
	case RLE_DECAP_ERR_INV_PL:
		return "[RLE_DECAP_ERR_INV_PL] Error. Given preallocated payload label array is invalid.";
	default:
		return "[Unknwon RLE_DECAP status]";
	}
}

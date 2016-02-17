/**
 * @file   test_perfs.c
 * @brief  Body file used for the performances test.
 * @author Henrick Deschamps
 * @date   06/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

/* system includes */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <getopt.h>
#include <signal.h>

#include "rle.h"

/** The program version */
#define TEST_VERSION  "RLE performances test application, version 0.0.1\n"

/** The device MTU */
#define DEV_MTU  0xffffU

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** A simple minimum macro */
#define min(x, y) \
        (((x) < (y)) ? (x) : (y))

/** Min, max and default burst sizes for fragmentation in the test. */
#define MIN_BURST_SIZE 14
#define MAX_BURST_SIZE 599
#define DEFAULT_BURST_SIZE MIN_BURST_SIZE

/* prototypes of private functions */
static void usage(void);
static void test_interrupt(int signum);
static void dump_buffer(const unsigned char *const buffer, const size_t buffer_length);
static int test_encap(const char *const device_name, const size_t burst_size);
static void send_fpdu(unsigned char *const fpdu, const size_t fpdu_max_size,
                      size_t *const fpdu_current_pos, size_t *const fpdu_remaining_size,
                      size_t *const fpdus_nb);
static int encap(struct rle_transmitter *const transmitter, const size_t fpdu_max_size,
                 size_t *const fpdu_current_pos, unsigned char *const fpdu, const size_t packet_length,
                 const unsigned char *const packet, const size_t link_len_src,
                 const size_t burst_size, size_t *const fpdus_nb);
static char *str_encap_error(const enum rle_encap_status status);
static char *str_frag_error(const enum rle_frag_status status);
static char *str_pack_error(const enum rle_pack_status status);

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
	size_t burst_size = DEFAULT_BURST_SIZE;

	/* parse program arguments, print the help message in case of failure */
	if (argc <= 1) {
		usage();
		goto error;
	}

	while (1) {
		int c;

		static struct option long_options[] =
		{
			{ "verbose", no_argument, &is_verbose, 1 },
			{ "ignore_malformed", no_argument, &ignore_malformed, 1 },
			{ "burst_size", required_argument, 0, 'b' },
			{ 0, 0, 0, 0 }
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "vhb:", long_options, &option_index);

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

		case 'b': /* Burst Size */
			printf("burst size with value `%s'\n", optarg);
			burst_size = atoi(optarg);

			if (burst_size < MIN_BURST_SIZE) {
				printf("ERROR: %zu burst size is too small. Minimum = %d octets.\n",
				       burst_size, MIN_BURST_SIZE);
				goto error;
			} else if (burst_size > MAX_BURST_SIZE) {
				printf("ERROR: %zu burst size is too big. Maximum = %d octets.\n",
				       burst_size, MIN_BURST_SIZE);
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
	status = test_encap(device_name, burst_size);

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
	        "RLE performances test tool:  test the RLE library with a network interface.\n"
	        "\n"
	        "usage: test_non_regression [OPTIONS] interface\n"
	        "\n"
	        "with:\n"
	        "  interface               The network interface to sniff.\n"
	        "\n"
	        "options:\n"
	        "  -v                      Print version information and exit\n"
	        "  -h                      Print this usage and exit\n"
	        "  --burst_size, -b        Change the burst size (default 14 octets)\n"
	        "  --ignore-malformed      Ignore malformed packets for test\n"
	        "  --verbose               Run the test in verbose mode\n");

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
 * @brief      Dump a buffer
 * @param[in]  buffer_length  The size of the buffer
 * @param[in]  buffer         The buffer
 */
static void dump_buffer(const unsigned char *const buffer, const size_t buffer_length)
{
	size_t buffer_it;

	for (buffer_it = 0; buffer_it < buffer_length; ++buffer_it) {
		printf_verbose("%02x%s", buffer[buffer_it], buffer_it % 16 == 15 ? "\n" : " ");
	}
	printf_verbose("\n");

	return;
}

/**
 * @brief          Pad and send an FPDU, then reset it for the next SDU to pack.
 *
 *                 Does not actually send the FPDU, as this is not requiered in our algorithm.
 *
 * @param[in,out]  fpdu                 The FPDU to send. Reseted after sending.
 * @param[in]      fpdu_max_size        Max size of an FPDU.
 * @param[in,out]  fpdu_current_pos     Current position in the FPDU. Reseted after sending.
 * @param[in,out]  fpdu_remaining_size  Remaining size in the FPDU. Reseted after sending.
 * @param[in,out]  fpdus_nb             Number of sent FPDU.
 */
static void send_fpdu(unsigned char *const fpdu, const size_t fpdu_max_size,
                      size_t *const fpdu_current_pos, size_t *const fpdu_remaining_size,
                      size_t *const fpdus_nb)
{
	/* Padding */
	rle_pad(fpdu, *fpdu_current_pos, *fpdu_remaining_size);

	printf_verbose("=== %zu-octets FPDU ready to be sent\n", fpdu_max_size);
	dump_buffer(fpdu, fpdu_max_size);
	printf_verbose("\n");
	++(*fpdus_nb);

	/* Virtually send. */

	memset((void *)fpdu, '\0', fpdu_max_size);
	*fpdu_current_pos = 0;
	*fpdu_remaining_size = fpdu_max_size;

	return;
}

/**
 * @brief Encapsulate, fragment, pack one SDU with a given transmitter.
 *
 * @param[in,out] transmitter       The transmitter to use.
 * @param[in]     fpdu_max_size     The maximum size of an FPDU
 * @param[in,out] fpdu_current_pos  The current position in the FPDU
 * @param[in,out] fpdu              A buffer to contain the FPDU, preallocated. May contains 
 *                                  fragments of SDUs between function call.
 * @param[in]     packet_length     Lenght of the packet to encapsulate.
 * @param[in]     packet            The packet to encapsulate (link layer included)
 * @param[in]     link_len_src      The length of the link layer header before IP data
 * @param[in]     burst_size        The size of the burst to pack
 * @param[out]    fpdus_nb          The number of FPDU sent
 *
 * @return                  1 if the process is successful
 *                          2 if the process is not successful, but due to a misuse of the RLE lib.
 *                          -1 if an error occurs while transmitting
 *                          -3 if the link layer is not Ethernet
 */
static int encap(struct rle_transmitter *const transmitter, const size_t fpdu_max_size,
                 size_t *const fpdu_current_pos, unsigned char *const fpdu,
                 const size_t packet_length,
                 const unsigned char *const packet, const size_t link_len_src,
                 const size_t burst_size, size_t *const fpdus_nb)
{
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;

	struct rle_sdu sdu_in;

	const size_t label_length = 0;
	const unsigned char *label = NULL;

	int status = 1;
	const uint8_t frag_id = 0;

	sdu_in.buffer = (unsigned char *)packet + link_len_src;
	sdu_in.size = packet_length - link_len_src;
	sdu_in.protocol_type = ntohs(*(uint16_t *)((void *)(packet + (ETHER_HDR_LEN - 2))));

	printf_verbose("=== %zu-byte SDU\n", sdu_in.size);
	dump_buffer(sdu_in.buffer, sdu_in.size);

	/* Encapsulate the IP packet into a RLE packet */
	printf_verbose("=== RLE encapsulation: start\n");
	ret_encap = rle_encapsulate(transmitter, &sdu_in, frag_id);

	switch (ret_encap) {
	case RLE_ENCAP_OK:
		printf_verbose("=== RLE encapsulation: success\n");
		break;
	case RLE_ENCAP_ERR_NULL_TRMT:
	case RLE_ENCAP_ERR_SDU_TOO_BIG:
		printf_verbose("=== RLE encapsulation: misuse\n    %s\n", str_encap_error(ret_encap));
		status = 2;
		goto exit;
	case RLE_ENCAP_ERR:
	default:
		printf_verbose("=== RLE encapsulation: failure\n");
		status = -1;
		goto exit;
	}

	while (rle_transmitter_stats_get_queue_size(transmitter, frag_id) != 0) {
		size_t fpdu_remaining_size = fpdu_max_size - *fpdu_current_pos;
		printf_verbose("Remaining size : %zu\n", fpdu_remaining_size);

		unsigned char *ppdu;
		size_t ppdu_length = 0;
		size_t ppdu_needed;

		/* If the FPDU already contains data, we try to make a PPDU small enough. If it is not 
		 * possible to make a small PPDU, a regular one is made instead, and will be pack in a new
		 * FPDU. The old FPDU then is padded and send. */

		if (fpdu_remaining_size < burst_size) {
			ppdu_needed = fpdu_remaining_size;
		} else {
			ppdu_needed = burst_size;
		}

		/* Fragmentation */
		do {
			printf_verbose("=== RLE fragmentation: start\n");
			ret_frag = rle_fragment(transmitter, frag_id, ppdu_needed, &ppdu, &ppdu_length);

			switch (ret_frag) {
			case RLE_FRAG_OK:
				printf_verbose("=== RLE fragmentation: success. "
				               "burst_size: %zu, remaining alpdu: %zu.\n",
				               ppdu_length,
				               rle_transmitter_stats_get_queue_size(transmitter, frag_id));
				printf_verbose("=== %zu-byte PPDU\n", ppdu_length);
				dump_buffer(ppdu, ppdu_length);
				break;
			case RLE_FRAG_ERR_BURST_TOO_SMALL:
				printf_verbose("=== RLE fragementation: burst size (%zu) too small. "
				               "Retry fragmentation with max burst size (%zu)\n",
				               ppdu_needed, burst_size);
				ppdu_needed = burst_size;
				break;
			case RLE_FRAG_ERR_NULL_TRMT:
			case RLE_FRAG_ERR_INVALID_SIZE:
			case RLE_FRAG_ERR_CONTEXT_IS_NULL:
				printf_verbose("=== RLE fragmentation: misuse\n"
				               "    %s\n", str_frag_error(ret_frag));
				status = 2;
				goto exit;
			case RLE_FRAG_ERR:
			default:
				printf_verbose("=== RLE fragmentation: failure\n");
				status = -1;
				goto exit;
			}
		} while(ret_frag == RLE_FRAG_ERR_BURST_TOO_SMALL);

		/* Packing */
		printf_verbose("=== RLE packing: start\n");
		do {
			ret_pack = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, fpdu_current_pos, 
					              &fpdu_remaining_size);

			switch (ret_pack) {
			case RLE_PACK_OK:
				printf_verbose("=== RLE packing: success\n");
				if (fpdu_remaining_size != 0) {
					printf_verbose("===> packed in %zu-byte FPDU (remains %zu bytes)\n",
					               *fpdu_current_pos, fpdu_remaining_size);
				} else {
					printf_verbose("=== RLE packing: FPDU Full.  %zu-octets FPDU ready to be sent\n",
					               fpdu_max_size);
					send_fpdu(fpdu, fpdu_max_size, fpdu_current_pos,
					          &fpdu_remaining_size,
					          fpdus_nb);
				}
				break;
			case RLE_PACK_ERR_FPDU_TOO_SMALL:
				/* FPDU too small to contain data. It is padded and send, and a new FPDU is created. */
				printf_verbose("=== RLE packing: FPDU Full,  padding, sending,"
						         "and starting new FPDU\n");
				send_fpdu(fpdu, fpdu_max_size, fpdu_current_pos, &fpdu_remaining_size, fpdus_nb);
				break;
			case RLE_PACK_ERR_INVALID_LAB:
			case RLE_PACK_ERR_INVALID_PPDU:
				printf_verbose("=== RLE packing: misuse\n"
				               "    %s\n", str_pack_error(ret_pack));
				status = 2;
				goto exit;
			case RLE_PACK_ERR:
			default:
				printf_verbose("=== RLE packing: failure\n");
				status = -1;
				goto exit;
			}
			/* If the FPDU were too small, we retry the packing with a new one. */
		} while (ret_pack == RLE_PACK_ERR_FPDU_TOO_SMALL);
	}

exit:
	printf_verbose("\n");
	return status;
}


/**
 * @brief Test the RLE library with a flow of IP packets going through
 *        encapsulation, fragmentation, and packing.
 *
 * @param[in] device_name      The name of the interface listened
 * @param[in] burst_size       The size of the bursts.
 *
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_encap(const char *const device_name, const size_t burst_size)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	const size_t fpdu_max_size = burst_size;
	unsigned char fpdu[fpdu_max_size];
	size_t fpdu_current_pos = 0;

	struct rle_transmitter *transmitter;

	int ret;
	size_t nb_bad = 0, nb_ok = 0, err_transmition = 0, nb_ref = 0, nb_inv = 0;
	int status = 1;

	size_t fpdus_processed = 0;

	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x30,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 1,
		.use_ptype_omission = 1
	};

	transmitter = rle_transmitter_new(&conf);

	if (transmitter == NULL) {
		printf("ERROR: transmitter non initialized\n");
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
	printf("===\tALPDU protection:    %s\n", conf.use_alpdu_crc ? "CRC" : "SeqNo");
	printf("===\tptype compression:   %s\n", conf.use_compressed_ptype ? "On" : "Off");
	printf("===\tptype ommission:     %s\n", conf.use_ptype_omission ? "On" : "Off");

	stop_program = 0;

	printf("\nTest starting...\n");

	while (!stop_program) {
		size_t packet_length = 0;
		size_t delta_fpdus_processed = 0;
		unsigned char *packet = (unsigned char *)pcap_next(handle, &header);

		if (packet == NULL) {
			/* no packet captured, re-try */
			continue;
		}

		++packets_counter;
		packet_length = header.len;

		printf_verbose("Packet #%zu\n", packets_counter);
		ret = encap(transmitter,
		            fpdu_max_size,
		            &fpdu_current_pos,
		            fpdu, (const size_t)packet_length,
		            (const unsigned char *const)packet, link_len_src,
		            burst_size, &delta_fpdus_processed);

		fpdus_processed += delta_fpdus_processed;

		if (ret == -1) {
			err_transmition++;
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

	/* Pad and send the last FPDU if exists. */
	if (fpdu_current_pos != 0) {
		size_t delta_fpdus_processed = 0;
		size_t fpdu_remaining_size = fpdu_max_size - fpdu_current_pos;
		send_fpdu(fpdu, fpdu_max_size, &fpdu_current_pos, &fpdu_remaining_size,
		          &delta_fpdus_processed);
		fpdus_processed += delta_fpdus_processed;
	}

	printf("\n");

	printf("=== statistics: \n");
	{
		u_int8_t frag_id;
		for (frag_id = 0; frag_id < 8; ++frag_id) {
			printf("===\tFrag ID %u\n", frag_id);
			printf("===\ttransmitter in:             %" PRIu64 "\n",
					rle_transmitter_stats_get_counter_sdus_in(transmitter, frag_id));
			printf("===\ttransmitter sent:           %" PRIu64 "\n",
					rle_transmitter_stats_get_counter_sdus_sent(transmitter, frag_id));
			printf("===\ttransmitter dropped:        %" PRIu64 "\n",
					rle_transmitter_stats_get_counter_sdus_dropped(transmitter, frag_id));
			printf("===\ttransmitter bytes in:       %" PRIu64 "\n",
					rle_transmitter_stats_get_counter_bytes_in(transmitter, frag_id));
			printf("===\ttransmitter bytes sent:     %" PRIu64 "\n",
					rle_transmitter_stats_get_counter_bytes_sent(transmitter, frag_id));
			printf("===\ttransmitter bytes dropped:  %" PRIu64 "\n",
					rle_transmitter_stats_get_counter_bytes_dropped(transmitter, frag_id));
			printf("\n");
		}
	}

	/* show the encapsulation results. */
	printf("=== summary:\n");
	printf("===\tSDU processed:        %zu\n", packets_counter);
	printf("===\tFPDU processed:       %zu\n", fpdus_processed);
	printf("===\tmalformed:            %zu\n", nb_bad);
	printf("===\tinvalid:              %zu\n", nb_inv);
	printf("===\ttransmition_failed:   %zu\n", err_transmition);
	printf("===\tvalid:                %zu\n", nb_ok);
	printf("\n");

	printf("=== shutdown:\n");
	if (err_transmition == 0 &&
	    (ignore_malformed || nb_bad == 0) && nb_ref == 0 &&
	    (nb_ok + nb_bad + nb_inv) == packets_counter) {
		/* test is successful */
		status = 0;
	}

close_input:
	pcap_close(handle);
	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
error:
	return status;
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

/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file    kmod_test_userspace.c
 * @brief   A small program to interact with the Linux Kernel module test.
 * @author  Henrick Deschamps <henrick.deschamps@toulouse.viveris.com>
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>         /* for ntohs() on Linux */
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <netinet/in.h>

#include <pcap/pcap.h>
#include <pcap.h>

#include "include/rle.h"

#define TEST_VERSION "0.0.1"
#define PROC_INTERFACE "/proc/librle_test_interface"

/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** Whether the application runs in verbose mode or not */
static int is_verbose = 0;

#define printf_verbose(x ...) do { \
		if (is_verbose) { printf(x); } \
} while (0)

static void usage(void);
static int write_file(const size_t sdu_in_length, const unsigned char *const sdu_in);
static int read_file(const size_t sdu_out_buffer_length, unsigned char *const sdu_out_buffer,
                     size_t *sdu_out_length);
static int compare_sdus(const size_t sdu_in_size, const unsigned char *const sdu_in,
                        const size_t sdu_out_size, const unsigned char *const sdu_out);
static int test_encap_and_decap(const char src_filename[]);
static int encap_decap(const size_t *const packets_length,
                       const unsigned char *const *const packets, const size_t number_of_packets,
                       const size_t link_len_src);

/**
 * @brief  Print usage
 */
static void usage(void)
{
	printf("KMOD test Userspace.                                \n"
	       "Test the RLE kernel module with a flow of IP packet.\n"
	       "                                                    \n"
	       "Usage:\t<test_name> [option] pcap_file              \n"
	       "                                                    \n"
	       "with:                                               \n"
	       "\tpcap_file   The name of the network trace.        \n"
	       "                                                    \n"
	       "options:                                            \n"
	       "\t--verbose:  verbose.                              \n"
	       "\t-h:         print usage.                          \n"
	       "\t-v:         print version.                        \n");
}

/**
 * @brief     Write an SDU in the interface file (for test module).
 * @param[in] sdu_in        The SDU to write.
 * @param[in] sdu_in_length The length of the SDU to write.
 * @return    EXIT_SUCCESS if successful, else EXIT_FAILURE.
 */
static int write_file(const size_t sdu_in_length, const unsigned char *const sdu_in)
{
	int exit_status = EXIT_FAILURE;
	int ret;
	int out_file_fd;
	const char *const out_filename = PROC_INTERFACE;

	printf_verbose("start writing to %s.\n", out_filename);

	out_file_fd = open(out_filename, O_WRONLY);

	if (out_file_fd == -1) {
		printf("ERROR: Unable to open %s - %s (%d).\n", out_filename, strerror(errno), errno);
		goto error;
	}

	ret = write(out_file_fd, (void *)sdu_in, sdu_in_length);

	if (ret == -1) {
		printf("ERROR: Unabe to write %zu-octets SDU in %s - %s (%d).\n", sdu_in_length,
		       out_filename, strerror(errno), errno);
		ret = close(out_file_fd);
		if (ret == -1) {
			printf("ERROR: Unable to close file %s - %s (%d).\n", out_filename, strerror(errno), errno);
		}
		goto error;
	}

	ret = close(out_file_fd);
	if (ret == -1) {
		printf("ERROR: Unable to close file %s - %s (%d).\n", out_filename, strerror(errno), errno);
		goto error;
	}

	printf_verbose("writing success, %zu-octets SDU written in %s.\n", sdu_in_length, out_filename);

	exit_status = EXIT_SUCCESS;

error:
	return exit_status;
}

/**
 * @brief         Read an SDU from the interface file (from the test module).
 * @param[in]     sdu_out_buffer_length The size of the buffer for the SDU.
 * @param[in,out] sdu_out_buffer        A buffer to store the SDU (preallocated).
 * @param[out]    sdu_out_length        The real size of the SDU.
 * @return        EXIT_SUCCESS if successful, else EXIT_FAILURE.
 */
static int read_file(const size_t sdu_out_buffer_length, unsigned char *const sdu_out_buffer,
                     size_t *sdu_out_length)
{
	int exit_status = EXIT_FAILURE;
	int ret;
	int in_file_fd;
	const char *const in_filename = PROC_INTERFACE;

	printf_verbose("start reading from %s.\n", in_filename);

	in_file_fd = open(in_filename, O_RDONLY);

	if (in_file_fd == -1) {
		printf("ERROR: Unable to open %s.\n", in_filename);
		goto error;
	}

	ret = read(in_file_fd, (void *)sdu_out_buffer, sdu_out_buffer_length);

	if (ret == -1) {
		printf("ERROR: Unable to read SDU from %s - %s (%d).\n", in_filename, strerror(errno), errno);
		close(in_file_fd);
		ret = close(in_file_fd);
		if (ret == -1) {
			printf("ERROR: Unable to close file %s - %s (%d).\n", in_filename, strerror(errno), errno);
		}
		goto error;
	}

	*sdu_out_length = ret;

	ret = close(in_file_fd);
	if (ret == -1) {
		printf("ERROR: Unable to close file %s - %s (%d).\n", in_filename, strerror(errno), errno);
		goto error;
	}

	printf_verbose("reading success: %zu-octets read from %s.\n", *sdu_out_length, in_filename);

	exit_status = EXIT_SUCCESS;

error:
	return exit_status;
}

/**
 * @brief     Compare two SDUs.
 * @param[in] sdu_in_size  The size of the SDU in.
 * @param[in] sdu_in       The SDU in (the one written for the test module).
 * @param[in] sdu_out_size The size of the SDU in.
 * @param[in] sdu_out      The SDU out (the one read from the test module).
 * @return    EXIT_SUCCESS if the SDUs are the same, else EXIT_FAILURE.
 */
static int compare_sdus(const size_t sdu_in_size, const unsigned char *const sdu_in,
                        const size_t sdu_out_size, const unsigned char *const sdu_out)
{
	int exit_status = EXIT_SUCCESS;

	if (sdu_in_size != sdu_out_size) {
		printf("=== ERROR: SDUs have different lengths (in: %zu, out: %zu)\n",
				  sdu_in_size, sdu_out_size);
	}

	printf_verbose("Comparing %zu-octets SDUs.\n", sdu_in_size);

	size_t iterator;

	for (iterator = 0; iterator < sdu_in_size; ++iterator) {
		if (sdu_in[iterator] != sdu_out[iterator]) {
			printf_verbose("Difference pos. %zu.\t(%02x != %02x)\n", iterator, sdu_in[iterator],
					         sdu_out[iterator]);
			exit_status = EXIT_FAILURE;
		}
	}

	if (exit_status == EXIT_SUCCESS) {
		printf_verbose("SDUs are the same.\n");
	}

	return exit_status;
}

/**
 * @brief     Read a PCAP file, and initialize the encapsulation/decapsulation on the packets.
 * @param[in] src_filename The name of the PCAP file.
 * @return    0 if OK, else 1.
 */
static int test_encap_and_decap(const char src_filename[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	unsigned char *packet;

	int counter;

	int ret;
	int status = 1;

	printf("=== initialization:\n");

	/* open the source dump file */
	handle = pcap_open_offline(src_filename, errbuf);
	if (handle == NULL) {
		printf("failed to open the source pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB) {
		printf("link layer type %d not supported in source dump (supported = "
		       "%d)\n", link_layer_type_src, DLT_EN10MB);
		goto close_input;
	}

	link_len_src = ETHER_HDR_LEN;

	printf_verbose("\n");

	/* for each packet in the dump */
	unsigned char **packets = malloc(sizeof(unsigned char *));

	if (packets == NULL) {
		printf("ERROR - Unable to allocate packets - %s (%d).\n", strerror(errno), errno);
		goto close_input;
	}

	size_t *packets_length = malloc(sizeof(size_t));

	if (packets_length == NULL) {
		printf("ERROR - Unable to allocate packets length - %s (%d).\n", strerror(errno), errno);
		goto free_alloc;
	}

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
		}
		packets = realloc_ret;
		realloc_ret = realloc((void *)packets_length, counter * sizeof(size_t));
		if (realloc_ret == NULL) {
			printf("failed to copy the packets length.\n");
			goto free_alloc;
		}
		packets_length = realloc_ret;
		packets_length[counter - 1] = header.len;

		packets[counter - 1] = calloc(packets_length[counter - 1], sizeof(unsigned char));
		if (packets[counter - 1] == NULL) {
			printf("failed to copy a packet.\n");
			goto free_alloc;
		}

		memcpy((void *)packets[counter - 1], (const void *)packet, packets_length[counter - 1]);
	}


	ret = encap_decap((const size_t *const)packets_length,
	                   (const unsigned char *const *const)packets,
	                   (const size_t)counter,
	                   link_len_src);

   /* show the encapsulation/decapsulation results. */
	printf_verbose("=== summary:\n");
	printf_verbose("===\tSDU processed:        %d\n", counter);
	printf_verbose("===\tmatches:              %d\n", ret);
	printf_verbose("\n");

	printf_verbose("=== shutdown:\n");
	if (counter == ret) {
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
 * @brief         Dump an SDU. Print purpose only.
 * @param[in] sdu The SDU to dump
 */
static void dump_sdu(const struct rle_sdu sdu)
{
	size_t it;
	for (it = 0; it < sdu.size; ++it) {
		printf_verbose("%02x%s", sdu.buffer[it], it % 16 == 15 ? "\n" : " ");
	}
	printf_verbose("\n");

	return;
}

/**
 * @brief     If the packet is an instance of IPv4 or IPv6, check the version in the IP header.
 *
 *            A wrong IP header version field leads to an error in the decapsulation.
 *
 * @param[in] sdu The SDU to check.
 * @return    EXIT_SUCCESS if OK, else EXIT_FAILURE.
 */
static int check_ip_integrity(const struct rle_sdu sdu)
{
	const uint16_t sdu_in_ptype = sdu.protocol_type;
	const uint8_t sdu_in_ip_version = (sdu.buffer[0] >> 4) & 0x0f;
	int ret_val = EXIT_FAILURE;

	switch (sdu_in_ptype) {
		case 0x0800:
			if (sdu_in_ip_version != 0x04) {
				printf("Invalid: IP version in IPv4 packet is %d, expected: %d.\n",
						 sdu_in_ip_version, 0x04);
				goto error;
			}
			break;
		case 0x86dd:
			if (sdu_in_ip_version != 0x06) {
				printf("Invalid: IP version in IPv6 packet is %d, expected: %d.\n",
						 sdu_in_ip_version, 0x06);
				goto error;
			}
			break;
		default:
			break;
	}

	ret_val = EXIT_SUCCESS;

error:
	return ret_val;
}

/**
 * @brief     Write in the file interface the previously extracted packets, then read them and
 *            compare them.
 *
 *            The test module encapsulated, fragment, pack and decapsulate the packets.
 *
 * @param[in] link_len_src      The lenght of the link layer in the packets.
 * @param[in] number_of_packets The number of packets.
 * @param[in] packets           The packets to write in the interface.
 * @param[in] packets_length    the lengths of the packets.
 * @return    EXIT_SUCCESS if OK, else EXIT_FAILURE.
 */
static int encap_decap(const size_t *const packets_length,
                       const unsigned char *const *const packets, const size_t number_of_packets,
                       const size_t link_len_src)
{
	int ret = 0;

	int exit_status = EXIT_SUCCESS;

	/* Prepare the buffers for input SDUs. */
	size_t packet_iterator = 0;
	struct rle_sdu sdus_in[number_of_packets];

	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		sdus_in[packet_iterator].buffer = (unsigned char *)packets[packet_iterator] +
		                                  link_len_src;
		sdus_in[packet_iterator].size = packets_length[packet_iterator] - link_len_src;
	}

	/* Prepare the buffers for decapsulated SDUs. */
	struct rle_sdu sdus_out[number_of_packets];
	const size_t sdu_out_buf_length = 5000;
	uint8_t sdu_out_buf[number_of_packets][sdu_out_buf_length];

	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		memset((void *)sdu_out_buf[packet_iterator], '\0', sdu_out_buf_length);
		sdus_out[packet_iterator].buffer = sdu_out_buf[packet_iterator] + link_len_src;
	}

	/* Write the packets in the interface. */
	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		int ip_integrity;
		printf_verbose("\n=== packet #%zu:\n", packet_iterator + 1);

		sdus_in[packet_iterator].protocol_type =
		        ntohs(*(uint16_t *)((void *)(packets[packet_iterator] + (ETHER_HDR_LEN - 2))));

		ip_integrity = check_ip_integrity(sdus_in[packet_iterator]);

		if (ip_integrity == EXIT_FAILURE) {
			printf("ERROR: Bad packet integrity.\n");
			goto exit;
		}

		printf_verbose("=== %zu-byte SDU\n", sdus_in[packet_iterator].size);
		dump_sdu(sdus_in[packet_iterator]);

		exit_status = write_file(sdus_in[packet_iterator].size, sdus_in[packet_iterator].buffer);

		if (exit_status == EXIT_FAILURE) {
			printf("ERROR: Unable to write SDU in /proc file.\n");
			goto exit;
		}
	}

	printf_verbose("=== RLE decapsulation: start\n");
	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		/* decapsulate the FPDU */
		exit_status = read_file(sdu_out_buf_length, sdus_out[packet_iterator].buffer,
		                        &sdus_out[packet_iterator].size);
		if (exit_status == EXIT_FAILURE) {
			printf("ERROR: Unable to read SDU from /proc file.\n");
			goto exit;
		}
	}

	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		printf_verbose("%zu-byte decapsuled SDU:\n", sdus_out[packet_iterator].size);
		dump_sdu(sdus_out[packet_iterator]);
	}

	/* compare the decapsulated packet with the original one */
	printf_verbose("=== IP comparison: start\n");
	for (packet_iterator = 0; packet_iterator < number_of_packets; ++packet_iterator) {
		struct rle_sdu sdu_in = sdus_in[packet_iterator];
		struct rle_sdu sdu_out = sdus_out[packet_iterator];

		exit_status = compare_sdus(sdu_in.size, sdu_in.buffer, sdu_out.size, sdu_out.buffer);
		if (exit_status == EXIT_FAILURE) {
			printf_verbose("=== IP comparison: failure\n");
		} else {
			printf_verbose("=== IP comparison: success\n");
			++ret;
		}
	}

exit:
	printf_verbose("\n");
	return ret;
}

/**
 * @brief     Main function. Parse the argument, and if needed, launch the test.
 * @param[in] argc  The number of argument.
 * @param[in] *argv The list of argument.
 * @return    EXIT_SUCCESS if OK, else EXIT_FAILURE
 */
int main(int argc, char *argv[])
{
	int exit_status = EXIT_FAILURE;
	int args_used;
	const char *src_filename;

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
		fprintf(stderr, "pcap_file is a mandatory parameter\n\n");
		usage();
		goto error;
	}

	/* test RLE encap/decap with the packets from the file */
	exit_status = test_encap_and_decap(src_filename);

	printf("=== exit test with code %d\n", exit_status);
	/* do not accept more than one filename without option name */

error:
	return exit_status;
}

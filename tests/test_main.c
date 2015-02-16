#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "test_common.h"
#include "constants.h"
#include "rle_ctx.h"
#include "header.h"
#include "trailer.h"

/* cmd line options */
static int opt_crc_flag = C_FALSE;
static int opt_seq_flag = C_FALSE;
static int opt_encap_deencap_test_flag = C_FALSE;
static int opt_frag_rea_min_max_test_flag = C_FALSE;
static int opt_frag_rea_test_flag = C_FALSE;

static struct option long_options[] =
{
	{ "burst_size", required_argument, NULL, 'b' },
	{ "ptype", required_argument, NULL, 'p' },
	{ "pcap_file", required_argument, NULL, 'f' },
	{ "enable_crc", no_argument, NULL, 'c' },
	{ "enable_seq", no_argument, NULL, 's' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "test_encap_deencap", no_argument, NULL, 'e' },
	{ "test_limits_rea", no_argument, NULL, 'l' },
	{ "test_frag_rea", no_argument, NULL, 'r' },
	{ "test_all", no_argument, NULL, 'a' },
	{ "help", no_argument, NULL, 'h' },
	{ 0, 0, 0, 0 }
};

static void print_usage(char *basename)
{
	PRINT("%s [-csvelrah] [ -b BURST_SIZE ] [ -p PROTOCOL_TYPE ] [ -f PCAP_FILENAME ]\n",
	      basename);
	PRINT("\t-v (verbose mode with RLE context dumps)\n"
	      "\t-c enable CRC trailer (default)\n"
	      "\t-s enable sequence number trailer\n"
	      "\t-e launch encapsulation/deencapsulation test\n"
	      "\t-l launch limits of fragmentation/reassembly test\n"
	      "\t-r launch fragmentation/reassembly test\n"
	      "\t-a launch all tests\n"
	      "\t-b BURST_SIZE in Bytes (valid values between 15 and 512 Bytes)\n"
	      "\t-p PROTOCOL_TYPE (uncompressed protocol type in hexa)\n"
	      "\t-f PCAP_FILENAME (valid pcap file corresponding to PROTOCOL_TYPE)\n"
	      "\t-h print this help\n");
}

int main(int argc, char *argv[])
{
	char *param_file_name = NULL;
	uint32_t param_protocol_type = 0;
	uint16_t param_burst_size = 0;
	int ret = C_OK;
	int opt = 0;
	int option_index = 0;

	opt_verbose_flag = C_FALSE;

	while ((opt = getopt_long(argc, argv, "csvelrah:b:p:f:",
	                          long_options, &option_index)) != -1) {
		switch (opt) {
		case 'b':
			param_burst_size = atoi(optarg);
			if ((param_burst_size > FAKE_BURST_MAX_SIZE) ||
			    (param_burst_size < 15)) {
				PRINT("ERROR fake burst size parameter is invalid\n");
				ret = C_ERROR;
				goto exit_ret;
			}
			break;
		case 'p':
			param_protocol_type = (uint32_t)strtol(optarg, NULL, 16);
			if (param_protocol_type > 0xffff) {
				PRINT("ERROR protocol type parameter is invalid\n");
				ret = C_ERROR;
				goto exit_ret;
			}
			break;
		case 'f':
			param_file_name = optarg;
			break;
		case 'c':
			opt_crc_flag = ENABLE_CRC;
			break;
		case 's':
			opt_seq_flag = ENABLE_SEQ;
			break;
		case 'e':
			opt_encap_deencap_test_flag = C_TRUE;
			break;
		case 'l':
			opt_frag_rea_min_max_test_flag = C_TRUE;
			break;
		case 'r':
			opt_frag_rea_test_flag = C_TRUE;
			break;
		case 'a':
			opt_encap_deencap_test_flag = C_TRUE;
			opt_frag_rea_min_max_test_flag = C_TRUE;
			opt_frag_rea_test_flag = C_TRUE;
			break;
		case 'v':
			opt_verbose_flag = C_TRUE;
			break;
		case '?':
		case 'h':
		default:
			print_usage(argv[0]);
			ret = C_ERROR;
			goto exit_ret;
		}
	}

	if (param_file_name == NULL) {
		PRINT("ERROR: no file name provided\n");
		goto exit_ret;
	}

	if (param_protocol_type != 0) {
		PRINT("INFO: TEST with protocol type 0x%0x\n"
		      " burst size %d\n"
		      " pcap file %s\n",
		      param_protocol_type,
		      param_burst_size,
		      param_file_name);
	} else {
		PRINT("INFO: TEST with protocol to determine in PCAP"
		      " burst size %d\n"
		      " pcap file %s\n",
		      param_burst_size,
		      param_file_name);
	}

	/* fallback on valid trailer type to test */
	if (opt_crc_flag != ENABLE_CRC && opt_seq_flag != ENABLE_SEQ) {
		PRINT("No trailer specified, test only CRC trailer\n");
		opt_crc_flag = ENABLE_CRC;
	}

	/* Test RLE fragmentation and reassembly */
	if (opt_frag_rea_test_flag == C_TRUE) {
		if (opt_crc_flag == ENABLE_CRC) {
			/* Test on multiple queue */
			ret = init_test_frag_rea(param_file_name,
			                         param_protocol_type,
			                         param_burst_size,
			                         RLE_MAX_FRAG_NUMBER,
			                         opt_crc_flag);
		}

		if (opt_seq_flag == ENABLE_SEQ && ret == C_OK) {
			/* Test on multiple queue */
			ret = init_test_frag_rea(param_file_name,
			                         param_protocol_type,
			                         param_burst_size,
			                         RLE_MAX_FRAG_NUMBER,
			                         opt_seq_flag);
		}
	}

	/* Test RLE fragmentation and reassembly limits */
	if (opt_frag_rea_min_max_test_flag == C_TRUE) {
		if (opt_crc_flag == ENABLE_CRC) {
			/* Test with CRC on one queue
			 * trailer */
			ret = init_test_frag_rea_min_max(param_file_name,
			                                 1,
			                                 opt_crc_flag);
		}

		if (opt_crc_flag == ENABLE_CRC && ret == C_OK) {
			/* Test on multiple queue
			 * with CRC
			 * trailer */
			ret = init_test_frag_rea_min_max(param_file_name,
			                                 RLE_MAX_FRAG_NUMBER,
			                                 opt_crc_flag);
		}

		if (opt_seq_flag == ENABLE_SEQ && ret == C_OK) {
			/* Test with Next Sequence Number on one queue
			 * trailer */
			ret = init_test_frag_rea_min_max(param_file_name,
			                                 1,
			                                 opt_seq_flag);
		}

		if (opt_seq_flag == ENABLE_SEQ && ret == C_OK) {
			/* Test on multiple queue
			 * with Next Sequence Number trailer */
			ret = init_test_frag_rea_min_max(param_file_name,
			                                 RLE_MAX_FRAG_NUMBER,
			                                 opt_seq_flag);
		}
	}

	/* Test RLE simple encapsulation and deencapsulation */
	if (opt_encap_deencap_test_flag == C_TRUE) {
		ret = init_test_encap_deencap(param_file_name, 1);

		if (ret == C_OK) {
			ret = init_test_encap_deencap(param_file_name, RLE_MAX_FRAG_NUMBER);
		}
	}

exit_ret:
	return ret;
}

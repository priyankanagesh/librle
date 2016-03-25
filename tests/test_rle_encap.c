/**
 * @file   test_rle_encap.c
 * @brief  Body file used for the encapsulation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_encap.h"

#include "rle_transmitter.h"
#include "rle_receiver.h"
#include "fragmentation_buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

/**
 * @brief         Compare two packets.
 *
 *                If pkt_1_length and pkt_2_length are different, there is no use to run the test,
 *                it will return false.
 *
 * @param[in]     pkt_1                    The first packet
 * @param[in]     pkt_1_length             The size of the first packet
 * @param[in]     pkt_2                    The second packet
 * @param[in]     pkt_2_length             The size of the second packet
 *
 * @return        true if OK, else false.
 */
static bool compare_packets(const unsigned char pkt_1[], const size_t pkt_1_length,
                                    const unsigned char pkt_2[],
                                    const size_t pkt_2_length);

static void print_modules_stats(void)
{
	print_transmitter_stats();
	return;
}

/**
 * @brief         Check the encapsulation of a given SDU in an ALPDU.
 *
 * @param[in]     sdu                      the SDU to check
 * @param[in]     sdu_length               the SDU length
 * @param[in]     alpdu                    the ALPDU to check
 * @param[in]     alpdu_length             the ALPDU length
 * @param[in]     alpdu_header             the ALPDU header we should have
 * @param[in]     alpdu_header_length      the ALPDU size we should have
 *
 * @return        true if OK, else false.
 */
static bool check_encap(const unsigned char sdu[], const size_t sdu_length,
                        const unsigned char alpdu[], const size_t alpdu_length,
                        const unsigned char alpdu_header[],
                        const size_t alpdu_header_length);

/**
 * @brief         Generic encapsulation test.
 *
 *                Simply encap in one of the frag id of a transmitter, knowing the protocol type
 *                and the length of the sdu.
 *
 * @param[in]     protocol_type            The protocol type of the SDU
 * @param[in]     conf                     Configuration of the transmitter
 * @param[in]     length                   The protocol length of the SDU
 * @param[in]     frag_id                  The fragment id
 *
 * @return        true if OK, else false.
 */
static bool test_encap(const uint16_t protocol_type,
                       const struct rle_config conf,
                       const size_t length,
                       const uint8_t frag_id);

static bool compare_packets(const unsigned char pkt_1[], const size_t pkt_1_length,
                                    const unsigned char pkt_2[],
                                    const size_t pkt_2_length)
{
	PRINT_TEST("subtest. sizes : %zu - %zu", pkt_1_length, pkt_2_length);
	bool output = false;
	size_t iterator = 0;

	/* Checking the sizes. */
	if (pkt_1_length != pkt_2_length) {
		PRINT_ERROR("packet sizes are different.");
		/* Although practicality beats purity. */
		goto exit_label;
	}

	/* Checking octet by octet. */
	output = true;
	for (iterator = 0; iterator < pkt_1_length; ++iterator) {
		if (pkt_1[iterator] != pkt_2[iterator]) {
			PRINT_ERROR(
			        "packets are different: pkt index %zu, expected 0x%02x, get 0x%02x",
			        iterator + 1, pkt_1[iterator], pkt_2[iterator]);
			output = false;
		}
	}

exit_label:
	PRINT_TEST_STATUS(output);
	return output;
}

static bool check_encap(const unsigned char sdu[], const size_t sdu_length,
                        const unsigned char alpdu[], const size_t alpdu_length,
                        const unsigned char alpdu_header[],
                        const size_t alpdu_header_length)
{
	bool output = false;
	size_t theorical_alpdu_length = sdu_length + alpdu_header_length;
	unsigned char theorical_alpdu[theorical_alpdu_length];

	assert(sdu != NULL);
	assert(alpdu != NULL);

	PRINT_TEST("subtest. sizes : SDU %zu, header %zu, ALPDU %zu", sdu_length,
	           alpdu_header_length, alpdu_length);

	/* Checking the sizes. */
	if (theorical_alpdu_length != alpdu_length) {
		PRINT_ERROR("SDU + theorical ALPDU header and ALPDU length are different");
		goto exit_label;
	}
	/* Merging SDU and theorical ALPDU header in a theorical ALPDU. */
	if (alpdu_header != NULL) {
		memcpy(theorical_alpdu, alpdu_header, alpdu_header_length);
	}
	memcpy(theorical_alpdu + alpdu_header_length, sdu, sdu_length);

	/* Checking theorical ALPDU and given ALPDU. */
	output = compare_packets(alpdu, alpdu_length, theorical_alpdu, theorical_alpdu_length);

exit_label:
	PRINT_TEST_STATUS(output);
	return output;
}

static bool is_suppressible(uint16_t protocol_type, uint8_t default_ptype)
{
	bool suppressible = false;

	switch (protocol_type) {
	case 0x0082:
		suppressible = true;
		break;
	case 0x8100:
		suppressible = (default_ptype == 0x0f);
		break;
	case 0x88a8:
		suppressible = (default_ptype == 0x19);
		break;
	case 0x9100:
		suppressible = (default_ptype == 0x1a);
		break;
	case 0x0800:
		suppressible = (default_ptype == 0x0d);
		suppressible |= (default_ptype == 0x30);
		break;
	case 0x86dd:
		suppressible = (default_ptype == 0x11);
		suppressible |= (default_ptype == 0x30);
		break;
	case 0x0806:
		suppressible = (default_ptype == 0x0e);
		break;
	default:
		break;
	}

	return suppressible;
}

static bool test_encap(const uint16_t protocol_type,
                       const struct rle_config conf,
                       const size_t length,
                       const uint8_t frag_id)
{
	PRINT_TEST(
	        "protocol type 0x%04x, length %zu, frag_id %d, conf %s", protocol_type, length,
	        frag_id,
	        conf.use_ptype_omission == 0 ?
	        (conf.use_compressed_ptype == 0 ?  "uncompressed" : "compressed") :
	        (conf.implicit_protocol_type == 0x00) ?  "non omitted" :
	        (conf.implicit_protocol_type == 0x30 ? "ip omitted" : "omitted"));
	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	unsigned char *theorical_alpdu_header = NULL;
	size_t theorical_alpdu_header_size = 0;
	unsigned char *alpdu = NULL;
	size_t alpdu_length;
	rle_frag_buf_t *f_buff;
	struct rle_transmitter *transmitter;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = 0,
		.protocol_type = protocol_type
	};

	transmitter = rle_transmitter_new(&conf);
	assert(transmitter != NULL);

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	/* Preparation of the SDU to encap.  */
	sdu.buffer = calloc(length, sizeof(unsigned char));
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, length);
	sdu.size = length;

	/* The function we are currently testing. */
	ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);

	/* If the function did not work well, it is useless to continue the test. */
	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("packet not encapsulated.");
		goto exit_label;
	}

	if (theorical_alpdu_header != NULL) {
		free(theorical_alpdu_header);
		theorical_alpdu_header = NULL;
	}

	/* Making of the ALPDU we theoricaly will have in the transmitter context. */
	if (!is_suppressible(protocol_type, conf.implicit_protocol_type)) {
		if (conf.use_compressed_ptype) {
			/* The protocol type is compressed */

			/* This is long and boring, but without surprise, and it is important as we want to check
			 * if the encap work without surprise. */

			unsigned char compressed_ptype = 0x00;
			theorical_alpdu_header_size = 1;
			switch (protocol_type) {
			case 0x0800:         /* IPv4        */
				theorical_alpdu_header =
				        calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				compressed_ptype = 0x0d;
				theorical_alpdu_header[0] = compressed_ptype;
				break;
			case 0x86dd:         /* IPv6        */
				theorical_alpdu_header =
				        calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				compressed_ptype = 0x11;
				theorical_alpdu_header[0] = compressed_ptype;
				break;
			case 0x8100:         /* VLAN        */
				theorical_alpdu_header =
				        calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				compressed_ptype = 0x0f;
				theorical_alpdu_header[0] = compressed_ptype;
				break;
			case 0x88a8:         /* QiNQ        */
				theorical_alpdu_header =
				        calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				compressed_ptype = 0x19;
				theorical_alpdu_header[0] = compressed_ptype;
				break;
			case 0x9100:         /* QinQ legacy */
				theorical_alpdu_header =
				        calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				compressed_ptype = 0x1a;
				theorical_alpdu_header[0] = compressed_ptype;
				break;
			case 0x0806:         /* ARP         */
				theorical_alpdu_header =
				        calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				compressed_ptype = 0x0e;
				theorical_alpdu_header[0] = compressed_ptype;
				break;
			default:
				/* Fallback */
				compressed_ptype = 0xff;
				theorical_alpdu_header_size += (size_t)2;
				theorical_alpdu_header = calloc(theorical_alpdu_header_size, sizeof(unsigned char));
				theorical_alpdu_header[0] = compressed_ptype;
				theorical_alpdu_header[1] = (unsigned char)((protocol_type & 0xff00) >> 8);
				theorical_alpdu_header[2] = (unsigned char)(protocol_type & 0x00ff);
			}
		} else {
			/* Protocol type is uncompressed */

			theorical_alpdu_header_size = (size_t)2;
			theorical_alpdu_header = calloc(theorical_alpdu_header_size, sizeof(unsigned char));
			theorical_alpdu_header[0] = (unsigned char)((protocol_type & 0xff00) >> 8);
			theorical_alpdu_header[1] = (unsigned char)(protocol_type & 0x00ff);
		}
	} else {
		/* Protocol type is omitted */

		theorical_alpdu_header_size = (size_t)0;
		theorical_alpdu_header = NULL;
	}

	f_buff = (rle_frag_buf_t *)transmitter->rle_ctx_man[frag_id].buff;
	alpdu_length = frag_buf_get_remaining_alpdu_length(f_buff);

	if (theorical_alpdu_header_size + length != alpdu_length) {
		PRINT_ERROR("dumped ALPDU has not the right length, %zu expected but we got %zu ",
		            theorical_alpdu_header_size + length,
		            alpdu_length);
		goto exit_label;
	}

	/* We check if the theorical ALPDU and the dumped ALPDU are the same. */
	alpdu = f_buff->alpdu.start;
	output =
	        check_encap(sdu.buffer, sdu.size, alpdu, alpdu_length, theorical_alpdu_header,
	                    theorical_alpdu_header_size);

	if (output == false) {
		goto exit_label;
	}

	/* It works, the dump ALPDU from the transmitter context is the theorical one. */
	output = true;

exit_label:

	print_modules_stats();

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	if (theorical_alpdu_header != NULL) {
		free(theorical_alpdu_header);
		theorical_alpdu_header = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_null_transmitter(void)
{
	PRINT_TEST("Special case : Encapsulation with a null transmitter.");
	bool output = false;
	const size_t max_size = RLE_MAX_PDU_SIZE;
	const uint16_t protocol_type = 0x0800; /* Arbitrarly */
	const uint8_t frag_id = 0; /* Arbitrarly */
	enum rle_encap_status ret = RLE_ENCAP_ERR;
	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = 0,
		.protocol_type = protocol_type
	};
	struct rle_transmitter *transmitter = NULL;

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	sdu.buffer = calloc(max_size, sizeof(unsigned char));
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, max_size);
	sdu.size = max_size;

	ret = rle_encapsulate(transmitter, &sdu, frag_id);

	if (ret != RLE_ENCAP_ERR_NULL_TRMT) {
		PRINT_ERROR("encapsulation does not return null transmitter.");
		goto exit_label;
	}

	output = true;

exit_label:

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_too_big(void)
{
	PRINT_TEST("Test the special case of too big encapsulation. ");
	bool output = false;
	const size_t max_size = RLE_MAX_PDU_SIZE;
	const uint16_t protocol_type = 0x0800; /* Arbitrarly */
	const uint8_t frag_id = 0; /* Arbitrarly */
	enum rle_encap_status ret = RLE_ENCAP_ERR;
	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = 0,
		.protocol_type = protocol_type
	};

	const struct rle_config conf = {
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_transmitter *transmitter;

	/* Good packet */

	transmitter = rle_transmitter_new(&conf);
	assert(transmitter != NULL);

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	sdu.buffer = calloc(max_size, sizeof(unsigned char));
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, max_size);
	sdu.size = max_size;

	ret = rle_encapsulate(transmitter, &sdu, frag_id);

	if (ret != RLE_ENCAP_OK) {
		PRINT_ERROR("packet of good size not encapsulated.");
		goto exit_label;
	}
	rle_transmitter_destroy(&transmitter);

	/* Too big packet */

	transmitter = rle_transmitter_new(&conf);
	assert(transmitter != NULL);

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	sdu.buffer = calloc(max_size + 1, sizeof(unsigned char));
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, max_size + 1);
	sdu.size = max_size + 1;

	ret = rle_encapsulate(transmitter, &sdu, frag_id);

	if (ret != RLE_ENCAP_ERR_SDU_TOO_BIG) {
		PRINT_ERROR("too big packet encapsulated.");
		goto exit_label;
	}

	output = true;

exit_label:

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_inv_config(void)
{
	PRINT_TEST("Special test: try to create an RLE transmitter module with an invalid conf. "
	           "Warning: An error message may be printed.");
	bool output = false;

	const struct rle_config conf = {
		.implicit_protocol_type = 0x31
	};
	struct rle_transmitter *transmitter;

	transmitter = rle_transmitter_new(&conf);

	output = (transmitter == NULL);

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_all(void)
{
	PRINT_TEST("Test the general cases of encapsulation.");
	bool output = true; /* True by default, False when a single test return False.*/
	size_t iterator = 0;
	const size_t length = 100; /* Arbitrarly */

	const uint16_t protocol_types[] = { 0x0082 /* Signal */,
		                            0x8100 /* VLAN        */,
		                            0x88a8 /* QinQ        */,
		                            0x9100 /* QinQ Legacy */,
		                            0x0800 /* IPv4        */,
		                            0x86dd /* IPv6        */,
		                            0x0806 /* ARP         */,
		                            0x1234 /* MISC        */ };

	/* The tests will be launch on each protocol_type. */
	for (iterator = 0; iterator != (sizeof(protocol_types) / sizeof(uint16_t)); ++iterator) {
		const uint8_t max_frag_id = 7;
		uint8_t frag_id = 0;

		uint8_t default_ptype = 0x00;
		switch (protocol_types[iterator]) {
		case 0x0082:
			default_ptype = 0x42;
			break;
		case 0x8100:
			default_ptype = 0x0f;
			break;
		case 0x88a8:
			default_ptype = 0x19;
			break;
		case 0x9100:
			default_ptype = 0x1a;
			break;
		case 0x0800:
			default_ptype = 0x0d;
			break;
		case 0x86dd:
			default_ptype = 0x11;
			break;
		case 0x0806:
			default_ptype = 0x0e;
			break;
		default:
			default_ptype = 0x00;
			break;
		}

		/* The test will be launch on each fragment id. */
		for (frag_id = 0; frag_id < max_frag_id; ++frag_id) {
			/* Configuration for uncompressed protocol type */
			struct rle_config conf_uncomp = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 0
			};

			/* Configuration for compressed protocol type */
			struct rle_config conf_comp = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 1,
				.use_ptype_omission = 0
			};

			/* Configuration for omitted protocol type */
			struct rle_config conf_omitted = {
				.implicit_protocol_type = default_ptype,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Special test for IPv4 and v6*/
			struct rle_config conf_omitted_ip = {
				.implicit_protocol_type = 0x30,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Configuration for non omitted protocol type in omission conf */
			struct rle_config conf_not_omitted = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Configurations */
			struct rle_config *confs[] = {
				&conf_uncomp,
				&conf_comp,
				&conf_omitted,
				&conf_omitted_ip,
				&conf_not_omitted,
				NULL
			};

			/* Configuration iterator */
			struct rle_config **conf;

			/* We launch the test on each configuration. All the cases then are test. */
			for (conf = confs; *conf; ++conf) {
				const bool ret =
				        test_encap(protocol_types[iterator], **conf, length,
				                   frag_id);
				if (ret == false) {
					/* Only one fail means the encap test fail. */
					output = false;
				}
			}
		}
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

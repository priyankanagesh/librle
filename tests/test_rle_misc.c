/**
 * @file   test_rle_misc.c
 * @brief  Body file used for the miscellaneous tests.
 * @author Henrick Deschamps
 * @date   07/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_misc.h"

#include "rle.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>

/** Test configuration structure */
struct test_request {
	const enum rle_fpdu_types fpdu_type;
	const size_t expected_size;
	const struct rle_context_configuration *const conf;
};

/**
 * @brief         RLE FPDU type to string
 *
 * @param[in]     fpdu_type     The type of the FPDU.
 *
 * @return        A printable string
 */
static char * get_fpdu_type(const enum rle_fpdu_types fpdu_type);

/**
 * @brief         RLE headers overhead test.
 *
 *                Requests an RLE headers overhead and compares it to the expected size.
 *
 * @param[in]     fpdu_type     The type of the FPDU.
 * @param[in]     expected_size The expected size to be returned by the request.
 * @param[in]     conf          The rle module configuration. Only needed for traffic-control
 *                              fpdus, otherwise could be set to "NULL".
 *
 * @return        true if OK, else false.
 */
static bool test_request_rle_header_overhead(
      const enum rle_fpdu_types fpdu_type,
      const size_t expected_size,
      const struct rle_context_configuration *const conf);

static char * get_fpdu_type(const enum rle_fpdu_types fpdu_type)
{
	switch (fpdu_type)
	{
		case RLE_LOGON_FPDU:
			return "Logon";
		case RLE_CTRL_FPDU:
			return "Control";
		case RLE_TRAFFIC_FPDU:
			return "Traffic";
		case RLE_TRAFFIC_CTRL_FPDU:
			return "Traffic control";
		default:
			return "Unknown";
	}
}

static bool test_request_rle_header_overhead(
      const enum rle_fpdu_types fpdu_type,
      const size_t expected_size,
      const struct rle_context_configuration *const conf)
{
	PRINT_TEST("subtest. FPDU type : %s, expected size : %zu\n", get_fpdu_type(fpdu_type),
	           expected_size);
	bool output = false;

	size_t overhead_size = 0;
	enum rle_header_size_status header_size_status = RLE_HEADER_SIZE_ERR;

	header_size_status = rle_get_header_size(conf, fpdu_type, &overhead_size);

	if (header_size_status == RLE_HEADER_SIZE_OK)
	{
		if (overhead_size == expected_size)
		{
			output = true;
		}
	}

	PRINT_TEST_STATUS(output);
	return output;
}

bool test_request_rle_header_overhead_traffic(void)
{
	PRINT_TEST("Request RLE header overhead traffic error.\n");
	bool output = false;

	size_t overhead_size = 0;
	enum rle_header_size_status header_size_status = RLE_HEADER_SIZE_ERR;
	const struct rle_context_configuration *const conf = NULL;

	header_size_status = rle_get_header_size(conf, RLE_TRAFFIC_FPDU, &overhead_size);

	if (header_size_status == RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC)
	{
			output = true;
	}

	PRINT_TEST_STATUS(output);
	return output;
}

bool test_request_rle_header_overhead_all(void)
{
	PRINT_TEST("Request RLE header overhead all.\n");
	bool output = true;

	/* Logon */
	const struct test_request test_logon = {
		.fpdu_type = RLE_LOGON_FPDU,
		.expected_size = 6,
		.conf = NULL,
	};

	/* Control */
	const struct test_request test_control = {
		.fpdu_type = RLE_CTRL_FPDU,
		.expected_size = 3,
		.conf = NULL,
	};

	/* Traffic-control */
	/* No conf => expected_size = Max of the traffic control expected size below. */
	const struct test_request test_tc_no_conf = {
		.fpdu_type = RLE_TRAFFIC_CTRL_FPDU,
		.expected_size = 5,
		.conf = NULL,
	};

	/* Traffic-Control */
	/* Conf omitted */
	const struct rle_context_configuration conf_omitted = {
		.implicit_protocol_type = 0x34,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 1,
		.use_compressed_ptype = 0,
	};
	const struct test_request test_tc_omitted = {
		.fpdu_type = RLE_TRAFFIC_CTRL_FPDU,
		.expected_size = 5,
		.conf = &conf_omitted,
	};

	/* Traffic-Control */
	/* Conf non-omitted, compressed. */
	const struct rle_context_configuration conf_non_omitted_comp = {
		.implicit_protocol_type = 0x34,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 1,
	};
	const struct test_request test_tc_non_omitted_comp = {
		.fpdu_type = RLE_TRAFFIC_CTRL_FPDU,
		.expected_size = 5,
		.conf = &conf_non_omitted_comp,
	};

	/* Traffic-Control */
	/* Conf non-omitted, uncompressed. */
	const struct rle_context_configuration conf_non_omitted_non_comp = {
		.implicit_protocol_type = 0x34,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};
	const struct test_request test_tc_non_omitted_non_comp = {
		.fpdu_type = RLE_TRAFFIC_CTRL_FPDU,
		.expected_size = 5,
		.conf = &conf_non_omitted_non_comp,
	};

	/* Request tests */
	const struct test_request *const test_requests[] = {
		&test_logon,
		&test_control,
		&test_tc_no_conf,
		&test_tc_omitted,
		&test_tc_non_omitted_comp,
		&test_tc_non_omitted_non_comp,
		NULL,
	};

	const struct test_request *const *test_request;

	for (test_request = test_requests; *test_request; ++test_request)
	{
		output &= test_request_rle_header_overhead((**test_request).fpdu_type,
		                                           (**test_request).expected_size,
		                                           (**test_request).conf);
	}

	PRINT_TEST_STATUS(output);
	return output;
}

bool test_rle_allocation_transmitter(void)
{
	bool output = false;
	const struct rle_context_configuration bad_conf = {
		.implicit_protocol_type = 0x31,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};
	const struct rle_context_configuration good_conf = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};

	struct rle_transmitter *t = NULL;

	PRINT_TEST("RLE transmitter allocation.\n");

	t = rle_transmitter_new(&bad_conf);

	if (t) {
		PRINT_ERROR("Transmitter should not be allocated with %02x protocol type.",
		            bad_conf.implicit_protocol_type);
		goto out;
	}

	t = rle_transmitter_new(&good_conf);

	if (!t) {
		PRINT_ERROR("Transmitter should be allocated.");
		goto out;
	}

	output = true;

out:

	rle_transmitter_destroy(&t);

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

bool test_rle_destruction_transmitter(void)
{
	bool output = false;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};

	PRINT_TEST("RLE transmitter destruction.\n");

	struct rle_transmitter *t = NULL;

	/* Should print error, but no segfault. */
	rle_transmitter_destroy(NULL);

	/* Should print error, but no segfault. */
	rle_transmitter_destroy(&t);

	t = rle_transmitter_new(&conf);

	if (!t) {
		PRINT_ERROR("Transmitter should be allocated. Can't test destruction.");
		goto out;
	}

	rle_transmitter_destroy(&t);

	if (t) {
		PRINT_ERROR("Transmitter should not be freed.");
		goto out;
	}

	output = true;

out:

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

bool test_rle_allocation_receiver(void)
{
	bool output = false;
	const struct rle_context_configuration bad_conf = {
		.implicit_protocol_type = 0x31,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};
	const struct rle_context_configuration good_conf = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};

	struct rle_receiver *r = NULL;

	PRINT_TEST("RLE receiver allocation.\n");

	r = rle_receiver_new(&bad_conf);

	if (r) {
		PRINT_ERROR("Receiver should not be allocated with %02x protocol type.",
						bad_conf.implicit_protocol_type);
		goto out;
	}

	r = rle_receiver_new(&good_conf);

	if (!r) {
		PRINT_ERROR("Receiver should be allocated.");
		goto out;
	}

	output = true;

out:
	rle_receiver_destroy(&r);

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

bool test_rle_destruction_receiver(void)
{
	bool output = false;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};

	struct rle_receiver *r = NULL;

	PRINT_TEST("RLE receiver destruction.\n");

	/* Should print error, but no segfault. */
	rle_receiver_destroy(NULL);

	/* Should print error, but no segfault. */
	rle_receiver_destroy(&r);

	r = rle_receiver_new(&conf);

	if (!r) {
		PRINT_ERROR("Receiver should be allocated. Can't test destruction.");
		goto out;
	}

	rle_receiver_destroy(&r);

	if (r) {
		PRINT_ERROR("Receiver should not be freed.");
		goto out;
	}

	output = true;

out:

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

bool test_rle_allocation_f_buff(void)
{
	bool output = false;

	struct rle_fragmentation_buffer *f = NULL;

	PRINT_TEST("RLE fragmentation buffer allocation.\n");

	f = rle_f_buff_new();

	if (!f) {
		PRINT_ERROR("Fragmentation buffer should be allocated.");
		goto out;
	}

	output = true;

out:
	rle_f_buff_del(&f);

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

bool test_rle_destruction_f_buff(void)
{
	bool output = false;

	struct rle_fragmentation_buffer *f = NULL;

	PRINT_TEST("RLE fragmentation buffer destruction.\n");

	/* Should print error, but no segfault. */
	rle_f_buff_del(NULL);

	/* Should print error, but no segfault. */
	rle_f_buff_del(&f);

	f = rle_f_buff_new();

	if (!f) {
		PRINT_ERROR("Fragmentation buffer should be allocated. Can't test destruction.");
		goto out;
	}

	rle_f_buff_del(&f);

	if (f) {
		PRINT_ERROR("Fragmentation buffer should not be freed.");
		goto out;
	}

	output = true;

out:

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

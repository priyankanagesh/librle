/**
 * @file   test_rle_misc.c
 * @brief  Body file used for the miscellaneous tests.
 * @author Henrick Deschamps
 * @date   07/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "test_rle_misc.h"

#include "rle.h"

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
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean test_request_rle_header_overhead(
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

static enum boolean test_request_rle_header_overhead(
      const enum rle_fpdu_types fpdu_type,
      const size_t expected_size,
      const struct rle_context_configuration *const conf)
{
	PRINT_TEST("subtest. FPDU type : %s, expected size : %zu\n", get_fpdu_type(fpdu_type),
	           expected_size);
	enum boolean output = BOOL_FALSE;

	size_t overhead_size = 0;
	enum rle_header_size_status header_size_status = RLE_HEADER_SIZE_ERR;

	header_size_status = rle_get_header_size(conf, fpdu_type, &overhead_size);

	if (header_size_status == RLE_HEADER_SIZE_OK)
	{
		if (overhead_size == expected_size)
		{
			output = BOOL_TRUE;
		}
	}

	PRINT_TEST_STATUS(output);
	return output;
}

enum boolean test_request_rle_header_overhead_traffic(void)
{
	PRINT_TEST("Request RLE header overhead traffic error.\n");
	enum boolean output = BOOL_FALSE;

	size_t overhead_size = 0;
	enum rle_header_size_status header_size_status = RLE_HEADER_SIZE_ERR;
	const struct rle_context_configuration *const conf = NULL;

	header_size_status = rle_get_header_size(conf, RLE_TRAFFIC_FPDU, &overhead_size);

	if (header_size_status == RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC)
	{
			output = BOOL_TRUE;
	}

	PRINT_TEST_STATUS(output);
	return output;
}

enum boolean test_request_rle_header_overhead_all(void)
{
	PRINT_TEST("Request RLE header overhead all.\n");
	enum boolean output = BOOL_TRUE;

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

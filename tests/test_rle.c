/**
 * @file   test_rle.c
 * @brief  Body file used for the libRLE test.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "test_rle.h"

#include "rle_transmitter.h"

static enum boolean tests(const char *const test_name, const struct test *const current_tests[])
{
	printf("\tTest %s\n\n", test_name);

	/* Success is True by default. False if a single test fail. */
	enum boolean test_success = BOOL_TRUE;

	/* Iterator */
	const struct test *const *current_test;

	size_t number_of_tests = 0;
	size_t number_of_succ_tests = 0;

	for (current_test = current_tests; *current_test; ++current_test) {
		enum boolean success = BOOL_FALSE;
		printf("Test %s\n", (**current_test).name);
		success = (**current_test).function();
		number_of_tests++;
		if (success) {
			number_of_succ_tests++;
		}
		test_success &= success;
	}

	total_number_of_tests += number_of_tests;
	total_number_of_succ_tests += number_of_succ_tests;

	printf("%s tests %s. %zu/%zu.\n\n", test_name, test_success == BOOL_TRUE ? "OK" : "KO",
	       number_of_succ_tests,
	       number_of_tests);

	return test_success;
}

static enum boolean encap_tests(void)
{
	const char *const encapsulation = "Encapsulation";

	const struct test all = { "All", test_encap_all };
	const struct test null_transmitter = { "Null transmitter", test_encap_null_transmitter };
	const struct test too_big = { "Too big", test_encap_too_big };
	const struct test inv_config = { "Invalid configuration", test_encap_inv_config };

	const struct test *const encapsulation_tests[] =
	{
		&all,
		&null_transmitter,
		&too_big,
		&inv_config,
		NULL
	};

	return tests(encapsulation, encapsulation_tests);
}

static enum boolean frag_tests(void)
{
	const char *const fragmentation = "Fragmentation";

	const struct test all = { "All", test_frag_all };
	const struct test null_transmitter = { "Null transmitter", test_frag_null_transmitter };
	const struct test too_small = { "Too small", test_frag_too_small };
	const struct test null_context = { "Null context", test_frag_null_context };
	const struct test invalid_size = { "Invalid size", test_frag_invalid_size };
	const struct test real_world = { "Real-world", test_frag_real_world };

	const struct test *const fragmentation_tests[] =
	{
		&all,
		&null_transmitter,
		&too_small,
		&null_context,
		&invalid_size,
		&real_world,
		NULL
	};

	return tests(fragmentation, fragmentation_tests);
}

static enum boolean pack_tests(void)
{
	const char *const packing = "Packing";

	const struct test all = { "All", test_pack_all };
	const struct test fpdu_too_small = { "FPDU too small", test_pack_fpdu_too_small };
	const struct test invalid_ppdu = { "Invalid PPDU", test_pack_invalid_ppdu };
	const struct test invalid_label = { "Invalid label", test_pack_invalid_label };

	const struct test *const packing_tests[] =
	{
		&all,
		&fpdu_too_small,
		&invalid_ppdu,
		&invalid_label,
		NULL
	};

	return tests(packing, packing_tests);
}

static enum boolean decap_tests(void)
{
	const char *const decapsulation = "Decapsulation";

	const struct test all = { "All", test_decap_all };
	const struct test null_receiver = { "Null receiver", test_decap_null_receiver };
	const struct test inv_fpdu = { "Invalid FPDU buffer", test_decap_inv_fpdu };
	const struct test inv_sdus = { "Invalid SDUs buffer", test_decap_inv_sdus };
	const struct test inv_pl = { "Invalid payload label buffer", test_decap_inv_pl };
	const struct test inv_config = { "Invalid receiver configuration", test_decap_inv_config };
	const struct test inv_padding = { "Invalid padding", test_decap_not_null_padding };

	const struct test *const decapsulation_tests[] =
	{
		&all,
		&null_receiver,
		&inv_fpdu,
		&inv_sdus,
		&inv_pl,
		&inv_config,
		&inv_padding,
		NULL
	};

	return tests(decapsulation, decapsulation_tests);
}

int main(void)
{
	PRINT_TEST("Lib RLE tests.\n");

	/* Success is True by default. False if a single test fail. */
	enum boolean tests_success = BOOL_TRUE;

	total_number_of_tests = 0;
	total_number_of_succ_tests = 0;

	/*---------------------*/
	/*--  Encapsulation  --*/
	/*---------------------*/

	tests_success &= encap_tests();

	/*---------------------*/
	/*--  Fragmentation  --*/
	/*---------------------*/

	tests_success &= frag_tests();

	/*---------------*/
	/*--  Packing  --*/
	/*---------------*/

	tests_success &= pack_tests();

	/*---------------------*/
	/*--  Decapsulation  --*/
	/*---------------------*/

	tests_success &= decap_tests();

	printf("Tests %s. %zu/%zu\n\n", tests_success == BOOL_TRUE ? "OK" : "KO",
	       total_number_of_succ_tests,
	       total_number_of_tests);
	return tests_success == BOOL_TRUE ? EXIT_SUCCESS : EXIT_FAILURE;
}
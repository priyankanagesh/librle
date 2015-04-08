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

static enum boolean tests(const char *const test_name, const char *const function_names[],
                          enum boolean(
                                  *const test_functions[]) (void))
{
	printf("\tTest %s\n\n", test_name);

	/* Success is True by default. False if a single test fail. */
	enum boolean test_success = BOOL_TRUE;

	/* Iterators */
	const char *const *function_name;
	enum boolean(*const *test_function) (void);

	size_t number_of_tests = 0;
	size_t number_of_succ_tests = 0;

	for (function_name = function_names, test_function = test_functions;
	     (*function_name) && (*test_function);
	     ++function_name, ++test_function) {
		enum boolean success = BOOL_FALSE;
		printf("Test %s\n", *function_name);
		success = (**test_function)();
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
	/** Array of encapsulation functions names */
	const char *const encap_functions_names[] = {
		"All",
		"Null transmitter",
		"Too big",
		NULL
	};

	/** Array of encapsulation test functions */
	enum boolean(*const encap_functions[]) (void) = {
		test_encap_all,
		test_encap_null_transmitter,
		test_encap_too_big,
		NULL
	};

	return tests(encapsulation, encap_functions_names, encap_functions);
}

static enum boolean frag_tests(void)
{
	const char *const fragmentation = "Fragmentation";
	/** Array of fragmentation functions names */
	const char *const frag_functions_names[] = {
		"All",
		"Null transmitter",
		"Too small",
		"Null context",
		"Invalid size",
		NULL
	};

	/** Array of fragmentation test functions */
	enum boolean(*const frag_functions[]) (void) = {
		test_frag_all,
		test_frag_null_transmitter,
		test_frag_too_small,
		test_frag_null_context,
		test_frag_invalid_size,
		NULL
	};

	return tests(fragmentation, frag_functions_names, frag_functions);
}

static enum boolean pack_tests(void)
{
	const char *const packing = "Packing";
	/** Array of packing functions names */
	const char *const pack_functions_names[] = {
		"All",
		"FPDU too small",
		"Invalid PPDU",
		"Invalid label",
		NULL
	};

	/** Array of packing test functions */
	enum boolean(*const pack_functions[]) (void) = {
		test_pack_all,
		test_pack_fpdu_too_small,
		test_pack_invalid_ppdu,
		test_pack_invalid_label,
		NULL
	};

	return tests(packing, pack_functions_names, pack_functions);
}

static enum boolean unpack_tests(void)
{
	const char *const unpacking = "Unpacking";
	/** Array of unpacking functions names */
	const char *const unpack_functions_names[] = {
		NULL
	};

	/** Array of unpacking test functions */
	enum boolean(*const unpack_functions[]) (void) = {
		NULL
	};

	return tests(unpacking, unpack_functions_names, unpack_functions);
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

	/*-----------------*/
	/*--  Unpacking  --*/
	/*-----------------*/

	tests_success &= unpack_tests();

	printf("Tests %s. %zu/%zu\n\n", tests_success == BOOL_TRUE ? "OK" : "KO",
	       total_number_of_succ_tests,
	       total_number_of_tests);
	return tests_success == BOOL_TRUE ? EXIT_SUCCESS : EXIT_FAILURE;
}

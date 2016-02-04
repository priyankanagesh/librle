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

static enum boolean encap_ctxtless_tests(void)
{
	const char *const encapsulation_contextless = "Encapsulation contextless";

	const struct test null_transmitter = { "Null transmitter",
	                                       test_encap_ctxtless_null_transmitter };
	const struct test null_f_buff = { "Null fragmentation buffer",
	                                  test_encap_ctxtless_null_f_buff };
	const struct test f_buff_not_init = { "fragmentation buffer not initialized",
	                                      test_encap_ctxtless_f_buff_not_init };
	const struct test too_big = { "Too big", test_encap_ctxtless_too_big };

	const struct test *const encapsulation_contextless_tests[] =
	{
		&null_transmitter,
		&null_f_buff,
		&f_buff_not_init,
		&too_big,
		NULL
	};

	return tests(encapsulation_contextless, encapsulation_contextless_tests);
}

static enum boolean frag_tests(void)
{
	const char *const fragmentation = "Fragmentation";

	const struct test all = { "All", test_frag_all };
	const struct test null_transmitter = { "Null transmitter", test_frag_null_transmitter };
	const struct test too_small = { "Too small", test_frag_too_small };
	const struct test null_context = { "Null context", test_frag_null_context };
	const struct test real_world = { "Real-world", test_frag_real_world };

	const struct test *const fragmentation_tests[] =
	{
		&all,
		&null_transmitter,
		&too_small,
		&null_context,
		&real_world,
		NULL
	};

	return tests(fragmentation, fragmentation_tests);
}

static enum boolean frag_ctxtless_tests(void)
{
	const char *const fragmentation_ctxtless = "Fragmentation contextless";

	const struct test null_transmitter = { "Null transmitter",
	                                       test_frag_ctxtless_null_transmitter };
	const struct test null_f_buff = { "NULL fragmentation buffer", test_frag_ctxtless_null_f_buff };
	const struct test f_buff_not_init = { "Fragmentation buffer not initialized",
	                                      test_frag_ctxtless_f_buff_not_init };
	const struct test no_len = { "Fragmentation without length", test_frag_ctxtless_no_len };
	const struct test too_small = { "Fragmentation with length too small",
	                                test_frag_ctxtless_too_small };
	const struct test too_big = { "Fragmentation with length too big", test_frag_ctxtless_too_big };

	const struct test *const fragmentation_ctxtless_tests[] =
	{
		&null_transmitter,
		&null_f_buff,
		&f_buff_not_init,
		&no_len,
		&too_small,
		&too_big,
		NULL
	};

	return tests(fragmentation_ctxtless, fragmentation_ctxtless_tests);
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
	const struct test ctxt_flush = { "Context Flushing", test_decap_flush_ctxt };
	const struct test null_seqno = { "Null sequence number", test_decap_null_seqno };
	const struct test context_free = { "Context freeing index", test_decap_context_free };

	const struct test *const decapsulation_tests[] =
	{
		&all,
		&null_receiver,
		&inv_fpdu,
		&inv_sdus,
		&inv_pl,
		&inv_config,
		&inv_padding,
		&ctxt_flush,
		&null_seqno,
		&context_free,
		NULL
	};

	return tests(decapsulation, decapsulation_tests);
}

static enum boolean misc_tests(void)
{
	const char *const miscellaneous = "Miscellaneous";

	const struct test request_overhead_all = { "Request overhead All",
	                                           test_request_rle_header_overhead_all };
	const struct test request_overhead_traffic = { "Request overhead Traffic",
	                                               test_request_rle_header_overhead_traffic };
	const struct test allocation_transmitter = { "Transmitter allocation",
	                                             test_rle_allocation_transmitter };
	const struct test destruction_transmitter = { "Transmitter destruction",
	                                              test_rle_destruction_transmitter };
	const struct test allocation_receiver = { "Receiver allocation",
	                                          test_rle_allocation_receiver };
	const struct test destruction_receiver = { "Receiver destruction",
	                                           test_rle_destruction_receiver };
	const struct test allocation_f_buff = { "Fragmentation buffer allocation",
	                                        test_rle_allocation_f_buff };
	const struct test destruction_f_buff = { "Fragmentation buffer destruction",
	                                         test_rle_destruction_f_buff };

	const struct test *const miscellaneous_tests[] =
	{
		&request_overhead_all,
		&request_overhead_traffic,
		&allocation_transmitter,
		&destruction_transmitter,
		&allocation_receiver,
		&destruction_receiver,
		&allocation_f_buff,
		&destruction_f_buff,
		NULL
	};

	return tests(miscellaneous, miscellaneous_tests);
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

	/*----------------------------------*/
	/*--  Encapsulation  contextless  --*/
	/*----------------------------------*/

	tests_success &= encap_ctxtless_tests();

	/*---------------------*/
	/*--  Fragmentation  --*/
	/*---------------------*/

	tests_success &= frag_tests();

	/*----------------------------------*/
	/*--  Fragmentation  contextless  --*/
	/*----------------------------------*/

	tests_success &= frag_ctxtless_tests();

	/*---------------*/
	/*--  Packing  --*/
	/*---------------*/

	tests_success &= pack_tests();

	/*---------------------*/
	/*--  Decapsulation  --*/
	/*---------------------*/

	tests_success &= decap_tests();

	/*---------------------*/
	/*--  Miscellaneous  --*/
	/*---------------------*/

	tests_success &= misc_tests();

	printf("Tests %s. %zu/%zu\n\n", tests_success == BOOL_TRUE ? "OK" : "KO",
	       total_number_of_succ_tests,
	       total_number_of_tests);
	return tests_success == BOOL_TRUE ? EXIT_SUCCESS : EXIT_FAILURE;
}

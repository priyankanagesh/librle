/**
 * @file   test_rle.h
 * @brief  Definition of variables and functions used for the libRLE test.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_H__
#define __TEST_RLE_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "rle.h"
#include "test_rle_common.h"
#include "test_rle_encap.h"
#include "test_rle_frag.h"
#include "test_rle_pack.h"
#include "test_rle_decap.h"

/** Test counters */
static size_t total_number_of_tests;      /**< Counter for the total number of tests.            */
static size_t total_number_of_succ_tests; /**< Counter for the total number of successful tests. */

/**
 * @brief         Generic test function
 *
 *                Launch a list of test.
 *
 * @param[in]     test_name                The name of the test
 * @param[in]     function_names           The names of the test functions
 * @param[in]     test_functions           The test functions
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean tests(const char *const test_name, const char *const function_names[],
                          enum boolean(
                                  *const test_functions[]) (void));

/**
 * @brief         Specific test function for encapsulation
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean encap_tests(void);

/**
 * @brief         Specific test function for fragmentation
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean frag_tests(void);

/**
 * @brief         Specific test function for packing
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean pack_tests(void);

/**
 * @brief         Specific test function for unpacking
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean unpack_tests(void);

#endif /* __TEST_RLE_H__ */

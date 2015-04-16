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

/*
 * How to add a Test:
 *
 * Step 1: Write a public function in one of the four test functions source files (encap, decap...)
 * Step 2: Write the name of the test and its symbole in a struct in the corresponding tests
 *         functions in the body source of this file.
 * Step 3: Append a pointer to this struct in the same function.
 * Step 4: Compile and execute.
 *
 */

/** Test structure, used to launch tests. */
struct test {
	const char *const name;                /**< The name of the test.    */
	enum boolean(*const function) (void);  /**< The function to execute. */
};

/** Test counters */
static size_t total_number_of_tests;      /**< Counter for the total number of tests.            */
static size_t total_number_of_succ_tests; /**< Counter for the total number of successful tests. */

/**
 * @brief         Generic test function
 *
 *                Launch a list of test.
 *
 * @param[in]     test_name                The name of the test
 * @param[in]     current_tests            The current tests to execute @see struct test
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean tests(const char *const test_name, const struct test *const current_tests[]);

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
 * @brief         Specific test function for decapsulation
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean decap_tests(void);

#endif /* __TEST_RLE_H__ */

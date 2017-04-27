/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

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
#include "test_rle_encap_ctxtless.h"
#include "test_rle_frag_ctxtless.h"
#include "test_rle_frag.h"
#include "test_rle_pack.h"
#include "test_rle_decap.h"
#include "test_rle_misc.h"
#include "test_rle_api_robustness.h"

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
	bool(*const function) (void);  /**< The function to execute. */
};

/**
 * @brief         Generic test function
 *
 *                Launch a list of test.
 *
 * @param[in]     test_name                The name of the test
 * @param[in]     current_tests            The current tests to execute @see struct test
 *
 * @return        true if OK, else false.
 */
static bool tests(const char *const test_name, const struct test *const current_tests[]);

/**
 * @brief         Specific test function for encapsulation
 *
 * @return        true if OK, else false.
 */
static bool encap_tests(void);

/**
 * @brief         Specific test function for encapsulation contextless.
 *
 * @return        true if OK, else false.
 */
static bool encap_ctxtless_tests(void);

/**
 * @brief         Specific test function for fragmentation
 *
 * @return        true if OK, else false.
 */
static bool frag_tests(void);


/**
 * @brief         Specific test function for fragmentation contextless.
 *
 * @return        true if OK, else false.
 */
static bool frag_ctxtless_tests(void);

/**
 * @brief         Specific test function for packing
 *
 * @return        true if OK, else false.
 */
static bool pack_tests(void);

/**
 * @brief         Specific test function for decapsulation
 *
 * @return        true if OK, else false.
 */
static bool decap_tests(void);

#endif /* __TEST_RLE_H__ */

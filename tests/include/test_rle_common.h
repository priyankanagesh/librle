/**
 * @file   test_rle_common.h
 * @brief  Definition of RLE structure, functions and variables shared by the tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_COMMON_H__
#define __TEST_RLE_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "rle.h"

#define PRINT_TEST(S, ...) printf("TEST %s:l.%d "S "\n", __func__, __LINE__, ## __VA_ARGS__)
#define PRINT_TEST_STATUS(status) printf("RET %s:l.%d: %s\n", __func__, __LINE__, status == \
                                         BOOL_TRUE ? "OK" : "KO")
#define PRINT_ERROR(S, ...) printf("ERROR %s:l.%d: "S "\n", __func__, __LINE__, ## __VA_ARGS__)

/** Boolean values, in order to perform cleaner tests. */
enum boolean {
	BOOL_FALSE, /**< Boolean representation of False. */
	BOOL_TRUE   /**< Boolean representation of True.  */
};

/**
 * Payload initializer,
 * This initializer is big enough to test too big SDU/ALPDU cases.
 * How to use :
 * For a n octets sdu: memcpy((void *)sdu, (const void *)payload_initializer, (size_t)n).
 *
 * Sufficient for encap, frag and pack, but IP header checking in decap might need to modify some
 * of the first octets.
 */
const unsigned char payload_initializer[5000];

/*--  Modules  --*/

struct rle_transmitter *transmitter; /**< Transmitter module used by our tests */
struct rle_receiver *receiver;       /**< Receiver module used by our tests */

/*--  Common  --*/

/**
 * @brief         Specific statistics printer for transmitter
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
void print_transmitter_stats(void);

/**
 * @brief         Specific statistics printer for receiver
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
void print_receiver_stats(void);

#endif /* __TEST_RLE_COMMON_H__ */

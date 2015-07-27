/**
 * @file   test_rle_misc.h
 * @brief  Definition of public functions used for the miscellaneous tests.
 * @author Henrick Deschamps
 * @date   07/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_MISC_H__
#define __TEST_RLE_MISC_H__

#include "test_rle_common.h"

/**
 * @brief         Requests RLE headers overhead for traffic.
 *
 *                RLE headers overhead for traffic is non deterministic, and must return an error.
 *
 * @return        BOOL_TRUE if RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC returned by the request.
 */
enum boolean test_request_rle_header_overhead_traffic(void);

/**
 * @brief         All the RLE headers overhead tests
 *
 *                Request RLE headers overhead for logon, control, and traffic control.
 *                Traffic control requests will be done with different configurations.
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
enum boolean test_request_rle_header_overhead_all(void);

#endif /* __TEST_RLE_MISC_H__ */

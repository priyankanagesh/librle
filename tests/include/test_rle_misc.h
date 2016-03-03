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
 * @return        true if RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC returned by the request.
 */
bool test_request_rle_header_overhead_traffic(void);

/**
 * @brief         All the RLE headers overhead tests
 *
 *                Request RLE headers overhead for logon, control, and traffic control.
 *                Traffic control requests will be done with different configurations.
 *
 * @return        true if OK, else false.
 */
bool test_request_rle_header_overhead_all(void);

/**
 * @brief         Test the transmitter allocation
 *
 *                Deactivate all the tests but this ones to check memory allocation.
 *
 * @return        true if OK, else false.
 */
bool test_rle_allocation_transmitter(void);

/**
 * @brief         Test the transmitter allocation
 *
 * @return        true if OK, else false.
 */
bool test_rle_destruction_transmitter(void);

/**
 * @brief         Test the receiver allocation
 *
 *                Deactivate all the tests but this ones to check memory allocation.
 *
 * @return        true if OK, else false.
 */
bool test_rle_allocation_receiver(void);

/**
 * @brief         Test the receiver allocation
 *
 *                Deactivate all the tests but this ones to check memory allocation.
 *
 * @return        true if OK, else false.
 */
bool test_rle_destruction_receiver(void);

/**
 * @brief         Test the fragmentation buffer allocation
 *
 *                Deactivate all the tests but this ones to check memory allocation.
 *
 * @return        true if OK, else false.
 */
bool test_rle_allocation_f_buff(void);

/**
 * @brief         Test the fragmentation buffer allocation
 *
 *                Deactivate all the tests but this ones to check memory allocation.
 *
 * @return        true if OK, else false.
 */
bool test_rle_destruction_f_buff(void);

/* Further tests can be done here, especially to check fragmentation and reassembly buffers. */


#endif /* __TEST_RLE_MISC_H__ */

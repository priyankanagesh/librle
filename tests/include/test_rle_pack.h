/**
 * @file   test_rle_pack.h
 * @brief  Definition of public functions used for the packing tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_PACK_H__
#define __TEST_RLE_PACK_H__

#include "test_rle_common.h"

/**
 * @brief         Packing test when FPDU is too small.
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
enum boolean test_pack_fpdu_too_small(void);

/**
 * @brief         Packing test when PPDU is invalid.
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
enum boolean test_pack_invalid_ppdu(void);

/**
 * @brief         Packing test when label is invalid.
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
enum boolean test_pack_invalid_label(void);

/**
 * @brief         Packing test in general cases.
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
enum boolean test_pack_all(void);

#endif /* __TEST_RLE_PACK_H__ */

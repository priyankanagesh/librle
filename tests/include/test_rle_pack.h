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
 * @return        true if OK, else false.
 */
bool test_pack_fpdu_too_small(void);

/**
 * @brief         Packing test when PPDU is invalid.
 *
 * @return        true if OK, else false.
 */
bool test_pack_invalid_ppdu(void);

/**
 * @brief         Packing test when label is invalid.
 *
 * @return        true if OK, else false.
 */
bool test_pack_invalid_label(void);

/**
 * @brief         Packing test in general cases.
 *
 * @return        true if OK, else false.
 */
bool test_pack_all(void);

#endif /* __TEST_RLE_PACK_H__ */

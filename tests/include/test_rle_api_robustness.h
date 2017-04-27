/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file   test_rle_api_robustness.h
 * @brief  Run robustness tests on the RLE public API
 * @author Didier Barvaux
 * @date   03/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_API_ROBUSTNESS_H__
#define __TEST_RLE_API_ROBUSTNESS_H__

#include "test_rle_common.h"

bool test_rle_api_robustness_transmitter(void);

bool test_rle_api_robustness_receiver(void);

#endif /* __TEST_RLE_MISC_H__ */

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
 * @file   test_rle_frag_ctxtless.h
 * @brief  Definition of public functions used for the fragmentation without context tests.
 * @author Henrick Deschamps
 * @date   02/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_FRAG_CTXTLESS_H__
#define __TEST_RLE_FRAG_CTXTLESS_H__

#include "test_rle_common.h"

/**
 * @brief         Fragmentation test with a null transmitter.
 *
 * @return        true if the RLE_FRAG_ERR_BURST_TOO_SMALL is raised, else false.
 */
bool test_frag_ctxtless_null_transmitter(void);

/**
 * @brief         Fragmentation test with a null fragmentation buffer.
 *
 * @return        true if the RLE_FRAG_ERR_NULL_F_BUFF is raised, else false.
 */
bool test_frag_ctxtless_null_f_buff(void);


/**
 * @brief         Fragmentation test with a fragmentation buffer not initialized.
 *
 * @return        true if the RLE_FRAG_ERR_N_INIT_F_BUFF is raised, else false.
 */
bool test_frag_ctxtless_f_buff_not_init(void);

/**
 * @brief         Fragmentation test with NULL PPDU buffer
 *
 * @return        true if error is reported, else false.
 */
bool test_frag_ctxtless_null_ppdu(void);

/**
 * @brief         Fragmentation test without length given as input.
 *
 *                Must not segfault.
 *
 * @return        true if exception is raised, else false.
 */
bool test_frag_ctxtless_no_len(void);

/**
 * @brief         Fragmentation test with a too small burst size.
 *
 * @return        true if the RLE_FRAG_ERR_BURST_TOO_SMALL is raised, else false.
 */
bool test_frag_ctxtless_too_small(void);

/**
 * @brief         Fragmentation test with a too big PPDU requested
 *
 * @return        true if error is raised, else false.
 */
bool test_frag_ctxtless_too_big(void);


#endif /* __TEST_RLE_FRAG_CTXTLESS_H__ */

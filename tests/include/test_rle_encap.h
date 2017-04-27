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
 * @file   test_rle_encap.h
 * @brief  Definition of public functions used for the encapsulation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_ENCAP_H__
#define __TEST_RLE_ENCAP_H__

#include "test_rle_common.h"

/**
 * @brief         Encapsulation test when transmitter is null.
 *
 *                This test try to encapsulate with a null transmitter. The encapsulation must
 *                return RLE_ENCAP_ERR_NULL_TRMT.
 *
 * @return        true if OK, else false.
 */
bool test_encap_null_transmitter(void);

/**
 * @brief         Encapsulation test when payload is too big.
 *
 *                This test try to encapsulate 2 packets. The first one is at the limite of
 *                acceptable size and will be encapsulate. The second one is one octet too big and
 *                will raise an error.
 *
 * @return        true if OK, else false.
 */
bool test_encap_too_big(void);

/**
 * @brief         Encapsulation test when transmitter configuration is invalid.
 *
 *                Ask the creation and initialization of an RLE transmitter, with an invalid
 *                configuration (i.e. with a non supported implicit protocol type).
 *                Warning: An ERROR message will be printed.
 *
 * @return        true if transmitter non initialized, else false.
 */
bool test_encap_inv_config(void);

/**
 * @brief         All the Encapsulation tests
 *
 *                Encapsulation test for different protocol types (IPv4, v6, VLAN, QinQ,
 *                QinQ legacy, ARP, signalling and miscalenous), for the 8 frag id, and for
 *                different configurations. One fail of encap means the test totaly fails.
 *
 * @return        true if OK, else false.
 */
bool test_encap_all(void);

#endif /* __TEST_RLE_ENCAP_H__ */

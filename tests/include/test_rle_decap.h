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
 * @file   test_rle_decap.h
 * @brief  Definition of public functions used for the decapsulation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_DECAP_H__
#define __TEST_RLE_DECAP_H__

#include "test_rle_common.h"

/**
 * @brief         Decapsulation test when transmitter is null.
 *
 *                This test try to decapsulate with a null receiver. The decapsulation must
 *                return RLE_DECAP_ERR_NULL_RCVR.
 *
 * @return        true if OK, else false.
 */
bool test_decap_null_receiver(void);

/**
 * @brief         Decapsulation test when FPDU is invalid.
 *
 *                Try to decap an invalid FPDU. Must return RLE_DECAP_ERR_INV_FPDU.
 *
 * @return        true if OK, else false.
 */
bool test_decap_inv_fpdu(void);

/**
 * @brief         Decapsulation test when SDUs buffer is invalid.
 *
 *                Try to decap an invalid SDUs buffer. Must return RLE_DECAP_ERR_INV_SDUS.
 *
 * @return        true if OK, else false.
 */
bool test_decap_inv_sdus(void);

/**
 * @brief         Decapsulation test when payload label buffer is invalid.
 *
 *                Try to decap an invalid payload label buffer. Must return RLE_DECAP_ERR_INV_PL.
 *
 * @return        true if OK, else false.
 */
bool test_decap_inv_pl(void);

/**
 * @brief         Decapsulation test when receiver configuration is invalid.
 *
 *                Ask the creation and initialization of an RLE receiver, with an invalid
 *                configuration (i.e. with a non supported implicit protocol type).
 *                Warning: An ERROR message will be printed.
 *
 * @return        true if receiver non initialized, else false.
 */
bool test_decap_inv_config(void);

/**
 * @brief         Decapsulation test when FPDU contains padding with a non equal to 0 octet.
 *
 *                No error should be raised, and decapsulation must be successful but a warning
 *                message will be printed.
 *
 * @return        true if decapsulation succeed, else false.
 */
bool test_decap_not_null_padding(void);

/**
 * @brief         Decapsulation test when an FPDU contains an invalid SeqNo, leading to a context
 *                flush. The decapsulation after the flushed one should be OK.
 *
 *                No error should be raised, and decapsulation must be successful but a warning
 *                message will be printed.
 *
 * @return        true if decapsulation succeed, else false.
 */
bool test_decap_flush_ctxt(void);

/**
 * @brief         Decapsulation test when an FPDU contains a null SeqNo.
 *
 *                No error should now be raised, and decapsulation must be successful but a warning
 *                message will be printed.
 *
 * @return        true if decapsulation succeed, else false.
 */
bool test_decap_null_seqno(void);

/**
 * @brief         Fix context freeing index.
 *
 *                No error should now be raised, and decapsulation must be successful.
 *
 * @return        true if decapsulation succeed, else false.
 */
bool test_decap_context_free(void);

/**
 * @brief Test the robustness against PPDU fragment with 0 byte of ALPDU
 *
 * @return        true if such fragments are ignored, else false
 */
bool test_decap_alpdu_fragment_0_byte(void);

/**
 * @brief Test the robustness against 2-byte PPDU fragment
 *
 * @return        true if such fragments are ignored, else false
 */
bool test_decap_ppdu_2_bytes(void);

/**
 * @brief Test the robustness against wrong CRC
 *
 * @return        true if such fragments are dropped, else false
 */
bool test_decap_wrong_crc(void);

/**
 * @brief Test the robustness against interlaced reassembly
 *
 * @return        true if all SDUs are reassembled, else false
 */
bool test_decap_interlaced_reassembly(void);

/**
 * @brief         All the Decapsulation tests
 *
 *                Decapsulation test for different protocol types (IPv4, v6, VLAN, QinQ,
 *                QinQ legacy, ARP, signalling and miscalenous), for the 8 frag id, and for
 *                different configurations, and different number of SDUs. One fail of decap means
 *                the test totaly fails.
 *
 * @return        true if OK, else false.
 */
bool test_decap_all(void);

#endif /* __TEST_RLE_DECAP_H__ */

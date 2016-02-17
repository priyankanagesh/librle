/**
 * @file   test_rle_encap_ctxtless.h
 * @brief  Definition of public functions used for the encapsulation without context tests.
 * @author Henrick Deschamps
 * @date   06/2016
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_ENCAP_CTXTLESS_H__
#define __TEST_RLE_ENCAP_CTXTLESS_H__

#include "test_rle_common.h"

/**
 * @brief         Encapsulation test when transmitter is null.
 *
 *                This test try to encapsulate with a null transmitter. The encapsulation must
 *                return RLE_ENCAP_ERR_NULL_TRMT.
 *
 * @return        true if OK, else false.
 */
bool test_encap_ctxtless_null_transmitter(void);

/**
 * @brief         Encapsulation test when fragmentation buffer is null.
 *
 *                This test try to encapsulate with a null fragmentation buffer. The encapsulation
 *                must return RLE_ENCAP_ERR_NULL_F_BUFF.
 *
 * @return        true if OK, else false.
 */
bool test_encap_ctxtless_null_f_buff(void);

/**
 * @brief         Encapsulation test when fragmentation buffer is not initialized.
 *
 *                This test try to encapsulate with a fragmentation buffer not initialized. The
 *                encapsulation must return RLE_ENCAP_ERR_NULL_F_BUFF.
 *
 * @return        true if OK, else false.
 */
bool test_encap_ctxtless_f_buff_not_init(void);

/**
 * @brief         Encapsulation test when payload is too big.
 *
 *                This test try to encapsulate 2 packets. The first one is at the limite of
 *                acceptable size and will be encapsulate. The second one is one octet too big and
 *                will raise an error.
 *
 * @return        true if OK, else false.
 */
bool test_encap_ctxtless_too_big(void);


#endif /* __TEST_RLE_ENCAP_CTXTLESS_H__ */

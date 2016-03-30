/**
 * @file   test_rle_encap_ctxtless.c
 * @brief  Body file used for the encapsulation tests without contexts.
 * @author Henrick Deschamps
 * @date   02/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_encap_ctxtless.h"

#include "fragmentation_buffer.h"
#include "rle_transmitter.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

bool test_encap_ctxtless_null_transmitter(void)
{
	bool output = false;
	enum rle_encap_status ret_encap;
	int ret;

	struct rle_frag_buf *f_buff = rle_frag_buf_new();

	const struct rle_sdu sdu = {
		.buffer        = (unsigned char *)payload_initializer,
		.size          = 100,
		.protocol_type = 0x1234,
	};
	struct rle_transmitter *transmitter = NULL;

	PRINT_TEST("Special case : Encapsulation with a null transmitter.");

	if (transmitter) {
		PRINT_ERROR("Transmitter is not NULL. Cannot test encap with NULL transmitter.");
		goto out;
	}

	if (!f_buff) {
		PRINT_ERROR("Fragmentation buffer is NULL. Cannot test encap with NULL transmitter.");
		goto out;
	}

	ret = rle_frag_buf_init(f_buff);
	assert(ret == 0); /* cannot fail since f_buff is not NULL */

	if (rle_frag_buf_cpy_sdu(f_buff, &sdu) != 0) {
		PRINT_ERROR("Unable to copy SDU in fragmentation buffer.");
		goto out;
	}

	ret_encap = rle_encap_contextless(transmitter, f_buff);

	switch (ret_encap) {
		case RLE_ENCAP_ERR_NULL_TRMT:
			PRINT_TEST("NULL transmitter detected, test sucessfull.");
			output = true;
			break;
		case RLE_ENCAP_OK:
			PRINT_TEST("Encapsulation is OK, Big error.");
			break;
		default:
			PRINT_TEST("Encapsulation failed, but not due to NULL transmitter. Test failed.");
			break;
	}

out:

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	if (f_buff) {
		rle_frag_buf_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_ctxtless_null_f_buff(void)
{
	bool output = false;
	enum rle_encap_status ret;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	struct rle_frag_buf *f_buff = NULL;
	struct rle_transmitter *transmitter;

	PRINT_TEST("Special case : Encapsulation with a null fragmentation buffer.");

	transmitter = rle_transmitter_new(&conf);
	if (!transmitter) {
		PRINT_ERROR("Transmitter is NULL. Cannot test encap with NULL fragmentation buffer.");
		goto out;
	}

	if (f_buff) {
		PRINT_ERROR("Fragmentation buffer is not NULL. Cannot test encap with NULL fragmentation "
		            "buffer.");
		goto out;
	}

	ret = rle_encap_contextless(transmitter, f_buff);

	switch (ret) {
		case RLE_ENCAP_ERR_NULL_F_BUFF:
			PRINT_TEST("NULL fragmentation buffer detected, test sucessfull.");
			output = true;
			break;
		case RLE_ENCAP_OK:
			PRINT_TEST("Encapsulation is OK, Big error.");
			break;
		default:
			PRINT_TEST("Encapsulation failed, but not due to NULL transmitter. Test failed.");
			break;
	}

out:

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	if (f_buff) {
		rle_frag_buf_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_ctxtless_f_buff_not_init(void)
{
	bool output = false;
	enum rle_encap_status ret;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	struct rle_frag_buf *f_buff = rle_frag_buf_new();
	struct rle_transmitter *transmitter;

	PRINT_TEST("Special case : Encapsulation with a fragmentation buffer not initialized.");

	transmitter = rle_transmitter_new(&conf);
	if (!transmitter) {
		PRINT_ERROR("Transmitter is not NULL. Cannot test encap with NULL transmitter.");
		goto out;
	}

	if (!f_buff) {
		PRINT_ERROR("Fragmentation buffer is NULL. Cannot test encap with NULL transmitter.");
		goto out;
	}

	ret = rle_encap_contextless(transmitter, f_buff);

	switch (ret) {
		case RLE_ENCAP_ERR_N_INIT_F_BUFF:
			PRINT_TEST("Not initialized fragmentation buffer transmitter detected, "
			           "test sucessfull.");
			output = true;
			break;
		case RLE_ENCAP_OK:
			PRINT_TEST("Encapsulation is OK, Big error.");
			break;
		default:
			PRINT_TEST("Encapsulation failed, but not due to NULL transmitter. Test failed.");
			break;
	}

out:

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	if (f_buff) {
		rle_frag_buf_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_encap_ctxtless_too_big(void)
{
	bool output = false;
	enum rle_encap_status ret_encap;
	int ret;

	struct rle_frag_buf *f_buff = rle_frag_buf_new();

	const struct rle_sdu sdu_ok = {
		.buffer        = (unsigned char *)payload_initializer,
		.size          = 4088,
		.protocol_type = 0x1234,
	};

	const struct rle_sdu sdu_ko = {
		.buffer        = (unsigned char *)payload_initializer,
		.size          = 4089,
		.protocol_type = 0x1234,
	};

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_transmitter *transmitter;

	PRINT_TEST("Special case : Encapsulation with a SDU too big.");

	transmitter = rle_transmitter_new(&conf);
	if (!transmitter) {
		PRINT_ERROR("Transmitter is NULL. Cannot test encap with too big SDU.");
		goto out;
	}

	if (!f_buff) {
		PRINT_ERROR("Fragmentation buffer is NULL. Cannot test encap with too big SDU.");
		goto out;
	}

	ret = rle_frag_buf_init(f_buff);
	assert(ret == 0); /* cannot fail since f_buff is not NULL */

	if (rle_frag_buf_cpy_sdu(f_buff, &sdu_ok) != 0) {
		PRINT_ERROR("Unable to copy SDU in fragmentation buffer.");
		goto out;
	}

	ret_encap = rle_encap_contextless(transmitter, f_buff);

	if (ret_encap == RLE_ENCAP_OK) {
		PRINT_TEST("Encapsulation is OK.");
	} else {
		PRINT_TEST("Encapsulation failed, but not due to SDU size. Test failed.");
		goto out;
	}

	ret = rle_frag_buf_init(f_buff);
	assert(ret == 0); /* cannot fail since f_buff is not NULL */

	if (rle_frag_buf_cpy_sdu(f_buff, &sdu_ko) == 0) {
		PRINT_ERROR("Too big SDU accepted in fragmentation buffer.");
		goto out;
	}

	output = true;

out:

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	if (f_buff) {
		rle_frag_buf_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

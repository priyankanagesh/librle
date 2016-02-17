/**
 * @file   test_rle_encap_ctxtless.c
 * @brief  Body file used for the encapsulation tests without contexts.
 * @author Henrick Deschamps
 * @date   02/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fragmentation_buffer.h"
#include "rle_transmitter.h"

#include "test_rle_encap_ctxtless.h"


enum boolean test_encap_ctxtless_null_transmitter(void)
{
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret;

	struct rle_fragmentation_buffer *f_buff = rle_f_buff_new();

	const struct rle_sdu sdu = {
		.buffer        = (unsigned char *)payload_initializer,
		.size          = 100,
		.protocol_type = 0x1234,
	};

	PRINT_TEST("Special case : Encapsulation with a null transmitter.");

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	if (transmitter) {
		PRINT_ERROR("Transmitter is not NULL. Cannot test encap with NULL transmitter.");
		goto out;
	}

	if (!f_buff) {
		PRINT_ERROR("Fragmentation buffer is NULL. Cannot test encap with NULL transmitter.");
		goto out;
	}

	if (rle_f_buff_init(f_buff) != 0) {
		PRINT_ERROR("Unable to initialize fragmentation buffer.");
		goto out;
	}

	if (rle_f_buff_cpy_sdu(f_buff, &sdu) != 0) {
		PRINT_ERROR("Unable to copy SDU in fragmentation buffer.");
		goto out;
	}

	ret = rle_encap_contextless(transmitter, f_buff);

	switch (ret) {
		case RLE_ENCAP_ERR_NULL_TRMT:
			PRINT_TEST("NULL transmitter detected, test sucessfull.");
			output = BOOL_TRUE;
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
		rle_f_buff_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_encap_ctxtless_null_f_buff(void)
{
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret;

	const struct rle_context_configuration conf = {
		.implicit_protocol_type                 = 0x00,
		.use_alpdu_crc                          = 0,
		.use_ptype_omission                     = 0,
		.use_compressed_ptype                   = 0,
	};

	struct rle_fragmentation_buffer *f_buff = NULL;

	PRINT_TEST("Special case : Encapsulation with a null fragmentation buffer.");

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

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
			output = BOOL_TRUE;
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
		rle_f_buff_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_encap_ctxtless_f_buff_not_init(void)
{
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret;

	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0,
	};

	struct rle_fragmentation_buffer *f_buff = rle_f_buff_new();

	PRINT_TEST("Special case : Encapsulation with a fragmentation buffer not initialized.");

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

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
			output = BOOL_TRUE;
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
		rle_f_buff_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_encap_ctxtless_too_big(void)
{
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret;

	struct rle_fragmentation_buffer *f_buff = rle_f_buff_new();

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

	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x00,
		.use_alpdu_crc          = 0,
		.use_ptype_omission     = 0,
		.use_compressed_ptype   = 0,
	};

	PRINT_TEST("Special case : Encapsulation with a SDU too big.");

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	transmitter = rle_transmitter_new(&conf);

	if (!transmitter) {
		PRINT_ERROR("Transmitter is NULL. Cannot test encap with too big SDU.");
		goto out;
	}

	if (!f_buff) {
		PRINT_ERROR("Fragmentation buffer is NULL. Cannot test encap with too big SDU.");
		goto out;
	}

	if (rle_f_buff_init(f_buff) != 0) {
		PRINT_ERROR("Unable to initialize fragmentation buffer.");
		goto out;
	}

	if (rle_f_buff_cpy_sdu(f_buff, &sdu_ok) != 0) {
		PRINT_ERROR("Unable to copy SDU in fragmentation buffer.");
		goto out;
	}

	ret = rle_encap_contextless(transmitter, f_buff);

	if (ret == RLE_ENCAP_OK) {
		PRINT_TEST("Encapsulation is OK.");
	} else {
		PRINT_TEST("Encapsulation failed, but not due to SDU size. Test failed.");
		goto out;
	}

	if (rle_f_buff_init(f_buff) != 0) {
		PRINT_ERROR("Unable to initialize fragmentation buffer.");
		goto out;
	}

	if (rle_f_buff_cpy_sdu(f_buff, &sdu_ko) == 0) {
		PRINT_ERROR("Too big SDU accepted in fragmentation buffer.");
	} else {
		output = BOOL_TRUE;
	}

out:

	if (transmitter) {
		rle_transmitter_destroy(&transmitter);
	}

	if (f_buff) {
		rle_f_buff_del(&f_buff);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

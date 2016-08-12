/**
 * @file   test_rle_decap.c
 * @brief  Body file used for the decapsulation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_decap.h"

#include "rle_transmitter.h"
#include "rle_receiver.h"
#include "fragmentation_buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

/**
 * @brief         Generic decapsulation test.
 *
 *                Simply decapsulate a previously encapsulated, fragmented and packed SDU.
 *
 * @param[in]     protocol_type            The protocol type of the SDU
 * @param[in]     conf                     Configuration of the transmitter and the receiver
 * @param[in]     number_of_sdus           The number of SDUs to pack/decap
 * @param[in]     sdu_length               The length of the SDUs
 * @param[in]     frag_id                  The fragment id
 * @param[in]     burst_size               The size of the burst for fragmentation
 * @param[in]     label_length             The length of the payload label
 *
 * @return        true if OK, else false.
 */
static bool test_decap(const uint16_t protocol_type,
                       const struct rle_config conf,
                       const size_t number_of_sdus,
                       const size_t sdu_length,
                       const uint8_t frag_id,
                       const size_t burst_size,
                       const size_t label_length);

static void print_modules_stats(const struct rle_transmitter *const transmitter,
                                const struct rle_receiver *const receiver)
{
	print_transmitter_stats(transmitter);
	print_receiver_stats(receiver);
}

static bool test_decap(const uint16_t protocol_type,
                       const struct rle_config conf,
                       const size_t number_of_sdus,
                       const size_t sdu_length,
                       const uint8_t frag_id,
                       const size_t burst_size,
                       const size_t label_length)
{
	PRINT_TEST(
	        "protocol type 0x%04x, number of SDUs %zu, SDU length %zu, frag_id %d, conf %s, "
	        "protection %s, burst size %zu, label length %zu", protocol_type, number_of_sdus,
	        sdu_length, frag_id, conf.allow_ptype_omission == 0 ?
	        (conf.use_compressed_ptype == 0 ?  "uncompressed" : "compressed") :
	        (conf.implicit_protocol_type == 0x00) ?  "non omitted" :
	        (conf.implicit_protocol_type == 0x30 ? "ip omitted" : "omitted"),
	        conf.allow_alpdu_sequence_number == 0 ? "SeqNo" : "CRC",
	        burst_size, label_length);

	bool output = false;

	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = 0,
		.protocol_type = protocol_type
	};
	struct rle_receiver *receiver = NULL;
	struct rle_transmitter *transmitter = NULL;

	const size_t fpdu_length = 1000; /* Arbitrarly */
	unsigned char fpdu[fpdu_length];
	size_t fpdu_iterator = 0;
	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		fpdu[fpdu_iterator] = '\0';
	}
	size_t fpdu_current_pos = 0;
	size_t fpdu_remaining_size = fpdu_length;
	size_t number_of_sdus_iterator = 0;

	assert(label_length <= MAX_LABEL_LEN);

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto exit_label;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter");
		goto exit_label;
	}

	for (number_of_sdus_iterator = 1;
	     number_of_sdus_iterator <= number_of_sdus;
	     ++number_of_sdus_iterator) {
		if (sdu.buffer != NULL) {
			free(sdu.buffer);
			sdu.buffer = NULL;
		}

		sdu.buffer = calloc(sdu_length, sizeof(unsigned char));
		if (sdu.buffer == NULL) {
			PRINT_ERROR("Error allocating SDU buffer");
			goto exit_label;
		}
		memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);

		switch (protocol_type) {
		case 0x0800:
			sdu.buffer[0] = 0x40;         /* IPv4 */
			break;
		case 0x86dd:
			sdu.buffer[0] = 0x60;         /* IPv6 */
			break;
		}

		sdu.size = sdu_length;
		ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
		if (ret_encap != RLE_ENCAP_OK) {
			PRINT_ERROR("Encap does not return OK.");
			goto exit_label;
		}

		{
			unsigned char label[MAX_LABEL_LEN];
			if (label_length != 0) {
				memcpy(label, payload_initializer, label_length);
			}
			while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
				unsigned char *ppdu;
				size_t ppdu_length = 0;

				ret_frag = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &ppdu_length);
				if (ret_frag != RLE_FRAG_OK) {
					PRINT_ERROR("Frag does not return OK.");
					goto exit_label;
				}

				ret_pack = rle_pack(ppdu, ppdu_length, label, label_length, fpdu,
				                    &fpdu_current_pos, &fpdu_remaining_size);

				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto exit_label;
				}
			}
		}
	}

	{
		const size_t sdus_max_nr = 10; /* Arbitrarly */
		size_t sdus_nr = 0;
		struct rle_sdu sdus[sdus_max_nr];
		size_t sdu_iterator = 0;
		unsigned char label[MAX_LABEL_LEN];
		unsigned char *labelp;
		if (label_length != 0) {
			memcpy(label, payload_initializer, label_length);
			labelp = label;
		} else {
			labelp = NULL;
		}

		for (sdu_iterator = 0; sdu_iterator < sdus_max_nr; ++sdu_iterator) {
			sdus[sdu_iterator].size = (size_t)RLE_MAX_PDU_SIZE;
			sdus[sdu_iterator].buffer = calloc(sdus[sdu_iterator].size, sizeof(unsigned char));
			if (sdus[sdu_iterator].buffer == NULL) {
				PRINT_ERROR("Error during SDUs buffer allocation, before decapsulation.");
				goto free_sdus;
			}
		}

		ret_decap = rle_decapsulate(receiver, fpdu, fpdu_length, sdus,
		                            sdus_max_nr, &sdus_nr, labelp, label_length);

		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto free_sdus;
		}

		if (sdus_nr != number_of_sdus) {
			PRINT_ERROR("SDUs number expected is %zu, not %zu", number_of_sdus, sdus_nr);
			goto free_sdus;
		} else if (sdu.size != sdus[0].size) {
			PRINT_ERROR("SDUs size are different : original %zu, decap %zu", sdu.size,
			            sdus[0].size);
			goto free_sdus;
		} else if (sdu.protocol_type != sdus[0].protocol_type) {
			PRINT_ERROR("SDUs protocol type are different : original %d, decap %d",
			            sdu.protocol_type,
			            sdus[0].protocol_type);
			goto free_sdus;
		} else {
			for (number_of_sdus_iterator = 1;
			     number_of_sdus_iterator <= number_of_sdus;
			     ++number_of_sdus_iterator) {
				size_t iterator = 0;
				bool equal = true;
				for (iterator = 0; iterator < sdu.size; ++iterator) {
					if (sdu.buffer[iterator] != sdus[0].buffer[iterator]) {
						PRINT_ERROR( "SDUs are different, at %zu, expected 0x%02x, get 0x%02x",
						             iterator, sdu.buffer[iterator], sdus[0].buffer[iterator]);
						equal = false;
					}
				}
				if (equal == false) {
					PRINT_ERROR("SDUs %zu are different.",
					            number_of_sdus_iterator);
					goto free_sdus;
				}
			}
		}

		output = true;

free_sdus:

		for (sdu_iterator = 0; sdu_iterator < sdus_max_nr; ++sdu_iterator) {
			if (sdus[sdu_iterator].buffer != NULL) {
				free(sdus[sdu_iterator].buffer);
				sdus[sdu_iterator].buffer = NULL;
			}
		}
	}

exit_label:

	print_modules_stats(transmitter, receiver);

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_decap_null_receiver(void)
{
	PRINT_TEST("Special case : Decapsulation with a null receiver.");
	bool output = false;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 5000;
	unsigned char fpdu[fpdu_length];
	size_t fpdu_iterator = 0;
	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		fpdu[fpdu_iterator] = '\0';
	}

	const size_t sdus_max_nr = 10;
	struct rle_sdu sdus[sdus_max_nr];

	size_t sdus_nr = 0;

	const size_t payload_label_size = 3;
	unsigned char payload_label[payload_label_size];

	struct rle_receiver *receiver = NULL;

	ret_decap =
	        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
	                        payload_label,
	                        payload_label_size);

	if (ret_decap != RLE_DECAP_ERR_NULL_RCVR) {
		PRINT_ERROR("decapsulation does not return null receiver.");
		goto exit_label;
	}

	output = true;

exit_label:

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_decap_inv_fpdu(void)
{
	PRINT_TEST("Special case : Decapsulation with an invalid FPDU buffer.");
	bool output = false;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t sdus_max_nr = 10;
	struct rle_sdu sdus[sdus_max_nr];

	size_t sdus_nr = 0;

	const size_t payload_label_size = 3;
	unsigned char payload_label[payload_label_size];

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto exit_label;
	}

	{
		const size_t fpdu_length = 0;
		unsigned char fpdu[1];

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_FPDU) {
			PRINT_ERROR(
			        "decapsulation does not return invalid FPDU buffer when buffer length is 0.");
			goto exit_label;
		}
	}

	{
		const size_t fpdu_length = 5000;
		unsigned char *fpdu = NULL;

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_FPDU) {
			PRINT_ERROR(
			        "decapsulation does not return invalid FPDU buffer when buffer is null.");
			goto exit_label;
		}
	}

	{
		const size_t fpdu_length = payload_label_size - 1;
		unsigned char fpdu[fpdu_length];
		size_t fpdu_iterator = 0;
		for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
			fpdu[fpdu_iterator] = '\0';
		}

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_FPDU) {
			PRINT_ERROR("decapsulation does not return invalid FPDU buffer "
			            "when buffer is smaller than the payload label one.");
			goto exit_label;
		}
	}

	output = true;

exit_label:

	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_decap_inv_sdus(void)
{
	PRINT_TEST("Special case : Decapsulation with an invalid SDUs buffer.");
	bool output = false;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 5000;
	unsigned char fpdu[fpdu_length];
	size_t fpdu_iterator = 0;
	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		fpdu[fpdu_iterator] = '\0';
	}

	size_t sdus_nr = 0;

	const size_t payload_label_size = 3;
	unsigned char payload_label[payload_label_size];

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto exit_label;
	}

	{
		const size_t sdus_max_nr = 0;
		struct rle_sdu sdus[1];

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_SDUS) {
			PRINT_ERROR(
			        "decapsulation does not return invalid SDUs buffer when length is 0.");
			goto exit_label;
		}
	}

	{
		const size_t sdus_max_nr = 10;
		struct rle_sdu *sdus = NULL;

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_SDUS) {
			PRINT_ERROR(
			        "decapsulation does not return invalid SDUs buffer when buffer is NULL.");
			goto exit_label;
		}
	}

	output = true;

exit_label:

	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_decap_inv_pl(void)
{
	PRINT_TEST("Special case : Decapsulation with an invalid payload label buffer.");
	bool output = false;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 5000;
	unsigned char fpdu[fpdu_length];
	size_t fpdu_iterator = 0;
	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		fpdu[fpdu_iterator] = '\0';
	}

	const size_t sdus_max_nr = 10;
	struct rle_sdu sdus[sdus_max_nr];

	size_t sdus_nr = 0;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto exit_label;
	}

	{
		const size_t payload_label_size = 0;
		unsigned char payload_label[3];

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_PL) {
			PRINT_ERROR("decapsulation does not return invalid payload label buffer "
			            "when size is 0 but buffer is not null.");
			goto exit_label;
		}
	}

	{
		const size_t payload_label_size = 3;
		unsigned char *payload_label = NULL;

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_PL) {
			PRINT_ERROR("decapsulation does not return invalid payload label buffer "
			            "when buffer is null but size is not 0.");
			goto exit_label;
		}
	}

	{
		const size_t payload_label_size = 2;
		unsigned char payload_label[payload_label_size];

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_ERR_INV_PL) {
			PRINT_ERROR("decapsulation does not return invalid payload label buffer"
			            "when size is invalid.");
			goto exit_label;
		}
	}

	output = true;

exit_label:

	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_decap_inv_config(void)
{
	PRINT_TEST("Special test: try to create an RLE receiver module with an invalid conf. "
	           "Warning: An error message may be printed.");
	bool output;

	const struct rle_config conf = {
		.implicit_protocol_type = 0x31
	};
	struct rle_receiver *receiver;

	receiver = rle_receiver_new(&conf);

	output = (receiver == NULL);

	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_decap_not_null_padding(void)
{
	PRINT_TEST("Special case : Decapsulation with an invalid FPDU padding. "
	           "Must succeed but print a warning message .");
	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 5000;
	unsigned char fpdu[fpdu_length];
	size_t fpdu_iterator = 0;
	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		fpdu[fpdu_iterator] = '\0';
	}

	const uint8_t frag_id = 0;

	const size_t sdu_length = 100;

	unsigned char *const buffer_in[sdu_length];
	unsigned char *const buffer_out[sdu_length];

	struct rle_sdu sdu = {
		.buffer = (unsigned char *)buffer_in,
		.size = sdu_length
	};
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);
	sdu.buffer[0] = 0x40; /* IPv4 */

	const size_t sdus_max_nr = 1;
	struct rle_sdu sdus[sdus_max_nr];
	sdus[0].buffer = (unsigned char *)buffer_out;

	size_t sdus_nr = 0;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver = NULL;
	struct rle_transmitter *transmitter = NULL;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver.");
		goto exit_label;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter.");
		goto exit_label;
	}

	ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap does not return OK.");
		goto exit_label;
	}

	{
		const size_t payload_label_size = 0;
		unsigned char *payload_label = NULL;
		size_t fpdu_current_pos = 0;
		size_t fpdu_remaining_size = fpdu_length;
		const size_t burst_size = 30;
		while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
			unsigned char *ppdu;
			size_t ppdu_length = 0;

			ret_frag = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &ppdu_length);

			if (ret_frag != RLE_FRAG_OK) {
				PRINT_ERROR("Frag does not return OK.");
				goto exit_label;
			}

			ret_pack =
			        rle_pack(ppdu, ppdu_length, payload_label, payload_label_size,
			                 fpdu,
			                 &fpdu_current_pos,
			                 &fpdu_remaining_size);

			if (ret_pack != RLE_PACK_OK) {
				PRINT_ERROR("Pack does not return OK.");
				goto exit_label;
			}
		}

		/* Bad injection, should trigger the warning bad padding message during decapsulation. */
		fpdu[fpdu_length - 1] = 0x01;

		ret_decap =
		        rle_decapsulate(receiver, fpdu, fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                        payload_label,
		                        payload_label_size);

		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}
	}

	output = true;

exit_label:
	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}


bool test_decap_flush_ctxt(void)
{
	PRINT_TEST("Special case : Decapsulation with a wrong SeqNo leading to a context flush. "
	           "Must succeed but print a ERROR REASSEMBLY and ERROR RECEIVER messages .");

	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 30;
	const size_t fpdus_max_nr = 20;
	unsigned char fpdu[fpdus_max_nr][fpdu_length];

	const uint8_t frag_id = 0;

	const size_t input_sdus_nr = 5;
	const size_t sdu_length = 100;

	unsigned char *const buffer_in[sdu_length];
	unsigned char *const buffer_out[sdu_length];

	struct rle_sdu sdu = {
		.buffer = (unsigned char *)buffer_in,
		.size = sdu_length
	};

	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);
	sdu.buffer[0] = 0x40; /* IPv4 */

	size_t sdus_total_nr;
	const size_t sdus_max_nr = 2;
	struct rle_sdu sdus[sdus_max_nr];
	sdus[0].buffer = (unsigned char *)buffer_out;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver = NULL;
	struct rle_transmitter *transmitter = NULL;
	size_t i;

	size_t fpdus_nr;
	size_t fpdu_current_pos;
	size_t fpdu_remaining_size;
	const size_t payload_label_size = 0;
	unsigned char *payload_label = NULL;

	size_t expected_bytes_dropped = 0;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver.");
		goto exit_label;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter.");
		goto exit_label;
	}

	/* encaspulate several SDUs */
	fpdus_nr = 0;
	fpdu_current_pos = 0;
	fpdu_remaining_size = fpdu_length;
	for (i = 0; i < input_sdus_nr; i++) {

		printf("encapsulate %zu-byte SDU #%zu:\n", sdu.size, i + 1);
		ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
		if (ret_encap != RLE_ENCAP_OK) {
			PRINT_ERROR("Encap does not return OK.");
			goto exit_label;
		}

		/* simulate a loss of the 3rd SDU */
		if (i == 2) {
			unsigned char *ppdu;
			size_t ppdu_length = 0;

			printf("\tsimulate a loss of the FPDU\n");

			while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
				ret_frag = rle_fragment(transmitter, frag_id, fpdu_length,
				                        &ppdu, &ppdu_length);
				if (ret_frag != RLE_FRAG_OK) {
					PRINT_ERROR("Frag does not return OK.");
					goto exit_label;
				}
			}
		}

		while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
			unsigned char *ppdu;
			size_t ppdu_length = 0;

			printf("\t\tfragment SDU into a max %zu-byte chunk\n",
			       fpdu_remaining_size);
			ret_frag = rle_fragment(transmitter, frag_id, fpdu_remaining_size,
			                        &ppdu, &ppdu_length);
			if (ret_frag == RLE_FRAG_ERR_BURST_TOO_SMALL) {
				printf("\t\tFPDU too small for fragment, wait for the next one\n");
				printf("\t\tpad FPDU on %zu bytes\n", fpdu_remaining_size);
				rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
				assert(fpdus_nr < fpdus_max_nr);
				fpdus_nr++;
				fpdu_current_pos = 0;
				fpdu_remaining_size = fpdu_length;
				printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);
			} else if (ret_frag != RLE_FRAG_OK) {
				PRINT_ERROR("Frag does not return OK.");
				goto exit_label;
			} else {
				printf("\t\t%zu-byte PPDU fragment generated\n", ppdu_length);

				/* the SDU after the simulated loss will be dropped */
				if (i == 3) {
					expected_bytes_dropped += ppdu_length;
				}

				printf("\t\tpack PPDU into a %zu-byte FPDU with %zu bytes remaining\n",
				       fpdu_length, fpdu_remaining_size);
				ret_pack = rle_pack(ppdu, ppdu_length,
				                    payload_label, payload_label_size,
										  fpdu[fpdus_nr], &fpdu_current_pos, &fpdu_remaining_size);
				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto exit_label;
				}
				printf("\t\t%zu/%zu bytes free in FPDU\n",
				       fpdu_remaining_size, fpdu_length);
			}
		}
	}

	/* flush the last FPDU if needed */
	if (fpdu_current_pos > 0) {
		rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
		assert(fpdus_nr < fpdus_max_nr);
		fpdus_nr++;
	}

	/* decapsulate all the generated FPDUs */
	sdus_total_nr = 0;
	for (i = 0; i < fpdus_nr; i++) {
		size_t sdus_nr = 0;

		printf("decapsulate pad FPDU #%zu\n", i + 1);
		ret_decap = rle_decapsulate(receiver, fpdu[i], fpdu_length,
		                            sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);
		if (i == 11 && ret_decap != RLE_DECAP_ERR) {
			PRINT_ERROR("decapsulation of FPDU #%zu failed to report drops, "
			            "it reported code %d instead", i + 1, ret_decap);
			goto exit_label;
		} else if (i != 11 && ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("decapsulation of FPDU #%zu failed to report OK, "
			            "it reported code %d instead", i + 1, ret_decap);
			goto exit_label;
		}
		printf("\t%zu SDUs decapsulated\n", sdus_nr);
		sdus_total_nr += sdus_nr;
	}

	if (sdus_total_nr != (input_sdus_nr - 2)) {
		PRINT_ERROR("%zu SDUs decapsulated while %zu SDUs encapsulated, "
		            "1 loss simulated and 1 expected drop",
		            sdus_total_nr, input_sdus_nr);
		goto exit_label;
	}

	/* check stats */
	{
		const uint64_t sdus_lost =
			rle_receiver_stats_get_counter_sdus_lost(receiver, frag_id);
		const uint64_t sdus_dropped =
			rle_receiver_stats_get_counter_sdus_dropped(receiver, frag_id);
		const uint64_t bytes_dropped =
			rle_receiver_stats_get_counter_bytes_dropped(receiver, frag_id);

		if (sdus_lost != 1) {
			PRINT_ERROR("%" PRIu64 " SDUs lost while 1 expected", sdus_lost);
			goto exit_label;
		}
		if (sdus_dropped != 1) {
			PRINT_ERROR("%" PRIu64 " SDUs dropped while 1 expected", sdus_dropped);
			goto exit_label;
		}
		if (bytes_dropped != expected_bytes_dropped) {
			PRINT_ERROR("%" PRIu64 " bytes dropped while %zu bytes expected",
			            bytes_dropped, expected_bytes_dropped);
			goto exit_label;
		}
	}

	output = true;

exit_label:
	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}


bool test_decap_all(void)
{
	PRINT_TEST("All general cases.");
	bool output = true;

	const size_t sdu_length = 100; /* Arbitrarly */

	size_t iterator = 0;

	const uint16_t protocol_types[] = { 0x0082 /* Signal */,
		                            0x8100 /* VLAN        */,
		                            0x88a8 /* QinQ        */,
		                            0x9100 /* QinQ Legacy */,
		                            0x0800 /* IPv4        */,
		                            0x86dd /* IPv6        */,
		                            0x0806 /* ARP         */,
		                            0x1234 /* MISC        */ };

	/* The tests will be launch on each protocol_type. */
	for (iterator = 0; iterator != (sizeof(protocol_types) / sizeof(uint16_t)); ++iterator) {
		const uint16_t protocol_type = protocol_types[iterator];
		const uint8_t max_frag_id = 8;
		uint8_t frag_id = 0;

		/* The test will be launch on each fragment id. */
		for (frag_id = 0; frag_id < max_frag_id; ++frag_id) {
			uint8_t default_ptype = 0x00;
			switch (protocol_types[iterator]) {
			case 0x0082:
				default_ptype = 0x42;
				break;
			case 0x8100:
				default_ptype = 0x0f;
				break;
			case 0x88a8:
				default_ptype = 0x19;
				break;
			case 0x9100:
				default_ptype = 0x1a;
				break;
			case 0x0800:
				default_ptype = 0x0d;
				break;
			case 0x86dd:
				default_ptype = 0x11;
				break;
			case 0x0806:
				default_ptype = 0x0e;
				break;
			default:
				default_ptype = 0x00;
				break;
			}

			/* Configuration for uncompressed protocol type */
			struct rle_config conf_uncomp = {
				.allow_ptype_omission = 0,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 0,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x0d,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for compressed protocol type */
			struct rle_config conf_comp = {
				.allow_ptype_omission = 0,
				.use_compressed_ptype = 1,
				.allow_alpdu_crc = 0,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for omitted protocol type */
			struct rle_config conf_omitted = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 0,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = default_ptype,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Special test for IPv4 and v6 */
			struct rle_config conf_omitted_ip = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 0,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x30,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for non omitted protocol type in omission conf */
			struct rle_config conf_not_omitted = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 0,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for uncompressed protocol type with CRC */
			struct rle_config conf_uncomp_crc = {
				.allow_ptype_omission = 0,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 0,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for compressed protocol type with CRC */
			struct rle_config conf_comp_crc = {
				.allow_ptype_omission = 0,
				.use_compressed_ptype = 1,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 0,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for omitted protocol type with CRC */
			struct rle_config conf_omitted_crc = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 0,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = default_ptype,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Special test for IPv4 and v6 */
			struct rle_config conf_omitted_ip_crc = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 0,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x30,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for non omitted protocol type in omission conf with CRC */
			struct rle_config conf_not_omitted_crc = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 0,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for uncompressed protocol type with CRC & seqnum */
			struct rle_config conf_uncomp_crc_seqnum = {
				.allow_ptype_omission = 0,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for compressed protocol type with CRC & seqnum */
			struct rle_config conf_comp_crc_seqnum = {
				.allow_ptype_omission = 0,
				.use_compressed_ptype = 1,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for omitted protocol type with CRC & seqnum */
			struct rle_config conf_omitted_crc_seqnum = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = default_ptype,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Special test for IPv4 and v6 with CRC & seqnum */
			struct rle_config conf_omitted_ip_crc_seqnum = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x30,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configuration for non omitted protocol type in omission conf with CRC & seqnum */
			struct rle_config conf_not_omitted_crc_seqnum = {
				.allow_ptype_omission = 1,
				.use_compressed_ptype = 0,
				.allow_alpdu_crc = 1,
				.allow_alpdu_sequence_number = 1,
				.use_explicit_payload_header_map = 0,
				.implicit_protocol_type = 0x00,
				.implicit_ppdu_label_size = 0,
				.implicit_payload_label_size = 0,
				.type_0_alpdu_label_size = 0,
			};

			/* Configurations */
			struct rle_config *confs[] = {
				&conf_uncomp,
				&conf_comp,
				&conf_omitted,
				&conf_omitted_ip,
				&conf_not_omitted,
				&conf_uncomp_crc,
				&conf_comp_crc,
				&conf_omitted_crc,
				&conf_omitted_ip_crc,
				&conf_not_omitted_crc,
				&conf_uncomp_crc_seqnum,
				&conf_comp_crc_seqnum,
				&conf_omitted_crc_seqnum,
				&conf_omitted_ip_crc_seqnum,
				&conf_not_omitted_crc_seqnum,
				NULL
			};

			/* Configuration iterator */
			struct rle_config **conf;

			/* We launch the test on each configuration. All the cases then are test. */
			for (conf = confs; *conf; ++conf) {
				const size_t nb_burst_sizes = 4;
				const size_t burst_sizes[] = { 30, 40, 80, 120 };
				size_t burst_size_iterator = 0;

				for (burst_size_iterator = 0;
				     burst_size_iterator < nb_burst_sizes;
				     ++burst_size_iterator) {
					const size_t burst_size = burst_sizes[burst_size_iterator];
					const size_t nb_labels = 3;
					const size_t label_length[] = { 0, 3, 6 };
					size_t label_length_iterator = 0;

					for (label_length_iterator = 0;
					     label_length_iterator < nb_labels;
					     ++label_length_iterator) {
						/* fpdu sizes, payload labels */

						const size_t pl_length = label_length[label_length_iterator];
						const size_t number_of_numbers_of_sdus = 2;
						const size_t numbers_of_sdus[] = { 1, 2 };
						size_t number_of_sdus_iterator = 0;

						for (number_of_sdus_iterator = 0;
						     number_of_sdus_iterator < number_of_numbers_of_sdus;
						     ++number_of_sdus_iterator) {
							const size_t number_of_sdus = numbers_of_sdus[ number_of_sdus_iterator];
							const bool ret =
							        test_decap(protocol_type, **conf, number_of_sdus, sdu_length,
							                   frag_id, burst_size, pl_length);
							if (ret == false) {
								/* Only one fail means the decap test fail. */
								output = false;
								goto error;
							}
						}
					}
				}
			}
		}
	}

error:
	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}


bool test_decap_null_seqno(void)
{
	PRINT_TEST("In order to allow automatic resynchronizing with transmitter in receiver, "
				"the SeqNo checking algorithm now considers wrong SeqNo as valid when "
				"received SeqNo is 0 (ie. the transmitter has relogged)..");

	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 30;
	const size_t fpdus_max_nr = 15;
	unsigned char fpdu[fpdus_max_nr][fpdu_length];

	const uint8_t frag_id = 0;

	const size_t input_sdus_nr = 3;
	const size_t sdu_length = 100;

	unsigned char *const buffer_in[sdu_length];
	unsigned char *const buffer_out[sdu_length];

	struct rle_sdu sdu = {
		.buffer = (unsigned char *)buffer_in,
		.size = sdu_length
	};

	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);
	sdu.buffer[0] = 0x40; /* IPv4 */

	size_t sdus_total_nr;
	const size_t sdus_max_nr = 2;
	struct rle_sdu sdus[sdus_max_nr];
	sdus[0].buffer = (unsigned char *)buffer_out;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver = NULL;
	struct rle_transmitter *transmitter = NULL;
	size_t i;

	size_t fpdus_nr;
	size_t fpdu_current_pos;
	size_t fpdu_remaining_size;
	const size_t payload_label_size = 0;
	unsigned char *payload_label = NULL;

	/* ensure SDU is larger than burst so that test is meaningful */
	assert(sdu_length > fpdu_length);

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver.");
		goto exit_label;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter.");
		goto exit_label;
	}

	/* encaspulate several SDUs */
	fpdus_nr = 0;
	fpdu_current_pos = 0;
	fpdu_remaining_size = fpdu_length;
	for (i = 0; i < input_sdus_nr; i++) {

		/* simulate a logoff/logon of the ST for the 3rd SDU */
		if (i == 2) {
			printf("simulate a logoff/logon of the ST\n");

			printf("\tflush FPDU #%zu\n", fpdus_nr + 1);
			rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
			assert(fpdus_nr < fpdus_max_nr);
			fpdus_nr++;
			fpdu_current_pos = 0;
			fpdu_remaining_size = fpdu_length;

			printf("\tdestroy then create RLE transmitter\n");
			rle_transmitter_destroy(&transmitter);
			transmitter = rle_transmitter_new(&conf);
			if (transmitter == NULL) {
				PRINT_ERROR("Error allocating transmitter");
				goto exit_label;
			}
		}

		printf("encapsulate %zu-byte SDU #%zu:\n", sdu.size, i + 1);
		ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
		if (ret_encap != RLE_ENCAP_OK) {
			PRINT_ERROR("Encap does not return OK.");
			goto exit_label;
		}

		printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);

		while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
			unsigned char *ppdu;
			size_t ppdu_length = 0;

			printf("\t\tfragment SDU into a max %zu-byte chunk\n",
			       fpdu_remaining_size);
			ret_frag = rle_fragment(transmitter, frag_id, fpdu_remaining_size,
			                        &ppdu, &ppdu_length);
			if (ret_frag == RLE_FRAG_ERR_BURST_TOO_SMALL) {
				printf("\t\tFPDU too small for fragment, wait for the next one\n");
				printf("\t\tpad FPDU on %zu bytes\n", fpdu_remaining_size);
				rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
				assert(fpdus_nr < fpdus_max_nr);
				fpdus_nr++;
				fpdu_current_pos = 0;
				fpdu_remaining_size = fpdu_length;
				printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);
			} else if (ret_frag != RLE_FRAG_OK) {
				PRINT_ERROR("Frag does not return OK.");
				goto exit_label;
			} else {
				printf("\t\t%zu-byte PPDU fragment generated\n", ppdu_length);

				printf("\t\tpack PPDU into a %zu-byte FPDU with %zu bytes remaining\n",
				       fpdu_length, fpdu_remaining_size);
				ret_pack = rle_pack(ppdu, ppdu_length,
				                    payload_label, payload_label_size,
										  fpdu[fpdus_nr], &fpdu_current_pos, &fpdu_remaining_size);
				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto exit_label;
				}
				printf("\t\t%zu/%zu bytes free in FPDU\n",
				       fpdu_remaining_size, fpdu_length);
			}
		}
	}

	/* flush the last FPDU if needed */
	if (fpdu_current_pos > 0) {
		rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
		assert(fpdus_nr < fpdus_max_nr);
		fpdus_nr++;
	}

	/* decapsulate all the generated FPDUs */
	sdus_total_nr = 0;
	for (i = 0; i < fpdus_nr; i++) {
		size_t sdus_nr = 0;

		printf("decapsulate pad FPDU #%zu\n", i + 1);
		ret_decap = rle_decapsulate(receiver, fpdu[i], fpdu_length,
		                            sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);
		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}
		printf("\t%zu SDUs decapsulated\n", sdus_nr);
		sdus_total_nr += sdus_nr;
	}

	if (sdus_total_nr != input_sdus_nr) {
		PRINT_ERROR("%zu SDUs decapsulated while %zu SDUs encapsulated",
		            sdus_total_nr, input_sdus_nr);
		goto exit_label;
	}

	output = true;

exit_label:
	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}


bool test_decap_context_free(void)
{
	PRINT_TEST("Fix context freeing index..");

	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 5000;
	const size_t nb_fpdu = 2;
	unsigned char fpdu[nb_fpdu][fpdu_length];
	size_t fpdu_iterator = 0;

	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		size_t it;
		for (it = 0; it < nb_fpdu; ++it) {
			fpdu[it][fpdu_iterator] = '\0';
		}
	}

	const size_t sdu_length = 100;

	unsigned char *const buffer_in[sdu_length];
	unsigned char *const buffer_out[sdu_length];

	struct rle_sdu sdu = {
		.buffer = (unsigned char *)buffer_in,
		.size = sdu_length
	};

	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);
	sdu.buffer[0] = 0x40; /* IPv4 */

	const size_t sdus_max_nr = 1;
	struct rle_sdu sdus[sdus_max_nr];
	sdus[0].buffer = (unsigned char *)buffer_out;

	size_t sdus_nr = 0;
	size_t last_pos = 0;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver = NULL;
	struct rle_transmitter *transmitter = NULL;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver.");
		goto exit_label;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter.");
		goto exit_label;
	}

	{
		const size_t payload_label_size = 0;
		unsigned char *payload_label = NULL;
		size_t fpdu_current_pos;
		size_t fpdu_remaining_size;
		size_t it;

		for (it = 0; it < nb_fpdu; ++ it) {
			fpdu_current_pos = 0;
			fpdu_remaining_size = fpdu_length;

			ret_encap = rle_encapsulate(transmitter, &sdu, it);
			if (ret_encap != RLE_ENCAP_OK) {
				PRINT_ERROR("Encap does not return OK.");
				goto exit_label;
			}


			while (rle_transmitter_stats_get_queue_size(transmitter, it)) {
				const size_t burst_size = 30;
				unsigned char *ppdu;
				size_t ppdu_length = 0;

				ret_frag = rle_fragment(transmitter, it, burst_size, &ppdu, &ppdu_length);

				if (ret_frag != RLE_FRAG_OK) {
					PRINT_ERROR("Frag does not return OK.");
					goto exit_label;
				}

				last_pos = fpdu_current_pos;
				ret_pack = rle_pack(ppdu, ppdu_length, payload_label, payload_label_size, fpdu[it],
				                    &fpdu_current_pos, &fpdu_remaining_size);

				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto exit_label;
				}
			}
		}

		for (it = 0; it < nb_fpdu; ++ it) {
			rle_pad(fpdu[it], fpdu_current_pos, fpdu_remaining_size);
		}

		// All 2 contexts should be free
		if (is_context_free(receiver, 0) == false) {
			PRINT_ERROR("Context 0 is not free NOK.");
			goto exit_label;
		}

		if (is_context_free(receiver, 1) == false) {
			PRINT_ERROR("Context 1 is not free NOK.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, fpdu[0], last_pos, sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);
		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, fpdu[1], last_pos, sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);
		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}


		// All 2 contexts should be occupied
		if (is_context_free(receiver, 0) == true) {
			PRINT_ERROR("Context 0 is free NOK.");
			goto exit_label;
		}

		if (is_context_free(receiver, 1) == true) {
			PRINT_ERROR("Context 1 is free NOK.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, &fpdu[0][last_pos], fpdu_length - last_pos, sdus, sdus_max_nr, &sdus_nr,
									NULL, 0);

		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}

		// First context should be free, and second occupied
		if (is_context_free(receiver, 0) == false) {
			PRINT_ERROR("Context 0 is not free NOK.");
			goto exit_label;
		}

		if (is_context_free(receiver, 1) == true) {
			PRINT_ERROR("Context 1 is free NOK.");
			goto exit_label;
		}

	}

	output = true;

exit_label:
	if (receiver != NULL) {
		rle_receiver_destroy(&receiver);
	}

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	PRINT_TEST_STATUS(output);
	printf("\n");

	return output;
}

bool test_decap_alpdu_fragment_0_byte(void)
{
	bool is_success = false;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x30,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	size_t sdu_len = 21; /* IPv4 */
	size_t protocol_type_len = 2; /* uncompressed protocol type */
	size_t trailer_len = 1; /* seqnum */

	size_t alpdu_len = protocol_type_len + sdu_len + trailer_len;
	size_t ppdu_start_len = 2 + 2 + 10 /* 10 bytes of ALPDU */;
	size_t ppdu_cont1_len = 2 + 0 /* 0-byte of ALPDU */;
	size_t ppdu_cont2_len = 2 + 0 /* 0-byte of ALPDU */;
	size_t ppdu_end_len = 2 + (alpdu_len - 10) /* remaining of ALPDU */;

	uint8_t frag_id = 2;
	uint8_t use_alpdu_crc = 0;
	uint8_t alpdu_label_type = 0;

	size_t fpdu_label_len = 3;
	unsigned char fpdu_label[fpdu_label_len];

	unsigned char fpdu1[] = {
		0x00, 0x01, 0x02, /* payload label */
		(1 << 7) | (0 << 6) | (((ppdu_start_len - 2) >> 5) & 0x3f), /* 1st PPDU byte */
		(((ppdu_start_len - 2) & 0x1f) << 3) | frag_id,             /* 2nd PPDU byte */
		(use_alpdu_crc << 7) | ((alpdu_len >> 5) & 0x7f),           /* 3rd PPDU byte */
		((alpdu_len & 0x1f) << 3) | (alpdu_label_type << 1) | conf.allow_ptype_omission, /* 4th PPDU byte */
		0x08, 0x00,                                     /* ALPDU protocol type */
		0x45, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* ALPDU payload: IPv4 */
	};
	unsigned char fpdu2[] = {
		0x00, 0x01, 0x02, /* payload label */
		(0 << 7) | (0 << 6) | (((ppdu_cont1_len - 2) >> 5) & 0x3f), /* 1st PPDU byte */
		(((ppdu_cont1_len - 2) & 0x1f) << 3) | frag_id,             /* 2nd PPDU byte */
	};
	unsigned char fpdu3[] = {
		0x00, 0x01, 0x02, /* payload label */
		(0 << 7) | (0 << 6) | (((ppdu_cont2_len - 2) >> 5) & 0x3f), /* 1st PPDU byte */
		(((ppdu_cont2_len - 2) & 0x1f) << 3) | frag_id,             /* 2nd PPDU byte */
	};
	unsigned char fpdu4[] = {
		0x00, 0x01, 0x02, /* payload label */
		(0 << 7) | (1 << 6) | (((ppdu_end_len - 2) >> 5) & 0x3f), /* 1st PPDU byte */
		(((ppdu_end_len - 2) & 0x1f) << 3) | frag_id,             /* 2nd PPDU byte */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0x42,                                           /* IPv4 payload */
		0x00,                                           /* ALPDU trailer */
	};

	const size_t sdu_buffer_len = 100;
	unsigned char sdu_buffer[sdu_buffer_len];
	size_t sdus_max_nr = 1;
	struct rle_sdu sdus[sdus_max_nr];
	size_t sdus_nr = 0;

	struct rle_receiver *receiver;
	enum rle_decap_status ret_decap;

	PRINT_TEST("Support for 0-byte ALPDU fragments");

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto error;
	}

	sdus[0].buffer = sdu_buffer;
	sdus[0].size = sdu_buffer_len;
	sdus[0].protocol_type = 0x0000;

	printf("\tdecapsulate %zu-byte FPDU\n", sizeof(fpdu1));
	ret_decap = rle_decapsulate(receiver, fpdu1, sizeof(fpdu1),
	                            sdus, sdus_max_nr, &sdus_nr,
	                            fpdu_label, fpdu_label_len);
	if (ret_decap != RLE_DECAP_OK) {
		PRINT_ERROR("Decap does not return OK.");
		goto free_receiver;
	}
	if (sdus_nr != 0) {
		PRINT_ERROR("%zu SDUs decapsulated while 0 expected", sdus_nr);
		goto free_receiver;
	}

	printf("\tdecapsulate %zu-byte FPDU\n", sizeof(fpdu2));
	ret_decap = rle_decapsulate(receiver, fpdu2, sizeof(fpdu2),
	                            sdus, sdus_max_nr, &sdus_nr,
	                            fpdu_label, fpdu_label_len);
	if (ret_decap != RLE_DECAP_OK) {
		PRINT_ERROR("Decap does not return OK.");
		goto free_receiver;
	}
	if (sdus_nr != 0) {
		PRINT_ERROR("%zu SDUs decapsulated while 0 expected", sdus_nr);
		goto free_receiver;
	}

	printf("\tdecapsulate %zu-byte FPDU\n", sizeof(fpdu3));
	ret_decap = rle_decapsulate(receiver, fpdu3, sizeof(fpdu3),
	                            sdus, sdus_max_nr, &sdus_nr,
	                            fpdu_label, fpdu_label_len);
	if (ret_decap != RLE_DECAP_OK) {
		PRINT_ERROR("Decap does not return OK.");
		goto free_receiver;
	}
	if (sdus_nr != 0) {
		PRINT_ERROR("%zu SDUs decapsulated while 0 expected", sdus_nr);
		goto free_receiver;
	}

	printf("\tdecapsulate %zu-byte FPDU\n", sizeof(fpdu4));
	ret_decap = rle_decapsulate(receiver, fpdu4, sizeof(fpdu4),
	                            sdus, sdus_max_nr, &sdus_nr,
	                            fpdu_label, fpdu_label_len);
	if (ret_decap != RLE_DECAP_OK) {
		PRINT_ERROR("Decap does not return OK.");
		goto free_receiver;
	}
	if (sdus_nr != 1) {
		PRINT_ERROR("%zu SDUs decapsulated while 1 expected", sdus_nr);
		goto free_receiver;
	}

	assert(rle_receiver_stats_get_counter_sdus_lost(receiver, frag_id) == 0);
	assert(rle_receiver_stats_get_counter_sdus_dropped(receiver, frag_id) == 0);
	assert(rle_receiver_stats_get_counter_bytes_dropped(receiver, frag_id) == 0);

	is_success = true;

free_receiver:
	rle_receiver_destroy(&receiver);
error:
	PRINT_TEST_STATUS(is_success);
	printf("\n");
	return is_success;
}

bool test_decap_ppdu_2_bytes(void)
{
	bool is_success = false;

	const struct rle_config conf = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 1,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	size_t sdu_len = 0; /* 0-byte SDU */
	size_t protocol_type_len = 0; /* omitted protocol type */
	size_t trailer_len = 0; /* no fragmentation */

	size_t alpdu_len = protocol_type_len + sdu_len + trailer_len;
	size_t ppdu_len = 2 + alpdu_len;

	uint8_t alpdu_label_type = 0;

	size_t fpdu_label_len = 3;
	unsigned char fpdu_label[fpdu_label_len];

	unsigned char fpdu[] = {
		0x00, 0x01, 0x02, /* payload label */
		(1 << 7) | (1 << 6) | (((ppdu_len - 2) >> 5) & 0x3f), /* 1st PPDU byte */
		(((ppdu_len - 2) & 0x1f) << 3) | (alpdu_label_type << 1) | conf.allow_ptype_omission, /* 2nd PPDU byte */
		/* empty ALPDU header */
		/* 0-byte SDU */
	};

	const size_t sdu_buffer_len = 100;
	unsigned char sdu_buffer[sdu_buffer_len];
	size_t sdus_max_nr = 1;
	struct rle_sdu sdus[sdus_max_nr];
	size_t sdus_nr = 0;

	struct rle_receiver *receiver;
	enum rle_decap_status ret_decap;

	PRINT_TEST("Support for 2-byte PPDU fragments");

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto error;
	}

	sdus[0].buffer = sdu_buffer;
	sdus[0].size = sdu_buffer_len;
	sdus[0].protocol_type = 0x0000;

	printf("\tdecapsulate %zu-byte FPDU\n", sizeof(fpdu));
	ret_decap = rle_decapsulate(receiver, fpdu, sizeof(fpdu),
	                            sdus, sdus_max_nr, &sdus_nr,
	                            fpdu_label, fpdu_label_len);
	if (ret_decap != RLE_DECAP_OK) {
		PRINT_ERROR("Decap does not return OK.");
		goto free_receiver;
	}
	if (sdus_nr != 1) {
		PRINT_ERROR("%zu SDUs decapsulated while 1 expected", sdus_nr);
		goto free_receiver;
	}
	assert(sdus[0].size == 0);
	assert(sdus[0].protocol_type == 0x0800);

	is_success = true;

free_receiver:
	rle_receiver_destroy(&receiver);
error:
	PRINT_TEST_STATUS(is_success);
	printf("\n");
	return is_success;
}

bool test_decap_wrong_crc(void)
{
	bool is_success = false;

	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 98;
	const size_t fpdus_max_nr = 2;
	unsigned char fpdu[fpdus_max_nr][fpdu_length];

	const uint8_t frag_id = 0;

	const size_t sdu_length = 100;
	unsigned char buffer_in[sdu_length];
	unsigned char buffer_out[sdu_length];

	struct rle_sdu sdu = {
		.buffer = buffer_in,
		.size = sdu_length
	};

	sdu.buffer[0] = 0x40; /* IPv4 */

	size_t sdus_nr = 0;
	const size_t sdus_max_nr = 2;
	struct rle_sdu sdus[sdus_max_nr];
	sdus[0].buffer = buffer_out;
	sdus[0].size = sdu_length;

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

	size_t fpdus_nr;
	size_t fpdu_current_pos;
	size_t fpdu_remaining_size;
	const size_t payload_label_size = 0;
	unsigned char *payload_label = NULL;

	/* ensure SDU is larger than burst so that test is meaningful */
	assert(sdu_length > fpdu_length);

	PRINT_TEST("Wrong CRC");

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver.");
		goto error;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter.");
		goto free_receiver;
	}

	/* encapsulate one SDU */
	printf("encapsulate %zu-byte SDU:\n", sdu.size);
	ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap does not return OK.");
		goto free_transmitter;
	}

	fpdus_nr = 0;
	fpdu_current_pos = 0;
	fpdu_remaining_size = fpdu_length;
	printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);
	while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
		unsigned char *ppdu;
		size_t ppdu_length = 0;

		printf("\t\tfragment SDU into a max %zu-byte chunk\n",
		       fpdu_remaining_size);
		ret_frag = rle_fragment(transmitter, frag_id, fpdu_remaining_size,
		                        &ppdu, &ppdu_length);
		if (ret_frag == RLE_FRAG_ERR_BURST_TOO_SMALL) {
			printf("\t\tFPDU too small for fragment, wait for the next one\n");
			printf("\t\tpad FPDU on %zu bytes\n", fpdu_remaining_size);
			rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
			assert(fpdus_nr < fpdus_max_nr);
			fpdus_nr++;
			fpdu_current_pos = 0;
			fpdu_remaining_size = fpdu_length;
			printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);
		} else if (ret_frag != RLE_FRAG_OK) {
			PRINT_ERROR("Frag does not return OK.");
			goto free_transmitter;
		} else {
			printf("\t\t%zu-byte PPDU fragment generated\n", ppdu_length);

			printf("\t\tpack PPDU into a %zu-byte FPDU with %zu bytes remaining\n",
			       fpdu_length, fpdu_remaining_size);
			ret_pack = rle_pack(ppdu, ppdu_length,
			                    payload_label, payload_label_size,
			                    fpdu[fpdus_nr], &fpdu_current_pos, &fpdu_remaining_size);
			if (ret_pack != RLE_PACK_OK) {
				PRINT_ERROR("Pack does not return OK.");
				goto free_transmitter;
			}
			printf("\t\t%zu/%zu bytes free in FPDU\n",
			       fpdu_remaining_size, fpdu_length);
		}
	}

	/* flush the last FPDU if needed */
	if (fpdu_current_pos > 0) {
		rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
		assert(fpdus_nr < fpdus_max_nr);
		fpdus_nr++;
	}

	assert(fpdus_nr == 2);

	/* damage the CRC */
	assert(fpdu_current_pos >= 4);
	fpdu[1][fpdu_current_pos - 1] = ~(fpdu[1][fpdu_current_pos - 1]);
	fpdu[1][fpdu_current_pos - 2] = ~(fpdu[1][fpdu_current_pos - 2]);
	fpdu[1][fpdu_current_pos - 3] = ~(fpdu[1][fpdu_current_pos - 3]);
	fpdu[1][fpdu_current_pos - 4] = ~(fpdu[1][fpdu_current_pos - 4]);

	/* decapsulate all the generated FPDUs */
	printf("decapsulate FPDU #1\n");
	ret_decap = rle_decapsulate(receiver, fpdu[0], fpdu_length,
	                            sdus, sdus_max_nr, &sdus_nr,
	                            payload_label, payload_label_size);
	if (ret_decap != RLE_DECAP_OK) {
		PRINT_ERROR("Decap does not return OK.");
		goto free_transmitter;
	}
	assert(sdus_nr == 0);
	assert(rle_receiver_stats_get_counter_sdus_lost(receiver, frag_id) == 0);
	assert(rle_receiver_stats_get_counter_sdus_dropped(receiver, frag_id) == 0);
	assert(rle_receiver_stats_get_counter_bytes_dropped(receiver, frag_id) == 0);

	printf("decapsulate FPDU #2\n");
	ret_decap = rle_decapsulate(receiver, fpdu[1], fpdu_length,
	                            sdus, sdus_max_nr, &sdus_nr,
	                            payload_label, payload_label_size);
	if (ret_decap != RLE_DECAP_ERR) {
		PRINT_ERROR("Decap failed to report problem");
		goto free_transmitter;
	}
	assert(sdus_nr == 0);
	assert(rle_receiver_stats_get_counter_sdus_lost(receiver, frag_id) == 1);
	assert(rle_receiver_stats_get_counter_sdus_dropped(receiver, frag_id) == 1);
	assert(rle_receiver_stats_get_counter_bytes_dropped(receiver, frag_id) ==
	       (4 /* PPDU START */ + 2 /* PPDU CONT */ +
	        2 /* proto */ + sdu_length + 4 /* CRC */));


	is_success = true;

free_transmitter:
	rle_transmitter_destroy(&transmitter);
free_receiver:
	rle_receiver_destroy(&receiver);
error:
	PRINT_TEST_STATUS(is_success);
	printf("\n");
	return is_success;
}

bool test_decap_interlaced_reassembly(void)
{
	bool is_success = false;
	size_t i;

	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	const size_t fpdu_length = 45;
	const size_t fpdus_max_nr = RLE_MAX_FRAG_NUMBER * 3;
	unsigned char fpdu[fpdus_max_nr][fpdu_length];

	uint8_t frag_id;

	const size_t sdu_length = 100;
	unsigned char buffer_in[sdu_length];
	unsigned char buffer_out[sdu_length];

	struct rle_sdu sdu = {
		.buffer = buffer_in,
		.size = sdu_length
	};

	sdu.buffer[0] = 0x40; /* IPv4 */

	size_t sdus_total_nr;
	const size_t sdus_max_nr = RLE_MAX_FRAG_NUMBER;
	struct rle_sdu sdus[sdus_max_nr];
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		sdus[i].buffer = buffer_out;
		sdus[i].size = sdu_length;
	}

	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

	size_t fpdus_nr;
	size_t fpdu_current_pos;
	size_t fpdu_remaining_size;
	const size_t payload_label_size = 0;
	unsigned char *payload_label = NULL;

	/* ensure SDU is larger than burst so that test is meaningful */
	assert(sdu_length > fpdu_length);

	PRINT_TEST("Interlaced reassembly");

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver.");
		goto error;
	}

	transmitter = rle_transmitter_new(&conf);
	if (transmitter == NULL) {
		PRINT_ERROR("Error allocating transmitter.");
		goto free_receiver;
	}

	fpdus_nr = 0;
	fpdu_current_pos = 0;
	fpdu_remaining_size = fpdu_length;

	/* encapsulate SDUs and generate fragments, with fragmentation contexts
	 * interlaced */
	for (i = 0; i < 3 /* 3 PPDU fragments */; i++) {
		for (frag_id = 0; frag_id < RLE_MAX_FRAG_NUMBER; frag_id++) {
			unsigned char *ppdu;
			size_t ppdu_length = 0;

			/* encapsulation only the first loop */
			if (i == 0) {
				printf("encapsulate %zu-byte SDU #%u in fragmentation context %u\n",
				       sdu.size, frag_id + 1, frag_id);
				ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
				if (ret_encap != RLE_ENCAP_OK) {
					PRINT_ERROR("Encap does not return OK.");
					goto free_transmitter;
				}
			}

			printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);

			printf("\t\tfragment SDU into a max %zu-byte chunk\n",
			       fpdu_remaining_size);
			ret_frag = rle_fragment(transmitter, frag_id, fpdu_remaining_size,
			                        &ppdu, &ppdu_length);
			if (ret_frag == RLE_FRAG_ERR_BURST_TOO_SMALL) {
				printf("\t\tFPDU too small for fragment, wait for the next one\n");
				printf("\t\tpad FPDU on %zu bytes\n", fpdu_remaining_size);
				rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
				assert(fpdus_nr < fpdus_max_nr);
				fpdus_nr++;
				fpdu_current_pos = 0;
				fpdu_remaining_size = fpdu_length;
				printf("\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);
			} else if (ret_frag != RLE_FRAG_OK) {
				PRINT_ERROR("Frag does not return OK.");
				goto free_transmitter;
			} else {
				printf("\t\t%zu-byte PPDU fragment generated\n", ppdu_length);

				printf("\t\tpack PPDU into a %zu-byte FPDU with %zu bytes remaining\n",
				       fpdu_length, fpdu_remaining_size);
				ret_pack = rle_pack(ppdu, ppdu_length,
				                    payload_label, payload_label_size,
				                    fpdu[fpdus_nr], &fpdu_current_pos, &fpdu_remaining_size);
				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto free_transmitter;
				}
				printf("\t\t%zu/%zu bytes free in FPDU\n",
				       fpdu_remaining_size, fpdu_length);

				if (fpdu_remaining_size < 21) {
					printf("\t\tpad FPDU on %zu bytes\n", fpdu_remaining_size);
					rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
					assert(fpdus_nr < fpdus_max_nr);
					fpdus_nr++;
					fpdu_current_pos = 0;
					fpdu_remaining_size = fpdu_length;
					printf("\t\tschedule SDU in FPDU #%zu\n", fpdus_nr + 1);
				}
			}
		}
	}

	/* flush the last FPDU if needed */
	if (fpdu_current_pos > 0) {
		rle_pad(fpdu[fpdus_nr], fpdu_current_pos, fpdu_remaining_size);
		assert(fpdus_nr < fpdus_max_nr);
		fpdus_nr++;
	}

	/* decapsulate all the generated FPDUs */
	sdus_total_nr = 0;
	for (i = 0; i < fpdus_nr; i++) {
		size_t sdus_nr = 0;

		printf("decapsulate FPDU #%zu\n", i + 1);
		ret_decap = rle_decapsulate(receiver, fpdu[i], fpdu_length,
		                            sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);
		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto free_transmitter;
		}
		printf("\t%zu SDUs decapsulated\n", sdus_nr);
		sdus_total_nr += sdus_nr;
	}

	if (sdus_total_nr != RLE_MAX_FRAG_NUMBER) {
		PRINT_ERROR("%zu SDUs decapsulated while %d SDUs encapsulated",
		            sdus_total_nr, RLE_MAX_FRAG_NUMBER);
		goto free_transmitter;
	}

	for (frag_id = 0; frag_id < RLE_MAX_FRAG_NUMBER; frag_id++) {
		assert(rle_receiver_stats_get_counter_sdus_received(receiver, frag_id) == 1);
		assert(rle_receiver_stats_get_counter_bytes_received(receiver, frag_id) ==
		       (4 /* PPDU START */ + 2 * 2 /* 2 PPDU CONT */ +
		        2 /* proto */ + sdu_length + 1 /* seqnum */));
		assert(rle_receiver_stats_get_counter_sdus_reassembled(receiver, frag_id) == 1);
		assert(rle_receiver_stats_get_counter_bytes_reassembled(receiver, frag_id) == sdu_length);
		assert(rle_receiver_stats_get_counter_sdus_lost(receiver, frag_id) == 0);
		assert(rle_receiver_stats_get_counter_sdus_dropped(receiver, frag_id) == 0);
		assert(rle_receiver_stats_get_counter_bytes_dropped(receiver, frag_id) == 0);
	}

	is_success = true;

free_transmitter:
	rle_transmitter_destroy(&transmitter);
free_receiver:
	rle_receiver_destroy(&receiver);
error:
	PRINT_TEST_STATUS(is_success);
	printf("\n");
	return is_success;
}


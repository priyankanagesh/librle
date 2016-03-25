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

static void print_modules_stats(void)
{
	print_transmitter_stats();
	print_receiver_stats();
	return;
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
	        sdu_length, frag_id, conf.use_ptype_omission == 0 ?
	        (conf.use_compressed_ptype == 0 ?  "uncompressed" : "compressed") :
	        (conf.implicit_protocol_type == 0x00) ?  "non omitted" :
	        (conf.implicit_protocol_type == 0x30 ? "ip omitted" : "omitted"),
	        conf.use_alpdu_crc == 0 ? "SeqNo" : "CRC",
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
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

	const size_t fpdu_length = 1000; /* Arbitrarly */
	unsigned char fpdu[fpdu_length];
	size_t fpdu_iterator = 0;
	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		fpdu[fpdu_iterator] = '\0';
	}
	size_t fpdu_current_pos = 0;
	size_t fpdu_remaining_size = fpdu_length;
	size_t number_of_sdus_iterator = 0;

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
			unsigned char label[label_length];
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
		unsigned char alloc_label[label_length];
		unsigned char *label = NULL;
		if (label_length != 0) {
			label = alloc_label;
			memcpy((void *)alloc_label, (const void *)payload_initializer, label_length);
		}

		for (sdu_iterator = 0; sdu_iterator < sdus_max_nr; ++sdu_iterator) {
			sdus[sdu_iterator].size = (size_t)RLE_MAX_PDU_SIZE;
			sdus[sdu_iterator].buffer = calloc(sdus[sdu_iterator].size, sizeof(unsigned char));
			if (sdus[sdu_iterator].buffer == NULL) {
				PRINT_ERROR("Error during SDUs buffer allocation, before decapsulation.");
				goto free_sdus;
			}
		}

		ret_decap = rle_decapsulate(receiver, (const unsigned char *)fpdu, fpdu_length, sdus,
		                            sdus_max_nr, &sdus_nr, label, label_length);

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

	print_modules_stats();

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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_receiver *receiver;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto exit_label;
	}

	{
		const size_t fpdu_length = 0;
		unsigned char fpdu[fpdu_length];

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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_receiver *receiver;

	receiver = rle_receiver_new(&conf);
	if (receiver == NULL) {
		PRINT_ERROR("Error allocating receiver");
		goto exit_label;
	}

	{
		const size_t sdus_max_nr = 0;
		struct rle_sdu sdus[sdus_max_nr];

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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
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
	bool output = false;

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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

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

	const size_t fpdu_length = 5000;
	const size_t nb_fpdu = 3;
	unsigned char fpdu[nb_fpdu][fpdu_length];
	size_t fpdu_iterator = 0;

	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		size_t it;
		for (it = 0; it < nb_fpdu; ++it) {
			fpdu[it][fpdu_iterator] = '\0';
		}
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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

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

			ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
			if (ret_encap != RLE_ENCAP_OK) {
				PRINT_ERROR("Encap does not return OK.");
				goto exit_label;
			}

			while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
				const size_t burst_size = 30;
				unsigned char *ppdu;
				size_t ppdu_length = 0;

				ret_frag = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &ppdu_length);

				if (ret_frag != RLE_FRAG_OK) {
					PRINT_ERROR("Frag does not return OK.");
					goto exit_label;
				}

				ret_pack = rle_pack(ppdu, ppdu_length, payload_label, payload_label_size, fpdu[it],
				                    &fpdu_current_pos, &fpdu_remaining_size);

				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto exit_label;
				}
			}
		}

		/* Modifying the seq no of the second FPDU. */
		fpdu[1][fpdu_current_pos - 1] += 3;
		/* To restart decapsulation. */
		fpdu[2][fpdu_current_pos - 1] = fpdu[1][fpdu_current_pos - 1] + 1;

		for (it = 0; it < nb_fpdu; ++ it) {
			rle_pad(fpdu[it], fpdu_current_pos, fpdu_remaining_size);
		}

		ret_decap = rle_decapsulate(receiver, fpdu[0], fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);

		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, fpdu[1], fpdu_length, sdus, sdus_max_nr, &sdus_nr,
                                  payload_label, payload_label_size);

		if (ret_decap != RLE_DECAP_ERR) {
			PRINT_ERROR("Decap does not drop.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, fpdu[2], fpdu_length, sdus, sdus_max_nr, &sdus_nr,
                                  payload_label, payload_label_size);

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
				.implicit_protocol_type = 0x0d,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 0
			};

			/* Configuration for compressed protocol type */
			struct rle_config conf_comp = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 1,
				.use_ptype_omission = 0
			};

			/* Configuration for omitted protocol type */
			struct rle_config conf_omitted = {
				.implicit_protocol_type = default_ptype,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Special test for IPv4 and v6 */
			struct rle_config conf_omitted_ip = {
				.implicit_protocol_type = 0x30,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Configuration for non omitted protocol type in omission conf */
			struct rle_config conf_not_omitted = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 0,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Configuration for uncompressed protocol type with CRC */
			struct rle_config conf_uncomp_crc = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 1,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 0
			};

			/* Configuration for compressed protocol type with CRC */
			struct rle_config conf_comp_crc = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 1,
				.use_compressed_ptype = 1,
				.use_ptype_omission = 0
			};

			/* Configuration for omitted protocol type with CRC */
			struct rle_config conf_omitted_crc = {
				.implicit_protocol_type = default_ptype,
				.use_alpdu_crc = 1,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Special test for IPv4 and v6 */
			struct rle_config conf_omitted_ip_crc = {
				.implicit_protocol_type = 0x30,
				.use_alpdu_crc = 1,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
			};

			/* Configuration for non omitted protocol type in omission conf with CRC */
			struct rle_config conf_not_omitted_crc = {
				.implicit_protocol_type = 0x00,
				.use_alpdu_crc = 1,
				.use_compressed_ptype = 0,
				.use_ptype_omission = 1
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
							}
						}
					}
				}
			}
		}
	}

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

	const size_t fpdu_length = 5000;
	const size_t nb_fpdu = 3;
	unsigned char fpdu[nb_fpdu][fpdu_length];
	size_t fpdu_iterator = 0;

	for (fpdu_iterator = 0; fpdu_iterator < fpdu_length; ++fpdu_iterator) {
		size_t it;
		for (it = 0; it < nb_fpdu; ++it) {
			fpdu[it][fpdu_iterator] = '\0';
		}
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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

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

			ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);
			if (ret_encap != RLE_ENCAP_OK) {
				PRINT_ERROR("Encap does not return OK.");
				goto exit_label;
			}

			while (rle_transmitter_stats_get_queue_size(transmitter, frag_id)) {
				const size_t burst_size = 30;
				unsigned char *ppdu;
				size_t ppdu_length = 0;

				ret_frag = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &ppdu_length);

				if (ret_frag != RLE_FRAG_OK) {
					PRINT_ERROR("Frag does not return OK.");
					goto exit_label;
				}

				ret_pack = rle_pack(ppdu, ppdu_length, payload_label, payload_label_size, fpdu[it],
				                    &fpdu_current_pos, &fpdu_remaining_size);

				if (ret_pack != RLE_PACK_OK) {
					PRINT_ERROR("Pack does not return OK.");
					goto exit_label;
				}
			}
		}

		/* Modifying the seq no of the third FPDU to null */
		fpdu[2][fpdu_current_pos - 1] = 0;

		for (it = 0; it < nb_fpdu; ++ it) {
			rle_pad(fpdu[it], fpdu_current_pos, fpdu_remaining_size);
		}

		ret_decap = rle_decapsulate(receiver, fpdu[0], fpdu_length, sdus, sdus_max_nr, &sdus_nr,
		                            payload_label, payload_label_size);

		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, fpdu[1], fpdu_length, sdus, sdus_max_nr, &sdus_nr,
                                  payload_label, payload_label_size);

		if (ret_decap != RLE_DECAP_OK) {
			PRINT_ERROR("Decap does not return OK.");
			goto exit_label;
		}

		ret_decap = rle_decapsulate(receiver, fpdu[2], fpdu_length, sdus, sdus_max_nr, &sdus_nr,
                                  payload_label, payload_label_size);

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
		.implicit_protocol_type = 0x0d,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 0,
		.use_compressed_ptype = 0
	};
	struct rle_receiver *receiver;
	struct rle_transmitter *transmitter;

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


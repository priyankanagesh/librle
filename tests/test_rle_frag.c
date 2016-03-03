/**
 * @file   test_rle_frag.c
 * @brief  Body file used for the fragmentation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_frag.h"

#include "rle_transmitter.h"
#include "rle_ctx.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define GET_CONF_VALUE(x) ((x) == 1 ? "True" : "False")

/**
 * @brief         Generic fragmentation test.
 *
 *                Simply fragment an encapsulated SDU from one of the frag id of a transmitter.
 *
 * @param[in]     protocol_type            The protocol type of the SDU
 * @param[in]     conf                     Configuration of the transmitter
 * @param[in]     length                   The protocol length of the SDU to encap before frag
 * @param[in]     burst_size               The size of the burst that the fragmentation depends on
 * @param[in]     frag_id                  The fragment id
 *
 * @return        true if OK, else false.
 */
static bool test_frag(const uint16_t protocol_type,
                              const struct rle_context_configuration conf, const size_t length,
                              const size_t burst_size,
                              const uint8_t frag_id);

/**
 *  @brief         Check if a fragmentation transition is OK.
 *
 *  @param[in]     current_state       The current state.
 *  @param[in]     next_state          The future state.
 *
 *  @return        FRAG_STATUS_OK if legal transition, else FRAG_STATUS_KO.
 */
static enum check_frag_status test_check_frag_transition(const enum frag_states old_state,
                                                         const enum frag_states new_state);

/**
 *  @brief         Get the type of the fragment in the buffer
 *
 *  @param[in]     ppdu_first_octet       The first octet of the PPDU.
 *
 *  @return        the fragment type @see enum frag_states
 */
static enum frag_states test_get_fragment_type(const unsigned char ppdu_first_octet);

static void print_modules_stats(void)
{
	print_transmitter_stats();
	return;
}

static enum check_frag_status test_check_frag_transition(const enum frag_states old_state,
                                                         const enum frag_states new_state)
{
	enum check_frag_status status = FRAG_STATUS_KO; /* KO states explicitly pass silently */

	/*
	 * Possible transitions:
	 *
	 *                +-------------------------------+
	 *                |                               |
	 *                |                               v
	 *              Start -------> Continue -------> End => OK
	 *                ^            ^      |
	 *                |            |      |
	 * Uninit --------+            +------+
	 *                |
	 *                v
	 *              Comp => OK
	 */

	switch (old_state) {
	case FRAG_STATE_UNINIT:
		switch (new_state) {
		case FRAG_STATE_START:
		case FRAG_STATE_COMP:
			status = FRAG_STATUS_OK;
			break;
		default:
			break;
		}
		break;
	case FRAG_STATE_START:
	case FRAG_STATE_CONT:
		switch (new_state) {
		case FRAG_STATE_CONT:
		case FRAG_STATE_END:
			status = FRAG_STATUS_OK;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return status;
}

enum frag_states test_get_fragment_type(const unsigned char ppdu_first_octet)
{
	enum frag_states fragment_type = RLE_PDU_COMPLETE;

	if (ppdu_first_octet & 0x80) {
		if (ppdu_first_octet & 0x40) {
			fragment_type = FRAG_STATE_COMP;
		} else {
			fragment_type = FRAG_STATE_START;
		}
	} else {
		if (ppdu_first_octet & 0x40) {
			fragment_type = FRAG_STATE_END;
		} else {
			fragment_type = FRAG_STATE_CONT;
		}
	}

	return fragment_type;
}

static bool test_frag(const uint16_t protocol_type,
                              const struct rle_context_configuration conf, const size_t length,
                              const size_t burst_size,
                              const uint8_t frag_id)
{
	PRINT_TEST("protocole type 0x%04x, conf (omitted protocol type %02x, compression %s, "
	           "omission %s) with %s protection. SDU length %zu, burst sizes %zu, frag id %d",
	           protocol_type, conf.implicit_protocol_type,
	           GET_CONF_VALUE(conf.use_compressed_ptype),
	           GET_CONF_VALUE(conf.use_ptype_omission), conf.use_alpdu_crc == 1 ? "CRC" : "Seq No",
	           length, burst_size, frag_id);
	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	transmitter = rle_transmitter_new(&conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));
	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);

	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap error in frag test.");
		goto exit_label;
	}

	{
		enum rle_frag_status ret_frag = RLE_FRAG_ERR;
		enum check_frag_status frag_status = FRAG_STATUS_KO;
		size_t frag_size = burst_size;
		unsigned char *ppdu;
		size_t real_size;
		enum frag_states old_state = FRAG_STATE_UNINIT;
		enum frag_states new_state;
		size_t queue_size = rle_transmitter_stats_get_queue_size(transmitter, frag_id);

		while (queue_size != 0) {
			if ((sizeof(rle_ppdu_header_cont_end_t) + queue_size) < frag_size) {
				frag_size = queue_size + sizeof(rle_ppdu_header_cont_end_t);
			}

			ret_frag = rle_fragment(transmitter, frag_id, frag_size, &ppdu, &real_size);

			if (ret_frag != RLE_FRAG_OK) {
				PRINT_ERROR("fragmentation error.");
				goto exit_label;
			}

			new_state = test_get_fragment_type(ppdu[0]);

			frag_status = test_check_frag_transition(old_state, new_state);

			if (frag_status != FRAG_STATUS_OK) {
				PRINT_ERROR("Check integrity.");
				goto exit_label;
			}

			old_state = new_state;
			queue_size = rle_transmitter_stats_get_queue_size(transmitter, frag_id);
		}

	}

	output = true;

exit_label:

	print_modules_stats();

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_frag_null_transmitter(void)
{
	bool output = false;
	const uint16_t protocol_type = 0x0800; /* Arbitrarly */
	const uint8_t frag_id = 0; /* Arbitrarly */
	const size_t sdu_length = 100;
	const size_t burst_size = 30;
	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = 0,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	sdu.buffer = calloc(sdu_length, sizeof(unsigned char));
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);
	sdu.size = sdu_length;

	{
		unsigned char *ppdu;
		size_t real_size;
		enum rle_frag_status status = RLE_FRAG_ERR;

		status = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &real_size);
		if (status != RLE_FRAG_ERR_NULL_TRMT) {
			PRINT_ERROR("Fragmentation on null transmitter.");
			goto exit_label;
		}
	}

	output = true;

exit_label:

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}
bool test_frag_too_small(void)
{
	PRINT_TEST("Frag too small.");
	bool output = false;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;

	const uint16_t protocol_type = 0x0800;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x0000,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	const size_t sdu_length = 100;
	const size_t burst_size = 2;
	const uint8_t frag_id = 1;

	enum rle_frag_status status = RLE_FRAG_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = sdu_length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	transmitter = rle_transmitter_new(&conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));

	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	ret_encap = rle_encapsulate(transmitter, &sdu, frag_id);

	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap error in frag test.");
		goto exit_label;
	}

	{
		unsigned char *ppdu;
		size_t real_size;
		if (rle_transmitter_stats_get_queue_size(transmitter, frag_id) == 0) {
			PRINT_ERROR("Nothing to frag");
			goto exit_label;
		}

		status = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &real_size);
	}

	output = (status == RLE_FRAG_ERR_BURST_TOO_SMALL);

exit_label:

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_frag_null_context(void)
{
	PRINT_TEST("Null context");
	bool output = false;
	/* enum rle_encap_status ret_encap = RLE_ENCAP_ERR;*/

	const uint16_t protocol_type = 0x0800;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x0000,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	const size_t sdu_length = 100; /* We could remove all the SDU manipulation parts, but I want to
	                                * make a test as realist as possible, here with a forgotten
	                                * encap leading to a null context. */
	const size_t burst_size = 50;
	const uint8_t frag_id = 1;

	enum rle_frag_status status = RLE_FRAG_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = sdu_length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	transmitter = rle_transmitter_new(&conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));

	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}

	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	{
		unsigned char *ppdu;
		size_t real_size;

		status = rle_fragment(transmitter, frag_id, burst_size, &ppdu, &real_size);
	}

	output = (status == RLE_FRAG_ERR_CONTEXT_IS_NULL);

exit_label:

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_frag_real_world(void)
{
	PRINT_TEST("Fragmentation with realistic values and Configuration.");
	bool output = true;
	const uint16_t protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP; /* IPv4 Arbitrarily. */
	const uint8_t frag_id = 1;

	const struct rle_context_configuration conf = {
		.implicit_protocol_type = RLE_PROTO_TYPE_IPV4_COMP,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 1
	};

	const size_t sdu_lengths[] = { 100, 1500 };
	size_t sdu_lengths_it;

	for (sdu_lengths_it = 0; sdu_lengths_it < sizeof(sdu_lengths) / sizeof *(sdu_lengths); 
			++sdu_lengths_it) {
		const size_t sdu_length = sdu_lengths[sdu_lengths_it];
		const size_t burst_sizes[] =
		{ 14, 24, 38, 51, 55, 59, 62, 69, 84, 85, 93, 96, 100, 115, 123, 130, 144, 170, 175,
		  188, 264, 298, 355, 400, 438, 444, 539, 599 };
		size_t burst_sizes_it;
		for (burst_sizes_it = 0; burst_sizes_it < sizeof(burst_sizes) / sizeof *(burst_sizes); 
				++burst_sizes_it) {
			const size_t burst_size = burst_sizes[burst_sizes_it];
			const bool ret = test_frag(protocol_type, conf, sdu_length, burst_size, frag_id);
			if (ret == false) {
				/* Only one fail means the encap test fail. */
				output = false;
			}
		}
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_frag_all(void)
{
	PRINT_TEST("Test all the general fragmentation cases.");
	bool output = true;
	uint16_t protocol_type = 0x0800; /* IPv4 Arbitrarily. */
	uint8_t frag_id = 1;
	const size_t sdu_length = 100;
	/* Those 4 burst sizes allow us to test all type of fragis and transitions.
	 * 30  -> START - CONT - CONT - END
	 * 40  -> START - CONT - END
	 * 80  -> START - END
	 * 120 -> COMP */
	const size_t burst_sizes[4] = { 30, 40, 80, 120 };
	size_t burst_iterator = 0;

	for (burst_iterator = 0; burst_iterator < 4; ++burst_iterator) {
		struct rle_context_configuration conf_uncomp = {
			.implicit_protocol_type = 0x0000,
			.use_alpdu_crc = 0,
			.use_compressed_ptype = 0,
			.use_ptype_omission = 0
		};

		/* Configuration for compressed protocol type */
		struct rle_context_configuration conf_comp = {
			.implicit_protocol_type = 0x0000,
			.use_alpdu_crc = 0,
			.use_compressed_ptype = 1,
			.use_ptype_omission = 0
		};

		/* Configuration for omitted protocol type */
		struct rle_context_configuration conf_omitted = {
			.implicit_protocol_type = protocol_type,
			.use_alpdu_crc = 0,
			.use_compressed_ptype = 0,
			.use_ptype_omission = 1
		};

		/* Configurations */
		struct rle_context_configuration *confs[] = {
			&conf_uncomp,
			&conf_comp,
			&conf_omitted,
			NULL
		};

		/* Configuration iterator */
		struct rle_context_configuration **conf;

		/* We launch the test on each configuration. All the cases then are test. */
		for (conf = confs; *conf; ++conf) {
			const bool ret =
			        test_frag(protocol_type, **conf, sdu_length,
			                  burst_sizes[burst_iterator], frag_id);
			if (ret == false) {
				/* Only one fail means the encap test fail. */
				output = false;
			}
		}

		/* With CRC. */
		for (conf = confs; *conf; ++conf) {
			(**conf).use_alpdu_crc = 1;
			const bool ret =
			        test_frag(protocol_type, **conf, sdu_length,
			                  burst_sizes[burst_iterator], frag_id);
			if (ret == false) {
				/* Only one fail means the encap test fail. */
				output = false;
			}
		}
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

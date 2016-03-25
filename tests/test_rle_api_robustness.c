/**
 * @file   test_rle_api_robustness.c
 * @brief  Run robustness tests on the RLE public API
 * @author Didier Barvaux
 * @date   03/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_api_robustness.h"

#include "rle.h"
#include "header.h"

#include <assert.h>
#include <string.h>

/**
 * @brief Test the robustness of the transmitter API
 *
 * @return  true if the test is OK, false if KO
 */
bool test_rle_api_robustness_transmitter(void)
{
	struct rle_config rle_config_ok = {
		.implicit_protocol_type = 0x30,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 1,
		.use_compressed_ptype = 1,
	};
	struct rle_config rle_config;
	struct rle_transmitter *rle_transmitter;
	size_t i;

	printf("test robustness of RLE transmitter\n");
	printf("\ttest rle_transmitter_new()\n");

	/* NULL config */
	printf("\t\trle_transmitter_new() with NULL config\n");
	rle_transmitter = rle_transmitter_new(NULL);
	assert(rle_transmitter == NULL);

	/* all possible implicit_protocol_type values */
	printf("\t\trle_transmitter_new() with different implicit_protocol_type\n");
	rle_config = rle_config_ok;
	for (i = 0x00; i <= 0xff; i++) {
		rle_config.implicit_protocol_type = i;
		rle_transmitter = rle_transmitter_new(&rle_config);
		if (i == 0x31) {
			/* compressed VLAN without protocol type field is not supported yet */
			assert(rle_transmitter == NULL);
		} else {
			assert(rle_transmitter != NULL);
			rle_transmitter_destroy(&rle_transmitter);
			assert(rle_transmitter == NULL);
		}
	}

	/* different valid and invalid values for use_alpdu_crc */
	printf("\t\trle_transmitter_new() with different use_alpdu_crc\n");
	rle_config = rle_config_ok;
	rle_config.use_alpdu_crc = 0;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_config.use_alpdu_crc = 1;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_config.use_alpdu_crc = -1;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	rle_config.use_alpdu_crc = 2;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);

	/* different valid and invalid values for use_ptype_omission */
	printf("\t\trle_transmitter_new() with different use_ptype_omission\n");
	rle_config = rle_config_ok;
	rle_config.use_ptype_omission = 0;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_config.use_ptype_omission = 1;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_config.use_ptype_omission = -1;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	rle_config.use_ptype_omission = 2;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);

	/* different valid and invalid values for use_compressed_ptype */
	printf("\t\trle_transmitter_new() with different use_compressed_ptype\n");
	rle_config = rle_config_ok;
	rle_config.use_compressed_ptype = 0;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_config.use_compressed_ptype = 1;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_config.use_compressed_ptype = -1;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);
	rle_config.use_compressed_ptype = 2;
	rle_transmitter = rle_transmitter_new(&rle_config);
	assert(rle_transmitter != NULL);
	rle_transmitter_destroy(&rle_transmitter);

	/* nominal case, valid config */
	printf("\t\trle_transmitter_new() with valid config\n");
	rle_transmitter = rle_transmitter_new(&rle_config_ok);
	assert(rle_transmitter != NULL);

	/* encapsulate one SDU */
	printf("\ttest rle_encapsulate()\n");
	{
		enum rle_encap_status encap_status;
		unsigned char sdu[] = "\x45\x01\x02\x03"; /* 1st byte shall be valid IPv4 for reassembly test */
		struct rle_sdu rle_sdu = {
			.buffer = sdu,
			.size = sizeof(sdu) - 1,
			.protocol_type = RLE_PROTO_TYPE_IPV4_UNCOMP,
		};
		size_t frag_id = 0;

		/* NULL parameters */
		printf("\t\trle_encapsulate() with NULL parameters\n");
		encap_status = rle_encapsulate(NULL, &rle_sdu, frag_id);
		assert(encap_status == RLE_ENCAP_ERR_NULL_TRMT);
		encap_status = rle_encapsulate(rle_transmitter, NULL, frag_id);
		assert(encap_status == RLE_ENCAP_ERR);

		/* too short/large SDUs */
		printf("\t\trle_encapsulate() with too short/large SDUs\n");
		rle_sdu.size = 0;
		encap_status = rle_encapsulate(rle_transmitter, &rle_sdu, RLE_MAX_FRAG_ID);
		assert(encap_status == RLE_ENCAP_ERR_SDU_TOO_BIG);
		rle_sdu.size = RLE_MAX_PDU_SIZE + 1;
		encap_status = rle_encapsulate(rle_transmitter, &rle_sdu, RLE_MAX_FRAG_ID);
		assert(encap_status == RLE_ENCAP_ERR_SDU_TOO_BIG);
		rle_sdu.size = sizeof(sdu) - 1;

		/* use all contexts */
		printf("\t\trle_encapsulate() with different context IDs\n");
		for (frag_id = 0x00; frag_id <= 0xff; frag_id++) {
			encap_status = rle_encapsulate(rle_transmitter, &rle_sdu, frag_id);
			if (frag_id < RLE_MAX_FRAG_NUMBER) {
				assert(encap_status == RLE_ENCAP_OK);
			} else {
				assert(encap_status == RLE_ENCAP_ERR);
			}
		}

		/* context already in use */
		printf("\t\trle_encapsulate() with different context ID in use\n");
		encap_status = rle_encapsulate(rle_transmitter, &rle_sdu, RLE_MAX_FRAG_ID);
		assert(encap_status == RLE_ENCAP_ERR);
	}

	/* fragment one ALPDU */
	printf("\ttest rle_fragment()\n");
	size_t ppdu_valid_max_len = 599;
	unsigned char ppdu_valid[ppdu_valid_max_len];
	size_t ppdu_valid_len;
	{
		enum rle_frag_status frag_status;
		size_t frag_id = 0;
		size_t fpdu_remain_len = 599;
		unsigned char *ppdu;
		size_t ppdu_len;

		/* NULL parameters */
		printf("\t\trle_fragment() with NULL parameters\n");
		frag_status = rle_fragment(NULL, frag_id, fpdu_remain_len,
		                           &ppdu, &ppdu_len);
		assert(frag_status == RLE_FRAG_ERR_NULL_TRMT);
		frag_status = rle_fragment(rle_transmitter, frag_id, fpdu_remain_len,
		                           NULL, &ppdu_len);
		assert(frag_status == RLE_FRAG_ERR);
		frag_status = rle_fragment(rle_transmitter, frag_id, fpdu_remain_len,
		                           &ppdu, NULL);
		assert(frag_status == RLE_FRAG_ERR);

		/* try with too short remaining FPDU room for START PPDU */
		printf("\t\trle_fragment() with too short remaining FPDU room for START PPDU\n");
		for (fpdu_remain_len = 0; fpdu_remain_len <= 3; fpdu_remain_len++) {
			frag_status = rle_fragment(rle_transmitter, frag_id, fpdu_remain_len,
			                           &ppdu, &ppdu_len);
			assert(frag_status == RLE_FRAG_ERR_BURST_TOO_SMALL);
		}

		/* try with too short remaining FPDU room, but for CONT PPDU */
		printf("\t\trle_fragment() with too short remaining FPDU room for CONT PPDU\n");
		fpdu_remain_len = 5;
		frag_status = rle_fragment(rle_transmitter, frag_id, fpdu_remain_len,
		                           &ppdu, &ppdu_len);
		assert(frag_status == RLE_FRAG_OK);
		assert(ppdu_len == fpdu_remain_len);
		fpdu_remain_len = 1;
		frag_status = rle_fragment(rle_transmitter, frag_id, fpdu_remain_len,
		                           &ppdu, &ppdu_len);
		assert(frag_status == RLE_FRAG_ERR_BURST_TOO_SMALL);
		fpdu_remain_len = 599;

		/* use all contexts */
		printf("\t\trle_fragment() with different context IDs\n");
		for (frag_id = 0x00; frag_id <= 0xff; frag_id++) {
			frag_status = rle_fragment(rle_transmitter, frag_id, fpdu_remain_len,
			                           &ppdu, &ppdu_len);
			if (frag_id < RLE_MAX_FRAG_NUMBER) {
				assert(frag_status == RLE_FRAG_OK);
				assert(ppdu_len > 0);
				assert(ppdu_len <= fpdu_remain_len);

				/* next test needs a valid PPDU */
				if (frag_id == RLE_MAX_FRAG_ID) {
					assert(ppdu_len <= ppdu_valid_max_len);
					memcpy(ppdu_valid, ppdu, ppdu_len);
					ppdu_valid_len = ppdu_len;
				}
			} else {
				assert(frag_status == RLE_FRAG_ERR);
			}
		}

		/* use empty context */
		printf("\t\trle_fragment() with empty context\n");
		frag_status = rle_fragment(rle_transmitter, RLE_MAX_FRAG_ID, fpdu_remain_len,
		                           &ppdu, &ppdu_len);
		assert(frag_status == RLE_FRAG_ERR_CONTEXT_IS_NULL);
	}

	/* pack PPDU together in one FPDU */
	printf("\ttest rle_pack()\n");
	{
		enum rle_pack_status pack_status;
		unsigned char fpdu_label[] = "\x00\x01\x02";
		size_t fpdu_label_len = sizeof(fpdu_label) - 1;
		unsigned char *ppdu = ppdu_valid;
		size_t ppdu_len = ppdu_valid_len;
		size_t fpdu_max_len = 599;
		unsigned char fpdu[fpdu_max_len];
		size_t fpdu_cur_pos = 0;
		size_t fpdu_remain_len = fpdu_max_len;
		size_t ppdus_nr = (fpdu_max_len - fpdu_label_len) / ppdu_len;
		size_t free_room = (fpdu_max_len - fpdu_label_len) % ppdu_len;

		/* NULL parameters */
		printf("\t\trle_pack() with NULL parameters\n");
		pack_status = rle_pack(NULL, ppdu_len, fpdu_label, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_INVALID_PPDU);
		pack_status = rle_pack(ppdu, 0, fpdu_label, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_INVALID_PPDU);
		pack_status = rle_pack(ppdu, ppdu_len, NULL, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_INVALID_LAB);
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, 1,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_INVALID_LAB);
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, 10,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_INVALID_LAB);
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
		                       NULL, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR);
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
		                       fpdu, NULL, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR);
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, NULL);
		assert(pack_status == RLE_PACK_ERR);
		fpdu_remain_len = 0;
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_FPDU_TOO_SMALL);
		fpdu_remain_len = fpdu_max_len;

		/* pack as many PPDUs as possible */
		printf("\t\trle_pack() with as many PPDUs as possible in a 599B FPDU\n");
		for (i = 0; i < ppdus_nr; i++) {
			printf("\t\t\trle_pack() with PPDU #%zu\n", i + 1);
			pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
			                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
			assert(pack_status == RLE_PACK_OK);
			assert(fpdu_cur_pos > 0);
			assert((fpdu_cur_pos + fpdu_remain_len) == fpdu_max_len);
		}
		assert(fpdu_remain_len == free_room);

		/* pack fails when no more enough FPDU room */
		printf("\t\trle_pack() with no more enough FPDU room\n");
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_FPDU_TOO_SMALL);

		/* pad remaining room at the very end of the FPDU */
		printf("\t\trle_pad() with %zu bytes\n", free_room);
		rle_pad(fpdu, fpdu_cur_pos, fpdu_remain_len);

		/* pack as many PPDUs as possible */
		printf("\t\trle_pack() with as many PPDUs as possible in a 23B FPDU\n");
		ppdus_nr = 5;
		free_room = ppdu_len - 1;
		fpdu_max_len = fpdu_label_len + ppdu_len * ppdus_nr + free_room;
		fpdu_cur_pos = 0;
		fpdu_remain_len = fpdu_max_len;
		for (i = 0; i < ppdus_nr; i++) {
			printf("\t\t\trle_pack() with PPDU #%zu\n", i + 1);
			pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
			                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
			assert(pack_status == RLE_PACK_OK);
		}
		assert(fpdu_remain_len == free_room);
		assert(fpdu_cur_pos == (fpdu_max_len - fpdu_remain_len));

		/* pack fails when no more enough FPDU room */
		printf("\t\trle_pack() with no more enough FPDU room\n");
		pack_status = rle_pack(ppdu, ppdu_len, fpdu_label, fpdu_label_len,
		                       fpdu, &fpdu_cur_pos, &fpdu_remain_len);
		assert(pack_status == RLE_PACK_ERR_FPDU_TOO_SMALL);

		/* pad remaining room at the very end of the FPDU */
		printf("\t\trle_pad() with %zu bytes\n", free_room);
		rle_pad(fpdu, fpdu_cur_pos, fpdu_remain_len);

		/* dump of FPDU is useful to determine the input of the receiver test */
		printf("unsigned char fpdu[] = {\n");
		for (i = 0; i < fpdu_max_len; i++) {
			if (i > 0 && i % 8 == 0) {
				printf("\n");
			}
			printf("0x%02x, ", fpdu[i]);
		}
		printf("\n};\n");

		/* padding robustness */
		printf("\t\trle_pad() with corner cases\n");
		rle_pad(NULL, fpdu_cur_pos, 0);
		rle_pad(fpdu, fpdu_cur_pos, 0);
	}

	/* test statistics */
	printf("\ttest statistics\n");
	{
		struct rle_transmitter_stats stats;
		size_t queue_len;
		uint64_t counter;

		printf("\t\trle_transmitter_stats_get_queue_size()\n");
		queue_len = rle_transmitter_stats_get_queue_size(NULL, 0);
		assert(queue_len == 0);
		queue_len = rle_transmitter_stats_get_queue_size(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(queue_len == 0);
		queue_len = rle_transmitter_stats_get_queue_size(rle_transmitter, 1);
		assert(queue_len == 0);

		printf("\t\trle_transmitter_stats_get_counter_sdus_in()\n");
		counter = rle_transmitter_stats_get_counter_sdus_in(NULL, 0);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_sdus_in(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_sdus_in(rle_transmitter, 1);
		assert(counter == 1);

		printf("\t\trle_transmitter_stats_get_counter_sdus_sent()\n");
		counter = rle_transmitter_stats_get_counter_sdus_sent(NULL, 0);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_sdus_sent(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_sdus_sent(rle_transmitter, 1);
		assert(counter == 1);

		printf("\t\trle_transmitter_stats_get_counter_sdus_dropped()\n");
		counter = rle_transmitter_stats_get_counter_sdus_dropped(NULL, 0);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_sdus_dropped(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_sdus_dropped(rle_transmitter, 1);
		assert(counter == 0);

		printf("\t\trle_transmitter_stats_get_counter_bytes_in()\n");
		counter = rle_transmitter_stats_get_counter_bytes_in(NULL, 0);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_bytes_in(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_bytes_in(rle_transmitter, 1);
		assert(counter == 4);

		printf("\t\trle_transmitter_stats_get_counter_bytes_sent()\n");
		counter = rle_transmitter_stats_get_counter_bytes_sent(NULL, 0);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_bytes_sent(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_bytes_sent(rle_transmitter, 1);
		assert(counter == 6);

		printf("\t\trle_transmitter_stats_get_counter_bytes_dropped()\n");
		counter = rle_transmitter_stats_get_counter_bytes_dropped(NULL, 0);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_bytes_dropped(rle_transmitter, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_transmitter_stats_get_counter_bytes_dropped(rle_transmitter, 1);
		assert(counter == 0);

		printf("\t\trle_transmitter_stats_get_counters()\n");
		counter = rle_transmitter_stats_get_counters(NULL, 0, &stats);
		assert(counter == 1);
		counter = rle_transmitter_stats_get_counters(rle_transmitter, RLE_MAX_FRAG_ID + 1, &stats);
		assert(counter == 1);
		counter = rle_transmitter_stats_get_counters(rle_transmitter, 0, NULL);
		assert(counter == 1);
		counter = rle_transmitter_stats_get_counters(rle_transmitter, 1, &stats);
		assert(counter == 0);

		printf("\t\trle_transmitter_stats_reset_counters()\n");
		rle_transmitter_stats_reset_counters(NULL, 0);
		rle_transmitter_stats_reset_counters(rle_transmitter, RLE_MAX_FRAG_ID + 1);
	}

	/* test destruction of RLE transmitter */
	printf("\ttest rle_transmitter_destroy()\n");
	rle_transmitter_destroy(&rle_transmitter);
	assert(rle_transmitter == NULL);
	rle_transmitter_destroy(&rle_transmitter);
	rle_transmitter_destroy(NULL);

	/* test fragmentation buffer */
	printf("\ttest rle_frag_buf_init()\n");
	assert(rle_frag_buf_init(NULL) == 1);

	return true;
}


/**
 * @brief Test the robustness of the receiver API
 *
 * @return  true if the test is OK, false if KO
 */
bool test_rle_api_robustness_receiver(void)
{
	struct rle_config rle_config_ok = {
		.implicit_protocol_type = 0x30,
		.use_alpdu_crc = 0,
		.use_ptype_omission = 1,
		.use_compressed_ptype = 1,
	};
	struct rle_config rle_config;
	struct rle_receiver *rle_receiver;
	int i;

	printf("test robustness of RLE receiver\n");
	printf("\ttest rle_receiver_new()\n");

	/* NULL config */
	printf("\t\trle_receiver_new() with NULL config\n");
	rle_receiver = rle_receiver_new(NULL);
	assert(rle_receiver == NULL);

	/* all possible implicit_protocol_type values */
	printf("\t\trle_receiver_new() with different implicit_protocol_type\n");
	rle_config = rle_config_ok;
	for (i = 0x00; i <= 0xff; i++) {
		rle_config.implicit_protocol_type = i;
		rle_receiver = rle_receiver_new(&rle_config);
		if (i == 0x31) {
			/* compressed VLAN without protocol type field is not supported yet */
			assert(rle_receiver == NULL);
		} else {
			assert(rle_receiver != NULL);
			rle_receiver_destroy(&rle_receiver);
			assert(rle_receiver == NULL);
		}
	}

	/* different valid and invalid values for use_alpdu_crc */
	printf("\t\trle_receiver_new() with different use_alpdu_crc\n");
	rle_config = rle_config_ok;
	rle_config.use_alpdu_crc = 0;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_config.use_alpdu_crc = 1;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_config.use_alpdu_crc = -1;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	rle_config.use_alpdu_crc = 2;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);

	/* different valid and invalid values for use_ptype_omission */
	printf("\t\trle_receiver_new() with different use_ptype_omission\n");
	rle_config = rle_config_ok;
	rle_config.use_ptype_omission = 0;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_receiver_destroy(&rle_receiver);
	rle_config.use_ptype_omission = 1;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_config.use_ptype_omission = -1;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	rle_config.use_ptype_omission = 2;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);

	/* different valid and invalid values for use_compressed_ptype */
	printf("\t\trle_receiver_new() with different use_compressed_ptype\n");
	rle_config = rle_config_ok;
	rle_config.use_compressed_ptype = 0;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_config.use_compressed_ptype = 1;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_config.use_compressed_ptype = -1;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);
	rle_config.use_compressed_ptype = 2;
	rle_receiver = rle_receiver_new(&rle_config);
	assert(rle_receiver != NULL);
	rle_receiver_destroy(&rle_receiver);

	/* nominal case, valid config */
	printf("\t\trle_receiver_new() with valid config\n");
	rle_receiver = rle_receiver_new(&rle_config_ok);
	assert(rle_receiver != NULL);

	/* decapsulate one FPDU */
	printf("\ttest rle_decapsulate()\n");
	{
		enum rle_decap_status decap_status;
		unsigned char fpdu[] = { /* generated with transmitter test */
			0x00, 0x01, 0x02, 0xc0, 0x15, 0x45, 0x01, 0xc0,
			0x15, 0x45, 0x01, 0xc0, 0x15, 0x45, 0x01, 0xc0,
			0x15, 0x45, 0x01, 0xc0, 0x15, 0x45, 0x01, 0x00,
			0x00, 0x00,
		};
		size_t fpdu_len = sizeof(fpdu);
		size_t sdus_max_nr = 10;
		struct rle_sdu sdus[sdus_max_nr];
		size_t sdus_nr;
		size_t fpdu_label_len = 3;
		unsigned char fpdu_label[fpdu_label_len];

		/* init the array of SDUs */
		for (i = 0; i < (int) sdus_max_nr; i++) {
			sdus[i].size = 599;
			sdus[i].protocol_type = 0x0000;
			sdus[i].buffer = malloc(sdus[i].size);
			assert(sdus[i].buffer != NULL);
		}

		/* NULL parameters */
		printf("\t\trle_decapsulate() with NULL parameters\n");
		decap_status = rle_decapsulate(NULL, fpdu, fpdu_len,
		                               sdus, sdus_max_nr, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_NULL_RCVR);
		decap_status = rle_decapsulate(rle_receiver, NULL, fpdu_len,
		                               sdus, sdus_max_nr, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_FPDU);
		decap_status = rle_decapsulate(rle_receiver, fpdu, 0,
		                               sdus, sdus_max_nr, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_FPDU);
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
		                               NULL, sdus_max_nr, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_SDUS);
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
		                               sdus, 0, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_SDUS);
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
		                               sdus, sdus_max_nr, NULL,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_SDUS);
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
		                               sdus, sdus_max_nr, &sdus_nr,
		                               NULL, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_PL);

		/* FPDU smaller than label */
		printf("\t\trle_decapsulate() with FPDU smaller than label\n");
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_label_len - 1,
		                               sdus, sdus_max_nr, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_INV_FPDU);

		/* too few SDUs */
		printf("\t\trle_decapsulate() with too few SDUs\n");
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
		                               sdus, 2, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_ERR_SOME_DROP);
		assert(sdus_nr == 2);
		assert(fpdu_label[0] == 0x00 && fpdu_label[1] == 0x01 && fpdu_label[2] == 0x02);

		/* FPDU with PPDU wrong length */
		{
			printf("\t\trle_decapsulate() with PPDU wrong length\n");
			rle_ppdu_header_comp_t *ppdu_comp_hdr =
				(rle_ppdu_header_comp_t *) (fpdu + fpdu_label_len);
			ppdu_comp_hdr->rle_packet_length_2--;
			decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
			                               sdus, sdus_max_nr, &sdus_nr,
			                               fpdu_label, fpdu_label_len);
			assert(decap_status != RLE_DECAP_OK);
			ppdu_comp_hdr->rle_packet_length_2++;
		}

		/* nominal case */
		printf("\t\trle_decapsulate() with nominal case\n");
		decap_status = rle_decapsulate(rle_receiver, fpdu, fpdu_len,
		                               sdus, sdus_max_nr, &sdus_nr,
		                               fpdu_label, fpdu_label_len);
		assert(decap_status == RLE_DECAP_OK);
		assert(sdus_nr <= sdus_max_nr);
		assert(fpdu_label[0] == 0x00 && fpdu_label[1] == 0x01 && fpdu_label[2] == 0x02); 

		/* destroy the array of SDUs */
		for (i = 0; i < (int) sdus_max_nr; i++) {
			free(sdus[i].buffer);
		}
	}

	/* test statistics */
	printf("\ttest statistics\n");
	{
		struct rle_receiver_stats stats;
		size_t queue_len;
		uint64_t counter;

		printf("\t\trle_receiver_stats_get_queue_size()\n");
		queue_len = rle_receiver_stats_get_queue_size(NULL, 0);
		assert(queue_len == 0);
		queue_len = rle_receiver_stats_get_queue_size(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(queue_len == 0);
		queue_len = rle_receiver_stats_get_queue_size(rle_receiver, 1);
		assert(queue_len == 0);

		printf("\t\trle_receiver_stats_get_counter_sdus_received()\n");
		counter = rle_receiver_stats_get_counter_sdus_received(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_received(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_received(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counter_sdus_reassembled()\n");
		counter = rle_receiver_stats_get_counter_sdus_reassembled(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_reassembled(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_reassembled(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counter_sdus_dropped()\n");
		counter = rle_receiver_stats_get_counter_sdus_dropped(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_dropped(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_dropped(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counter_sdus_lost()\n");
		counter = rle_receiver_stats_get_counter_sdus_lost(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_lost(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_sdus_lost(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counter_bytes_received()\n");
		counter = rle_receiver_stats_get_counter_bytes_received(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_bytes_received(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_bytes_received(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counter_bytes_reassembled()\n");
		counter = rle_receiver_stats_get_counter_bytes_reassembled(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_bytes_reassembled(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_bytes_reassembled(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counter_bytes_dropped()\n");
		counter = rle_receiver_stats_get_counter_bytes_dropped(NULL, 0);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_bytes_dropped(rle_receiver, RLE_MAX_FRAG_ID + 1);
		assert(counter == 0);
		counter = rle_receiver_stats_get_counter_bytes_dropped(rle_receiver, 1);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_get_counters()\n");
		counter = rle_receiver_stats_get_counters(NULL, 0, &stats);
		assert(counter == 1);
		counter = rle_receiver_stats_get_counters(rle_receiver, RLE_MAX_FRAG_ID + 1, &stats);
		assert(counter == 1);
		counter = rle_receiver_stats_get_counters(rle_receiver, 0, NULL);
		assert(counter == 1);
		counter = rle_receiver_stats_get_counters(rle_receiver, 1, &stats);
		assert(counter == 0);

		printf("\t\trle_receiver_stats_reset_counters()\n");
		rle_receiver_stats_reset_counters(NULL, 0);
		rle_receiver_stats_reset_counters(rle_receiver, RLE_MAX_FRAG_ID + 1);
	}

	/* test destruction of RLE receiver */
	printf("\ttest rle_receiver_destroy()\n");
	rle_receiver_destroy(&rle_receiver);
	assert(rle_receiver == NULL);
	rle_receiver_destroy(&rle_receiver);
	rle_receiver_destroy(NULL);

	/* test generic function */
	printf("\ttest generic functions\n");
	{
		struct rle_config conf = { 0 };
		enum rle_fpdu_types fpdu_type = RLE_TRAFFIC_FPDU;
		size_t rle_hdr_len;
		enum rle_header_size_status ret;
		uint8_t comp_protocol_type;

		printf("\ttest generic function rle_get_header_size()\n");
		ret = rle_get_header_size(NULL, fpdu_type, &rle_hdr_len);
		assert(ret == RLE_HEADER_SIZE_ERR);
		ret = rle_get_header_size(&conf, 4242, &rle_hdr_len);
		assert(ret == RLE_HEADER_SIZE_ERR);
		ret = rle_get_header_size(&conf, fpdu_type, NULL);
		assert(ret == RLE_HEADER_SIZE_ERR);

		printf("\ttest generic function rle_header_ptype_compression()\n");
		comp_protocol_type = rle_header_ptype_compression(RLE_PROTO_TYPE_SIGNAL_UNCOMP);
		assert(comp_protocol_type == RLE_PROTO_TYPE_SIGNAL_COMP);
		comp_protocol_type = rle_header_ptype_compression(0xffff);
		assert(comp_protocol_type == 0);
	}

	return true;
}


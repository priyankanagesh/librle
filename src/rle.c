/**
 * @file   rle.c
 * @brief  Interface file body for the librle library.
 * @author Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#else

#include <linux/string.h>
#define assert BUG_ON

#endif

#include "constants.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "rle_receiver.h"
#include "rle_transmitter.h"
#include "fragmentation.h"

#include "header.h"
#include "trailer.h"

#include "rle.h"

/**
 * @brief          Check if a transmitter queue context is valid and extract it.
 *
 * @param[in]      transmitter              The transmitter with the context to extract.
 * @param[in]      fragment_id              The fragment ID linked to the context to extract.
 * @param[out]     ctx_man                  The extracted context.
 *
 * @return         0 if OK, else 1.
 */
static int valid_transmitter_context(const struct rle_transmitter *const transmitter,
                                     const uint8_t fragment_id,
                                     struct rle_ctx_management *const ctx_man);
/**
 * @brief          Check if a receiver queue context is valid and extract it.
 *
 * @param[in]      receiver                 The receiver with the context to extract.
 * @param[in]      fragment_id              The fragment ID linked to the context to extract.
 * @param[out]     ctx_man                  The extracted context.
 *
 * @return         0 if OK, else 1.
 */
static int valid_receiver_context(const struct rle_receiver *const receiver,
                                  const uint8_t fragment_id,
                                  struct rle_ctx_management *const ctx_man);

static int valid_transmitter_context(const struct rle_transmitter *const transmitter,
                                     const uint8_t fragment_id,
                                     struct rle_ctx_management *const ctx_man)
{
	int status = 1;

	if (!transmitter) {
		/* Transmitter null. */
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		/* Out of bound */
		goto error;
	}

	if (!ctx_man) {
		/* Context manager null. */
		goto error;
	}

	*ctx_man = transmitter->rle_ctx_man[fragment_id];

	status = 1;

error:
	return status;
}

static int valid_receiver_context(const struct rle_receiver *const receiver,
                                  const uint8_t fragment_id,
                                  struct rle_ctx_management *const ctx_man)
{
	int status = 1;

	if (!receiver) {
		/* receiver null. */
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		/* Out of bound */
		goto error;
	}

	if (!ctx_man) {
		/* Context manager null. */
		goto error;
	}

	*ctx_man = receiver->rle_ctx_man[fragment_id];

	status = 1;

error:
	return status;
}

struct rle_transmitter *rle_transmitter_new(const struct rle_context_configuration configuration)
{
	struct rle_transmitter *transmitter = rle_transmitter_module_new();

	if (configuration.implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
		PRINT(
		        "ERROR: could not initialize transmitter with 0x31 as implicit protocol type : "
		        "Not supported yet.\n");
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
		goto exit_label;
	}

	if (transmitter != NULL) {
		size_t iterator = 0;

		for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
			rle_ctx_set_alpdu_length(
			        &((struct rle_transmitter *)transmitter)->rle_ctx_man[iterator], 0);
			rle_ctx_set_pdu_length(
			        &((struct rle_transmitter *)transmitter)->rle_ctx_man[iterator], 0);
			rle_ctx_set_remaining_alpdu_length(
			        &((struct rle_transmitter *)transmitter)->rle_ctx_man[iterator], 0);
			rle_ctx_set_remaining_pdu_length(
			        &((struct rle_transmitter *)transmitter)->rle_ctx_man[iterator], 0);
		}

		rle_conf_set_default_ptype(transmitter->rle_conf,
		                           configuration.implicit_protocol_type);
		rle_conf_set_crc_check(transmitter->rle_conf, configuration.use_alpdu_crc);
		rle_conf_set_ptype_compression(transmitter->rle_conf,
		                               configuration.use_compressed_ptype);
		rle_conf_set_ptype_suppression(transmitter->rle_conf,
		                               configuration.use_ptype_omission);
	}

exit_label:
	return transmitter;
}

void rle_transmitter_destroy(struct rle_transmitter *const transmitter)
{
	rle_transmitter_module_destroy(transmitter);
}


struct rle_receiver *rle_receiver_new(const struct rle_context_configuration configuration)
{
	struct rle_receiver *receiver = rle_receiver_module_new();

	if (configuration.implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
		PRINT("ERROR: could not initialize receiver with 0x31 as implicit protocol type : "
		      "Not supported yet.\n");
		rle_receiver_destroy(receiver);
		receiver = NULL;
		goto exit_label;
	}

	if (receiver != NULL) {
		size_t iterator = 0;

		for (iterator = 0; iterator < RLE_MAX_FRAG_NUMBER; ++iterator) {
			rle_conf_set_default_ptype(receiver->rle_conf[iterator],
			                           configuration.implicit_protocol_type);
			rle_conf_set_crc_check(receiver->rle_conf[iterator],
			                       configuration.use_alpdu_crc);
			rle_conf_set_ptype_compression(receiver->rle_conf[iterator],
			                               configuration.use_compressed_ptype);
			rle_conf_set_ptype_suppression(receiver->rle_conf[iterator],
			                               configuration.use_ptype_omission);
		}
	}

exit_label:
	return receiver;
}

void rle_receiver_destroy(struct rle_receiver *const receiver)
{
	rle_receiver_module_destroy(receiver);
}


enum rle_encap_status rle_encapsulate(struct rle_transmitter *const transmitter,
                                      const struct rle_sdu sdu,
                                      const uint8_t frag_id)
{
	enum rle_encap_status status = RLE_ENCAP_ERR;
	int ret = 0;

	if (transmitter == NULL) {
		status = RLE_ENCAP_ERR_NULL_TRMT;
		goto exit_label;
	}

	if (sdu.size > RLE_MAX_PDU_SIZE) {
		status = RLE_ENCAP_ERR_SDU_TOO_BIG;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	ret = rle_transmitter_encap_data(transmitter, sdu.buffer, sdu.size, sdu.protocol_type,
	                                 frag_id);

	if (ret == C_OK) {
		status = RLE_ENCAP_OK;
	}

exit_label:
	return status;
}

enum rle_frag_status rle_fragment(struct rle_transmitter *const transmitter, const uint8_t frag_id,
                                  const size_t remaining_burst_size, unsigned char *const ppdu,
                                  size_t *const ppdu_length)
{
	enum rle_frag_status status = RLE_FRAG_ERR; /* Error by default. */

	size_t min_burst_size = 0;
	int ret = 0;
	size_t remaining_pdu = 0;
	size_t remaining_alpdu = 0;
	size_t burst_size = 0;

	if (transmitter == NULL) {
		status = RLE_FRAG_ERR_NULL_TRMT;
		goto exit_label;
	}

	min_burst_size = RLE_CONT_HEADER_SIZE;

	remaining_pdu = rle_ctx_get_remaining_pdu_length(&transmitter->rle_ctx_man[frag_id]);
	remaining_alpdu = rle_ctx_get_remaining_alpdu_length(&transmitter->rle_ctx_man[frag_id]);
	burst_size = remaining_burst_size <
	             RLE_MAX_PPDU_PL_SIZE ? remaining_burst_size : RLE_MAX_PPDU_PL_SIZE;

	if (remaining_alpdu == 0) {
		status = RLE_FRAG_ERR_CONTEXT_IS_NULL;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	if (fragmentation_is_needed(&transmitter->rle_ctx_man[frag_id], remaining_burst_size) &&
	    !rle_ctx_get_is_fragmented(&transmitter->rle_ctx_man[frag_id])) {
		min_burst_size = RLE_START_MANDATORY_HEADER_SIZE;
	}

	if (burst_size < min_burst_size) {
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	/*
	 * The further statement checks if the remaining burst size is large enough to send SDU,
	 * but not the ALPDU protection octets. If not, there is no framentation, and an error code is
	 * returned. The user of the library must retry the fragmentation with either:
	 * - a smaller burst size, in order to send partially or fully the ALPDU without its
	 *   protection bytes. Those octets could not be split apart and should be sent together in a
	 *   forthcoming burst.
	 * - a bigger burst size, for the same reason as exposed previously.
	 */
	if ((burst_size > RLE_CONT_HEADER_SIZE + remaining_pdu) &&
	    (burst_size < RLE_CONT_HEADER_SIZE + remaining_alpdu)) {
		status = RLE_FRAG_ERR_INVALID_SIZE;
		rle_transmitter_free_context(transmitter, frag_id);
		goto exit_label;
	}

	if ((remaining_alpdu + RLE_CONT_HEADER_SIZE) < burst_size) {
		*ppdu_length = remaining_alpdu + RLE_CONT_HEADER_SIZE;
	} else {
		*ppdu_length = burst_size;
	}

	ret = rle_transmitter_get_packet(transmitter, ppdu, *ppdu_length, frag_id,
	                                 rle_ctx_get_proto_type(&transmitter->rle_ctx_man[frag_id]));

	if (ret == C_ERROR_FRAG_SIZE) {
		status = RLE_FRAG_ERR_BURST_TOO_SMALL;
		goto exit_label;
	}

	remaining_alpdu = rle_ctx_get_remaining_alpdu_length(&transmitter->rle_ctx_man[frag_id]);

	if (remaining_alpdu == 0) {
		rle_transmitter_free_context(transmitter, frag_id);
	}

	if (ret == C_OK) {
		status = RLE_FRAG_OK;
	}


exit_label:
	return status;
}

enum rle_pack_status rle_pack(const unsigned char *const ppdu, const size_t ppdu_length,
                              const unsigned char *const label, const size_t label_size,
                              unsigned char *const fpdu,
                              size_t *const fpdu_current_pos,
                              size_t *const fpdu_remaining_size)
{
	enum rle_pack_status status = RLE_PACK_ERR;

	if ((fpdu == NULL) || (*fpdu_remaining_size == 0)) {
		status = RLE_PACK_ERR_FPDU_TOO_SMALL;
		goto exit_label;
	}

	if ((label_size + ppdu_length) > *fpdu_remaining_size) {
		status = RLE_PACK_ERR_FPDU_TOO_SMALL;
		goto exit_label;
	}

	if ((ppdu == NULL) || (ppdu_length == 0)) {
		status = RLE_PACK_ERR_INVALID_PPDU;
		goto exit_label;
	}

	if ((label == NULL) ^ (label_size == 0)) {
		status = RLE_PACK_ERR_INVALID_LAB;
		goto exit_label;
	}

	if ((label_size != 0) && (label_size != 3) && (label_size != 6)) {
		status = RLE_PACK_ERR_INVALID_LAB;
		goto exit_label;
	}

	{
		void *mem_ret = NULL;

		if (label_size != 0) {
			mem_ret = memcpy((void *)(fpdu + *fpdu_current_pos), (const void *)label,
			                 label_size);
			if (mem_ret == NULL) {
				mem_ret = memset((void *)(fpdu + *fpdu_current_pos), 0, label_size);
				if (mem_ret == NULL) {
					status = RLE_PACK_ERR_FPDU_TOO_SMALL;
					goto exit_label;
				}
				status = RLE_PACK_ERR_INVALID_LAB;
				goto exit_label;
			}
		}

		mem_ret =
		        memcpy((void *)(fpdu + *fpdu_current_pos + label_size), (const void *)ppdu,
		               ppdu_length);
		if (mem_ret == NULL) {
			mem_ret = memset((void *)(fpdu + *fpdu_current_pos), 0,
			                 label_size + ppdu_length);
			if (mem_ret == NULL) {
				status = RLE_PACK_ERR_FPDU_TOO_SMALL;
				goto exit_label;
			}
			status = RLE_PACK_ERR_INVALID_PPDU;
			goto exit_label;
		}

		*fpdu_current_pos += label_size + ppdu_length;
		*fpdu_remaining_size -= label_size + ppdu_length;
	}

	status = RLE_PACK_OK;

exit_label:
	return status;
}

void rle_pad(unsigned char *const fpdu, const size_t fpdu_current_pos,
             const size_t fpdu_remaining_size)
{
	memset((void *)(fpdu + fpdu_current_pos), 0, fpdu_remaining_size);
}

enum rle_decap_status rle_decapsulate(struct rle_receiver *const receiver,
                                      const unsigned char *const fpdu, const size_t fpdu_length,
                                      struct rle_sdu sdus[],
                                      const size_t sdus_max_nr, size_t *const sdus_nr,
                                      unsigned char *const payload_label,
                                      const size_t payload_label_size)
{
	enum rle_decap_status status = RLE_DECAP_ERR;
	int padding_detected = C_FALSE;
	size_t offset = 0;

	/* no SDUs decapsulated yet */
	*sdus_nr = 0;

	/* checks inputs */
	if (receiver == NULL) {
		status = RLE_DECAP_ERR_NULL_RCVR;
		goto exit_label;
	}

	if ((fpdu == NULL) || (fpdu_length == 0)) {
		status = RLE_DECAP_ERR_INV_FPDU;
		goto exit_label;
	}

	if ((fpdu_length < payload_label_size)) {
		status = RLE_DECAP_ERR_INV_FPDU;
		goto exit_label;
	}

	if ((sdus == NULL) || (sdus_max_nr == 0)) {
		status = RLE_DECAP_ERR_INV_SDUS;
		goto exit_label;
	}

	if ((payload_label == NULL) ^ (payload_label_size == 0)) {
		status = RLE_DECAP_ERR_INV_PL;
		goto exit_label;
	}

	if ((payload_label_size != 0) && (payload_label_size != 3) && (payload_label_size != 6)) {
		status = RLE_DECAP_ERR_INV_PL;
		goto exit_label;
	}

	/* copy payload label to user if present */
	if (payload_label_size != 0) {
		memcpy(payload_label, fpdu, payload_label_size);
		offset += payload_label_size;
	}

	/* parse all PPDUs that the FPDU contains until there is less than 2 bytes
	 * in the FPDU payload and padding is not detected */
	while ((offset + 1) < fpdu_length && !padding_detected) {

		enum frag_states fragment_type;
		size_t fragment_length;
		int fragment_id;
		int ret;

		/* is there padding? */
		if (fpdu[offset] == 0x00 && fpdu[offset + 1] == 0x00) {
			padding_detected = C_TRUE;
			continue;
		}

		/* retrieve the fragment type and length in the first 2 bytes of the PPDU fragment */
		fragment_type = get_fragment_type(&fpdu[offset]);
		fragment_length = get_fragment_length(&fpdu[offset]);

		/* stop parsing the FPDU if the PPDU length is wrong */
		if (fragment_length > (fpdu_length - offset)) {
			PRINT("Invalid fragment size, fragment length too big for FPDU\n");
			PRINT("Fragment length: %zu, Remaining FPDU size: %zu\n",
			      fragment_length, fpdu_length - offset);
			goto exit_label;
		}

		/* parse the PPDU fragment */
		ret = rle_receiver_deencap_data(receiver, (void *) &fpdu[offset], fragment_length,
		                                &fragment_id);
		if (ret != C_OK && ret != C_REASSEMBLY_OK) {
			/* TODO cleaning, pkt dropping, etc... */
			PRINT("Error during reassembly.\n");
			status = RLE_FRAG_ERR;
			goto exit_label;
		}

		/* PPDU fragment successfully parsed, skip it */
		offset += fragment_length;

		/* in case of complete or END fragment, decapsulate the reassembled PPDU */
		if (fragment_type == FRAG_STATE_COMP || fragment_type == FRAG_STATE_END) {
			int sdu_proto = 0;
			uint32_t sdu_len = 0;

			assert(fragment_id >= 0);

			ret = rle_receiver_get_packet(receiver, fragment_id, sdus[*sdus_nr].buffer,
			                              &sdu_proto, &sdu_len);
			if (ret != C_OK) {
				/* TODO cleaning, pkt dropping, etc... */
				PRINT("Error getting packet from context.\n");
				status = RLE_FRAG_ERR;
				goto exit_label;
			} else {
				/* reassembly and decapsulation are over, so free context resources */
				rle_receiver_free_context(receiver, fragment_id);
			}
			sdus[*sdus_nr].size = (size_t) sdu_len;
			sdus[*sdus_nr].protocol_type = (uint16_t) sdu_proto;
			(*sdus_nr)++;
		}
	}

	/* remaining FPDU bytes are padding: they should be all zero, warn if it is not the case */
	for ( ; offset < fpdu_length; offset++) {
		if (fpdu[offset] != 0x00) {
			PRINT("WARNING: Current padding contains octets non equal to 0x00.\n");
			break; /* stop padding verification after first error */
		}
	}

	status = RLE_DECAP_OK;

exit_label:
	return status;
}

size_t rle_transmitter_stats_get_queue_size(const struct rle_transmitter *const transmitter,
                                            const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_remaining_alpdu_length(&ctx_man);

error:
	return stat;
}

size_t rle_transmitter_stats_get_counter_sdus_in(const struct rle_transmitter *const transmitter,
                                                 const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_in(&ctx_man);

error:
	return stat;
}

size_t rle_transmitter_stats_get_counter_sdus_sent(const struct rle_transmitter *const transmitter,
                                                   const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_ok(&ctx_man);

error:
	return stat;
}

size_t rle_transmitter_stats_get_counter_sdus_dropped(
        const struct rle_transmitter *const transmitter, const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_dropped(&ctx_man);

error:
	return stat;
}

size_t rle_transmitter_stats_get_counter_bytes_in(const struct rle_transmitter *const transmitter,
                                                  const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_bytes_in(&ctx_man);

error:
	return stat;
}

size_t rle_transmitter_stats_get_counter_bytes_sent(const struct rle_transmitter *const transmitter,
                                                  const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_bytes_ok(&ctx_man);

error:
	return stat;
}

size_t rle_transmitter_stats_get_counter_bytes_dropped(
        const struct rle_transmitter *const transmitter, const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_transmitter_context(transmitter, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_bytes_dropped(&ctx_man);

error:
	return stat;
}

int rle_transmitter_stats_get_counters(const struct rle_transmitter *const transmitter,
                                       const uint8_t fragment_id,
                                       struct rle_transmitter_stats *const stats)
{
	int status = 1;

	if (!transmitter) {
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		goto error;
	}

	if (!stats) {
		goto error;
	}

	stats->sdus_in       = rle_transmitter_stats_get_counter_sdus_in(transmitter, fragment_id);
	stats->sdus_sent     = rle_transmitter_stats_get_counter_sdus_sent(transmitter, fragment_id);
	stats->sdus_dropped  = rle_transmitter_stats_get_counter_sdus_dropped(transmitter, fragment_id);
	stats->bytes_in      = rle_transmitter_stats_get_counter_bytes_in(transmitter, fragment_id);
	stats->bytes_sent    = rle_transmitter_stats_get_counter_bytes_sent(transmitter, fragment_id);
	stats->bytes_dropped = rle_transmitter_stats_get_counter_bytes_dropped(transmitter, fragment_id);

	status = 0;

error:
	return status;
}

size_t rle_receiver_stats_get_queue_size(const struct rle_receiver *const receiver,
                                         const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_remaining_pdu_length(&ctx_man);

error:
	return stat;
}

size_t rle_receiver_stats_get_counter_sdus_received(const struct rle_receiver *const receiver,
                                                    const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_in(&ctx_man);

error:
	return stat;
}


size_t rle_receiver_stats_get_counter_sdus_reassembled(const struct rle_receiver *const receiver,
                                                       const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_ok(&ctx_man);

	error:
		return stat;
}

size_t rle_receiver_stats_get_counter_sdus_dropped(const struct rle_receiver *const receiver,
                                                   const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_dropped(&ctx_man);

error:
	return stat;
}

size_t rle_receiver_stats_get_counter_sdus_lost(const struct rle_receiver *const receiver,
                                                const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_lost(&ctx_man);

error:
	return stat;
}

size_t rle_receiver_stats_get_counter_bytes_received(const struct rle_receiver *const receiver,
                                                     const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_bytes_in(&ctx_man);

	error:
		return stat;
}

size_t rle_receiver_stats_get_counter_bytes_reassembled(const struct rle_receiver *const receiver,
                                                        const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_bytes_ok(&ctx_man);

error:
	return stat;
}

size_t rle_receiver_stats_get_counter_bytes_dropped(const struct rle_receiver *const receiver,
                                                    const uint8_t fragment_id)
{
	size_t stat = 0;
	struct rle_ctx_management ctx_man;

	if (!valid_receiver_context(receiver, fragment_id, &ctx_man)) {
		goto error;
	}

	stat = (size_t)rle_ctx_get_counter_bytes_dropped(&ctx_man);

error:
	return stat;
}

int rle_receiver_stats_get_counters(const struct rle_receiver *const receiver,
                                    const uint8_t fragment_id,
                                    struct rle_receiver_stats *const stats)
{
	int status = 1;

	if (!receiver) {
		goto error;
	}

	if (fragment_id >= RLE_MAX_FRAG_ID) {
		goto error;
	}

	if (!stats) {
		goto error;
	}

	stats->sdus_received     = rle_receiver_stats_get_counter_sdus_received(receiver, fragment_id);
	stats->sdus_reassembled  = rle_receiver_stats_get_counter_sdus_reassembled(receiver,
	                                                                           fragment_id);
	stats->sdus_dropped      = rle_receiver_stats_get_counter_sdus_dropped(receiver, fragment_id);
	stats->bytes_received    = rle_receiver_stats_get_counter_bytes_received(receiver, fragment_id);
	stats->bytes_reassembled = rle_receiver_stats_get_counter_bytes_reassembled(receiver,
	                                                                            fragment_id);
	stats->bytes_dropped     = rle_receiver_stats_get_counter_bytes_dropped(receiver, fragment_id);

	status = 0;

error:
	return status;
}

enum rle_header_size_status rle_get_header_size(const struct rle_context_configuration *const conf,
                                                const enum rle_fpdu_types fpdu_type,
                                                size_t *const rle_header_size)
{
	enum rle_header_size_status status = RLE_HEADER_SIZE_ERR;
	size_t header_size = 0;

	switch(fpdu_type)
	{
		case RLE_LOGON_FPDU:

			/* FPDU header. */
			/* payload label = 6 */
			header_size = 6;

			status = RLE_HEADER_SIZE_OK;
			break;

		case RLE_CTRL_FPDU:

			/* FPDU header. */
			/* payload label = 3 */
			header_size = 3;

			status = RLE_HEADER_SIZE_OK;
			break;

		case RLE_TRAFFIC_FPDU:

			/* Unable to guess the headers overhead size */

			status = RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC;
			break;

		case RLE_TRAFFIC_CTRL_FPDU:

			/* FPDU header. */
			/* payload label = 3 */
			header_size = 3;

			/* PPDU header. Only complete PPDU. */
			/* se_length_ltt = 2 */
			/* pdu_label     = 0 */
			header_size += 2 + 0;

			if (conf != NULL) {
				/* ALPDU header. */
				/* protocol_type    = 0. May depends on conf with a different implementation. */
				/* alpdu_label      = 0 */
				/* protection_bytes = 0 */
				header_size += 0 + 0 + 0;
			} else {
				/* ALPDU header. */
				/* protocol_type    = 0 */
				/* alpdu_label      = 0 */
				/* protection_bytes = 0 */
				header_size += 0 + 0 + 0;
			}

			status = RLE_HEADER_SIZE_OK;
			break;
		default:
			break;
	}

	*rle_header_size = header_size;

	return status;
}

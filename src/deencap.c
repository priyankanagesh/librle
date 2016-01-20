/**
 * @file   deencap.c
 * @brief  Definition of RLE deencapsulation structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
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

#endif

#include "rle.h"
#include "deencap.h"
#include "rle_receiver.h"
#include "rle_ctx.h"
#include "constants.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "DEENCAP"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

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

	status = RLE_DECAP_OK;

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
			PRINT("Fragment length: %zu, Remaining FPDU size: %zu\n", fragment_length,
			      fpdu_length - offset);
			status = RLE_DECAP_ERR;
			goto exit_label;
		}

		/* parse the PPDU fragment */
		ret = rle_receiver_deencap_data(receiver, (void *) &fpdu[offset], fragment_length,
		                                &fragment_id);

		/* PPDU fragment successfully parsed, skip it */
		offset += fragment_length;

		if ((ret != C_OK) && (ret != C_REASSEMBLY_OK)) {
			PRINT("Error during reassembly.\n");
			rle_receiver_free_context(receiver, fragment_id);
			status = RLE_DECAP_ERR;
		} else if (fragment_type == FRAG_STATE_COMP || fragment_type == FRAG_STATE_END) {
			/* in case of complete or END fragment, decapsulate the reassembled PPDU */
			int sdu_proto = 0;
			uint32_t sdu_len = 0;

			assert(fragment_id >= 0);

			ret = rle_receiver_get_packet(receiver, fragment_id, sdus[*sdus_nr].buffer, &sdu_proto,
			                              &sdu_len);
			/* reassembly and decapsulation are over, so free context resources */
			rle_receiver_free_context(receiver, fragment_id);
			if (ret != C_OK) {
				PRINT("Error getting packet from context.\n");
				status = RLE_DECAP_ERR;
				goto exit_label;
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

exit_label:
	return status;
}

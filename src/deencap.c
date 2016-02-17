/**
 * @file   deencap.c
 * @brief  Definition of RLE deencapsulation structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "deencap.h"
#include "rle_receiver.h"
#include "rle_ctx.h"
#include "constants.h"
#include "reassembly_buffer.h"
#include "rle.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#else

#include <linux/string.h>

#endif


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
		goto out;
	}

	if ((fpdu == NULL) || (fpdu_length == 0)) {
		status = RLE_DECAP_ERR_INV_FPDU;
		goto out;
	}

	if ((fpdu_length < payload_label_size)) {
		status = RLE_DECAP_ERR_INV_FPDU;
		goto out;
	}

	if ((sdus == NULL) || (sdus_max_nr == 0)) {
		status = RLE_DECAP_ERR_INV_SDUS;
		goto out;
	}

	if ((payload_label == NULL) ^ (payload_label_size == 0)) {
		status = RLE_DECAP_ERR_INV_PL;
		goto out;
	}

	if ((payload_label_size != 0) && (payload_label_size != 3) && (payload_label_size != 6)) {
		status = RLE_DECAP_ERR_INV_PL;
		goto out;
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

		struct rle_sdu *const potential_sdu = &sdus[*sdus_nr];
		const unsigned char *const ppdu = &fpdu[offset];
		size_t ppdu_length;
		int fragment_id;
		int ret;

		/* is there padding? */
		if (ppdu[0] == 0x00 && ppdu[1] == 0x00) {
			padding_detected = C_TRUE;
			continue;
		}

		/* retrieve the fragment type and length in the first 2 bytes of the PPDU fragment */
		ppdu_length = get_fragment_length(ppdu);

		/* stop parsing the FPDU if the PPDU length is wrong */
		if (ppdu_length > (fpdu_length - offset)) {
			PRINT("Invalid fragment size, fragment length too big for FPDU\n");
			PRINT("Fragment length: %zu, Remaining FPDU size: %zu\n", ppdu_length,
			      fpdu_length - offset);
			status = RLE_DECAP_ERR;
			goto out;
		}

		/* parse the PPDU fragment */
		ret = rle_receiver_deencap_data(receiver, ppdu, ppdu_length, &fragment_id, potential_sdu);

		/* PPDU fragment successfully parsed, skip it */
		offset += ppdu_length;

		if ((ret != C_OK) && (ret != C_REASSEMBLY_OK)) {
			PRINT("Error during reassembly.\n");
			rle_receiver_free_context(receiver, fragment_id);
			status = RLE_DECAP_ERR;
		} else if (ret == C_REASSEMBLY_OK) {
			/* Potential SDU received. */
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

out:
	return status;
}

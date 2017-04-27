/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

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
#include <stdbool.h>
#include <assert.h>

#else

#include <linux/string.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_DEENCAP


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_decap_status rle_decapsulate(struct rle_receiver *const receiver,
                                      unsigned char *const fpdu, const size_t fpdu_length,
                                      struct rle_sdu sdus[],
                                      const size_t sdus_max_nr, size_t *const sdus_nr,
                                      unsigned char *const payload_label,
                                      const size_t payload_label_size)
{
	enum rle_decap_status status = RLE_DECAP_ERR;
	int padding_detected = false;
	size_t offset = 0;

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
	PRINT_RLE_DEBUG("decapsulate one %zu-byte FPDU with a %zu-byte Payload Label",
	                fpdu_length, payload_label_size);

	if (sdus == NULL || sdus_max_nr == 0 || sdus_nr == NULL) {
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

	/* no SDUs decapsulated yet */
	*sdus_nr = 0;

	/* copy payload label to user if present */
	if (payload_label_size != 0) {
		memcpy(payload_label, fpdu, payload_label_size);
		offset += payload_label_size;
	}

	status = RLE_DECAP_OK;

	/* parse all PPDUs that the FPDU contains until there is less than 2 bytes
	 * in the FPDU payload and padding is not detected */
	while ((offset + 1) < fpdu_length && !padding_detected) {
		unsigned char *const ppdu = &fpdu[offset];
		size_t ppdu_length;
		int fragment_id;
		int ret;

		/* is there padding? */
		if (ppdu[0] == 0x00 && ppdu[1] == 0x00) {
			PRINT_RLE_DEBUG("padding detected at byte #%zu in FPDU", offset + 1);
			padding_detected = true;
			continue;
		}

		/* retrieve the fragment type and length in the first 2 bytes of the PPDU fragment */
		ppdu_length = get_fragment_length(ppdu);
		PRINT_RLE_DEBUG("%zu-byte PPDU detected at byte #%zu in FPDU",
		                ppdu_length, offset + 1);

		/* stop parsing the FPDU if the PPDU length is wrong */
		if (ppdu_length > (fpdu_length - offset)) {
			PRINT_RLE_ERROR("Invalid fragment size, fragment length too big for FPDU\n");
			PRINT_RLE_ERROR("Fragment length: %zu, Remaining FPDU size: %zu\n", ppdu_length,
			      fpdu_length - offset);
			status = RLE_DECAP_ERR;
			goto out;
		}

		/* stop deencapulation if there is no more SDU buffers */
		if ((*sdus_nr) == sdus_max_nr) {
			PRINT_RLE_ERROR("failed to decapsulate all SDUs from the FPDU: all %zu SDU buffers "
			                "are full, but FPDU is not fully parsed (current %zu-byte PPDU "
			                "fragment will be lost, as well as the %zu bytes of FPDU that "
			                "remain to be parsed)\n", sdus_max_nr, ppdu_length,
			                fpdu_length - offset);
			status = RLE_DECAP_ERR_SOME_DROP;
			goto out;
		}

		/* parse the PPDU fragment */
		PRINT_RLE_DEBUG("decapsule the %zu-byte PPDU", ppdu_length);
		ret = rle_receiver_deencap_data(receiver, ppdu, ppdu_length, &fragment_id,
		                                &sdus[*sdus_nr]);

		/* PPDU fragment successfully parsed, skip it */
		offset += ppdu_length;

		if ((ret != C_OK) && (ret != C_REASSEMBLY_OK)) {
			PRINT_RLE_ERROR("Error during reassembly.\n");
			if (fragment_id != -1) {
				rle_receiver_free_context(receiver, fragment_id);
			}
			status = RLE_DECAP_ERR;
		} else if (ret == C_REASSEMBLY_OK) {
			/* Potential SDU received. */
			(*sdus_nr)++;
		}
		PRINT_RLE_DEBUG("%zu bytes remaining to be parsed in FPDU",
		                fpdu_length - offset);
	}

	/* remaining FPDU bytes are padding: they should be all zero, warn if it is not the case */
	PRINT_RLE_DEBUG("%zu-byte padding detected", fpdu_length - offset);
	for (; offset < fpdu_length; offset++) {
		if (fpdu[offset] != 0x00) {
			PRINT_RLE_WARNING("FPDU padding contains octets non equal to 0x00 (at least byte #%zu "
			      "of the %zu-byte FPDU)\n", offset + 1, fpdu_length);
			break; /* stop padding verification after first error */
		}
	}

	PRINT_RLE_DEBUG("%zu SDU(s) decapsuled from FPDU", *sdus_nr);

out:
	return status;
}

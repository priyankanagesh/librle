/**
 * @file   pack.c
 * @brief  RLE packing functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "constants.h"
#include "rle.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>

#else

#include <linux/string.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_NAME "PACK"


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PUBLIC FUNCTIONS CODE -------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

enum rle_pack_status rle_pack_init(const unsigned char *const label, const size_t label_size,
                                   unsigned char *const fpdu,
                                   size_t *const fpdu_current_pos,
                                   size_t *const fpdu_remaining_size)
{
	enum rle_pack_status status;

	if ((label_size != 0 && label_size != 3 && label_size != 6) ||
	    (label_size > 0 && label == NULL)) {
		status = RLE_PACK_ERR_INVALID_LAB;
		goto exit_label;
	}

	if (fpdu == NULL || fpdu_current_pos == NULL || fpdu_remaining_size == NULL) {
		status = RLE_PACK_ERR;
		goto exit_label;
	}

	/* Check FPDU is empty */
	if((*fpdu_current_pos) != 0) {
		status = RLE_PACK_ERR;
		goto exit_label;
	}

	/* Check there is enough place for FPDU label */
	if ((*fpdu_remaining_size) < label_size) {
		status = RLE_PACK_ERR_FPDU_TOO_SMALL;
		goto exit_label;
	}

	/* when FPDU is empty, copy the FPDU label before the first PPDU */
	memcpy(fpdu, label, label_size);
	(*fpdu_current_pos) += label_size;
	(*fpdu_remaining_size) -= label_size;

	status = RLE_PACK_OK;

exit_label:
	return status;
}

enum rle_pack_status rle_pack(const unsigned char *const ppdu, const size_t ppdu_length,
                              const unsigned char *const label, const size_t label_size,
                              unsigned char *const fpdu,
                              size_t *const fpdu_current_pos,
                              size_t *const fpdu_remaining_size)
{
	enum rle_pack_status status;

	if (ppdu == NULL || ppdu_length == 0) {
		status = RLE_PACK_ERR_INVALID_PPDU;
		goto exit_label;
	}
	if ((label_size != 0 && label_size != 3 && label_size != 6) ||
	    (label_size > 0 && label == NULL)) {
		status = RLE_PACK_ERR_INVALID_LAB;
		goto exit_label;
	}
	if (fpdu == NULL || fpdu_current_pos == NULL || fpdu_remaining_size == NULL) {
		status = RLE_PACK_ERR;
		goto exit_label;
	}

	/* when FPDU is empty, we must have enough room for both the FPDU label and
	 * the first PPDU ; when the FPDU already contains at least one PPDU, we must
	 * have enough room for the new PPDU only */
	if (((*fpdu_current_pos) == 0 && (*fpdu_remaining_size) < (label_size + ppdu_length)) ||
	    ((*fpdu_current_pos) != 0 && (*fpdu_remaining_size) < ppdu_length)) {
		status = RLE_PACK_ERR_FPDU_TOO_SMALL;
		goto exit_label;
	}

	/* when FPDU is empty, copy the FPDU label before the first PPDU */
	if ((*fpdu_current_pos) == 0 && label_size > 0) {
		memcpy(fpdu, label, label_size);
		(*fpdu_current_pos) += label_size;
		(*fpdu_remaining_size) -= label_size;
	}

	/* copy the PPDU */
	memcpy(fpdu + (*fpdu_current_pos), ppdu, ppdu_length);
	(*fpdu_current_pos) += ppdu_length;
	(*fpdu_remaining_size) -= ppdu_length;

	status = RLE_PACK_OK;

exit_label:
	return status;
}

void rle_pad(unsigned char *const fpdu, const size_t fpdu_current_pos,
             const size_t fpdu_remaining_size)
{
	if (fpdu != NULL && fpdu_remaining_size != 0) {
		memset(fpdu + fpdu_current_pos, 0, fpdu_remaining_size);
	}
}

/**
 * @file   rle_log.c
 * @brief  definition of rle log module.
 * @author Josselin Vallet
 * @date   09/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include <rle.h>

static rle_trace_callback_t rle_trace_callback = (void*)0;

void rle_set_trace_callback(rle_trace_callback_t callback)
{
	rle_trace_callback = callback;
}

rle_trace_callback_t rle_get_trace_callback(void)
{
	return rle_trace_callback;
}

const rle_log_module_tuple_t* rle_get_log_modules_list(size_t *nb_modules)
{
	/* Declare a constant array describing the rle modules.
	 * It associates the two following informations: 
	 *    - the rle module id
	 *    - the rle module name
	 */
	static const rle_log_module_tuple_t rle_modules_list[] = {
		{RLE_MOD_ID_DEENCAP, "RLE_DEENCAP"},
		{RLE_MOD_ID_ENCAP, "RLE_ENCAP"},
		{RLE_MOD_ID_FRAGMENTATION, "RLE_FRAGMENTATION"},
		{RLE_MOD_ID_FRAGMENTATION_BUFFER, "RLE_FRAGMENTATION_BUFFER"},
		{RLE_MOD_ID_HEADER, "RLE_HEADER"},
		{RLE_MOD_ID_PACK, "RLE_PACK"},
		{RLE_MOD_ID_REASSEMBLY, "RLE_REASSEMBLY"},
		{RLE_MOD_ID_REASSEMBLY_BUFFER, "RLE_REASSEMBLY_BUFFER"},
		{RLE_MOD_ID_CONF, "RLE_CONF"},
		{RLE_MOD_ID_CTX, "RLE_CTX"},
		{RLE_MOD_ID_RECEIVER, "RLE_RECEIVER"},
		{RLE_MOD_ID_TRANSMITTER, "RLE_TRANSMITTER"},
		{RLE_MOD_ID_TRAILER, "RLE_TRAILER"}
	};
	/* if the pointer passed as argument is not null,
	 * set its pointed value to the number of rle log modules */
	if (nb_modules != NULL) {
		*nb_modules = sizeof(rle_modules_list) / sizeof(rle_modules_list[0]);
	}

	/* return a pointer to the module list */
	return &rle_modules_list[0];
} 

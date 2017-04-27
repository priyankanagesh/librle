/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file   encap.h
 * @brief  Definition of RLE encapsulation structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __ENCAP_H__
#define __ENCAP_H__

#include "rle_ctx.h"


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------------- PUBLIC FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief encapsulate data into an rle packet
 *
 *  @warning
 *
 *  @param rle_ctx			the rle fragment context
 *  @param rle_conf			the rle configuration
 *  @param data_buffer		data buffer's address to encapsulate
 *  @param data_length		data length to encapsulate
 *  @param protocol_type	the protocol type
 *
 *  @return C_ERROR if KO
 *		C_OK if OK
 *
 *  @ingroup
 */
int encap_encapsulate_pdu(struct rle_ctx_management *rle_ctx,
                          struct rle_config *rle_conf,
                          void *data_buffer, size_t data_length,
                          uint16_t protocol_type);

#endif /* __ENCAP_H__ */

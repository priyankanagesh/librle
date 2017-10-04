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
 * @file   rle_header_proto_type_field.h
 * @brief  Definition of RLE header protocol type fields constant values and meanings.
 *         Removed from header for more readibility, especialy since the ICD v.10 specifications.
 * @author Henrick Deschamps, based on Aurelien Castanie works.
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __KERNEL__

#include <stdint.h>
#include <stdbool.h>

#else

#include <linux/types.h>

#endif


#ifndef __RLE_HEADER_PROTO_TYPE_FIELD_H__
#define __RLE_HEADER_PROTO_TYPE_FIELD_H__

#include "rle.h"


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Label Type for implicit protocol type */
#define RLE_LT_IMPLICIT_PROTO_TYPE         2
/** Label Type for protocol signalling */
#define RLE_LT_PROTO_SIGNAL                3
/** Type field - protocol type not supressed */
#define RLE_T_PROTO_TYPE_NO_SUPP           0
/** Type field - protocol type supressed */
#define RLE_T_PROTO_TYPE_SUPP              1


/** Size of Protocol Type uncompressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_UNCOMP   2

/** Size of Protocol Type compressed field in Bytes */
#define RLE_PROTO_TYPE_FIELD_SIZE_COMP     1

/** Max protocol type compressed value */
#define RLE_PROTO_TYPE_MAX_COMP_VALUE      0xff


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------------- PUBLIC FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief Get the ALPDU label type depending on the protocol type.
 *
 * @param protocol_type                the SDU protocol_type.
 * @param is_protocol_type_suppressed  Whether protocol type is suppressed or not
 * @param type_0_alpdu_label_size      The size of the ALPDU label of type 0
 * @return                             The ALPDU label type in range [0-3]
 */
uint8_t get_alpdu_label_type(const uint16_t protocol_type,
                             const bool is_protocol_type_suppressed,
                             const uint8_t type_0_alpdu_label_size)
__attribute__((warn_unused_result));


#endif /* __RLE_HEADER_PROTO_TYPE_FIELD_H__ */

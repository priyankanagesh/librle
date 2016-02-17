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
 *  @brief         Get the ALPDU label type depending on the protocol type.
 *
 *  @param[in]     protocol_type                the SDU protocol_type.
 *  @param[in]     is_protocol_type_suppressed  1 if protocol type is suppressed, else 0.
 *
 *  @return        0 if OK, 1 if KO.
 *
 *  @ingroup
 */
int get_alpdu_label_type(const uint16_t protocol_type, const int is_protocol_type_suppressed);


#endif /* __RLE_HEADER_PROTO_TYPE_FIELD_H__ */

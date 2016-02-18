/**
 * @file   reassembly.h
 * @brief  Definition of RLE reassembly structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __REASSEMBLY_H__
#define __REASSEMBLY_H__

#include "rle_ctx.h"
#include "rle_conf.h"


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------------- PUBLIC FUNCTIONS ----------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx			the rle reassembly context
 *  @param pdu_buffer		pdu buffer's address to reassemble
 *  @param pdu_proto_type	the pdu protocol type
 *  @param pdu_length		the pdu buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_get_pdu(struct rle_ctx_management *rle_ctx, void *pdu_buffer, int *pdu_proto_type,
                       uint32_t *pdu_length);

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx			the rle reassembly context
 *  @param rle_conf                     the rle configuration
 *  @param data_buffer		data buffer's address to reassemble
 *  @param data_length		the data_buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
                              struct rle_configuration *rle_conf, void *data_buffer,
                              size_t data_length,
                              int frag_type);

/**
 * @brief Extract an ALPDU fragment from a complete PPDU.
 *
 * @param[in]  comp_ppdu           The PPDU.
 * @param[in]  ppdu_len            The PPDU length.
 * @param[out] alpdu_fragment      The ALPDU fragment extracted.
 * @param[out] alpdu_fragment_len  The length of the ALPDU fragment extracted.
 *
 * @return 0 if OK, else 1.
 *
 * @ingroup RLE reassembly
 */
int comp_ppdu_extract_alpdu_fragment(const unsigned char comp_ppdu[], const size_t ppdu_len,
                                     const unsigned char *alpdu_fragment[],
                                     size_t *alpdu_fragment_len);

/**
 * @brief Extract an ALPDU fragment from a start PPDU.
 *
 * @param[in]  start_ppdu          The PPDU.
 * @param[in]  ppdu_len            The PPDU length.
 * @param[out] alpdu_fragment      The ALPDU fragment extracted.
 * @param[out] alpdu_fragment_len  The length of the ALPDU fragment extracted.
 *
 * @return 0 if OK, else 1.
 *
 * @ingroup RLE reassembly
 */
int start_ppdu_extract_alpdu_fragment(const unsigned char start_ppdu[], const size_t ppdu_len,
                                      const unsigned char *alpdu_fragment[],
                                      size_t *const alpdu_fragment_len,
                                      size_t *const alpdu_total_len,
                                      int *const is_crc_used);

/**
 * @brief Extract an ALPDU fragment from a continue or end PPDU.
 *
 * @param[in]  cont_end_ppdu       The PPDU.
 * @param[in]  ppdu_len            The PPDU length.
 * @param[out] alpdu_fragment      The ALPDU fragment extracted.
 * @param[out] alpdu_fragment_len  The length of the ALPDU fragment extracted.
 *
 * @return 0 if OK, else 1.
 *
 * @ingroup RLE reassembly
 */
int cont_end_ppdu_extract_alpdu_fragment(const unsigned char cont_end_ppdu[], const size_t ppdu_len,
                                         const unsigned char *alpdu_fragment[],
                                         size_t *const alpdu_fragment_len);

/**
 * @brief Reassemble complete PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    reassembled_sdu  The reassembled SDU.
 *
 * @ingroup RLE receiver
 */
int reassembly_comp_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                         const size_t ppdu_length,
                         struct rle_sdu *const reassembled_sdu);

/**
 * @brief Start reassembly with start PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    index_ctx        The index of the reassmbly context.
 *
 * @ingroup RLE receiver
 */
int reassembly_start_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                          const size_t ppdu_length,
                          int *const index_ctx);

/**
 * @brief Continue reassembly with cont PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    index_ctx        The index of the reassmbly context.
 *
 * @ingroup RLE receiver
 */
int reassembly_cont_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                         const size_t ppdu_length,
                         int *const index_ctx);

/**
 * @brief End reassembly with end PPDU.
 *
 * @param[in,out] _this            The receiver module to use for reassembly.
 * @param[in]     ppdu             The PPDU containing ALPDU fragments to reassemble.
 * @param[in]     ppdu_length      The length of the PPDU.
 * @param[out]    reassembled_sdu  The reassembled SDU.
 *
 * @ingroup RLE receiver
 */
int reassembly_end_ppdu(struct rle_receiver *_this, const unsigned char ppdu[],
                        const size_t ppdu_length, int *const index_ctx,
                        struct rle_sdu *const reassembled_sdu);


#endif /* __REASSEMBLY_H__ */

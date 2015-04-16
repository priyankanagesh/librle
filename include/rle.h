/**
 * @file   rle.h
 * @brief  Interface file for the librle library.
 * @author Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __RLE_H__
#define __RLE_H__

#include <stddef.h>
#include <stdint.h>

/** Status of the encapsulation. */
enum rle_encap_status {
	RLE_ENCAP_OK,              /**< Ok.                                    */
	RLE_ENCAP_ERR,             /**< Default error. SDU should be dropped.  */
	RLE_ENCAP_ERR_NULL_TRMT,   /**< Error. The transmitter is NULL.        */
	RLE_ENCAP_ERR_SDU_TOO_BIG  /**< Error. SDU too big to be encapsulated. */
};

/** Status of the fragmentation. */
enum rle_frag_status {
	RLE_FRAG_OK,                  /**< Ok.                                                    */
	RLE_FRAG_ERR,                 /**< Default error. SDU should be dropped.                  */
	RLE_FRAG_ERR_NULL_TRMT,       /**< Error. The transmitter is NULL.                        */
	RLE_FRAG_ERR_BURST_TOO_SMALL, /**< Error. Burst size is too small.                        */
	RLE_FRAG_ERR_CONTEXT_IS_NULL, /**< Error. Context is NULL, ALPDU may be empty.            */
	RLE_FRAG_ERR_INVALID_SIZE     /**< Error. Remaining data size may be invalid in End PPDU. */
};

/** Status of the frame packing. */
enum rle_pack_status {
	RLE_PACK_OK,                 /**< Ok.                                                      */
	RLE_PACK_ERR,                /**< Default error. SDUs should be dropped.                   */
	RLE_PACK_ERR_FPDU_TOO_SMALL, /**< Error. FPDU is too small for the current PPDU. No drop.  */
	RLE_PACK_ERR_INVALID_PPDU,   /**< Error. Current PPDU is invalid, maybe NULL or bad size.  */
	RLE_PACK_ERR_INVALID_LAB     /**< Error. Current label is invalid, maybe NULL or bad size. */
};

/** Status of the decapsulation. */
enum rle_decap_status {
	RLE_DECAP_OK,            /**< Ok.                                                       */
	RLE_DECAP_ERR,           /**< Error. SDUs should be dropped.                            */
	RLE_DECAP_ERR_NULL_RCVR, /**< Error. The receiver is NULL.                              */
	RLE_DECAP_ERR_ALL_DROP,  /**< Error. All current SDUs were dropped. Some may be lost.   */
	RLE_DECAP_ERR_SOME_DROP, /**< Error. Some SDUs were dropped. Some may be lost.          */
	RLE_DECAP_ERR_INV_FPDU,  /**< Error. Invalid FPDU. Maybe Null or bad size.              */
	RLE_DECAP_ERR_INV_SDUS,  /**< Error. Given preallocated SDUs array is invalid.          */
	RLE_DECAP_ERR_INV_PL     /**< Error. Given preallocated payload label array is invalid. */
};

/**
 * RLE transmitter.
 * For encapsulation, fragmentation and packing.
 */
struct rle_transmitter;

/**
 * RLE receiver.
 * For decapsulation.
 */
struct rle_receiver;

/**
 * RLE Service Data Unit.
 * Interface for the encapsulation and decapsulation functions.
 */
struct rle_sdu {
	unsigned char *buffer;   /**< The buffer containing the RLE SDU.               */
	size_t size;             /**< The size of the previous buffer.                 */
	uint16_t protocol_type;  /**< The protocol type (uncompressed) of the RLE SDU. */
};

/**
 * RLE Context configuration.
 * Interface for the configuration initialisation in transmitter and receiver "new" functions.
 */
struct rle_context_configuration {
	uint8_t implicit_protocol_type; /**< Protocol type that could be omitted.                  */
	int use_alpdu_crc;              /**< If set to 1, RLE check on CRC, else if 0, Seq number. */
	int use_ptype_omission;         /**< If set to 1, implicit_protocol_type is omitted.       */
	int use_compressed_ptype;       /**< If set to 1, protocol types are compressed.           */
};

/**
 * @brief         Create and initialize a RLE transmitter module.
 *
 * @param[in]     configuration            The configuration of the RLE transmitter.
 *
 * @return        A pointer to the transmitter module.
 *
 * @ingroup       RLE transmitter
 */
struct rle_transmitter *rle_transmitter_new(const struct rle_context_configuration configuration);

/**
 * @brief         Destroy a RLE transmitter module.
 *
 * @param[in,out] transmitter              The transmitter to destroy.
 *
 * @ingroup       RLE transmitter
 */
void rle_transmitter_destroy(struct rle_transmitter *const transmitter);

/**
 * @brief         Create and initialize a RLE receiver module.
 *
 * @param[in]     configuration            The configuration of the RLE receiver.
 *
 * @return        A pointer to the receiver module.
 *
 * @ingroup       RLE receiver
 */
struct rle_receiver *rle_receiver_new(const struct rle_context_configuration configuration);

/**
 * @brief         Destroy a RLE receiver module.
 *
 * @param[in,out] receiver                 The receiver to destroy.
 *
 * @ingroup       RLE receiver
 */
void rle_receiver_destroy(struct rle_receiver *const receiver);

/**
 * @brief         RLE encapsulation. Encapsulate a SDU in a RLE ALPDU frame.
 *
 *                The ALPDU is stored in the internal context of the RLE transmitter
 *                waiting for eventual fragmentation. The fragments are retrieved
 *                by one or more calls to the \ref rle_fragment API function.
 *
 * @param[in,out] transmitter             The transmitter module.
 * @param[in]     sdu                     The RLE Service data unit to encapsulate.
 * @param[in]     frag_id                 Identify the context to which belongs the datas to encap.
 *
 * @return        Encapsulation status.
 *
 * @ingroup       RLE transmitter
 */
enum rle_encap_status rle_encapsulate(struct rle_transmitter *const transmitter,
                                      const struct rle_sdu sdu,
                                      const uint8_t frag_id);

/**
 * @brief         RLE fragmentation. Get the next PPDU fragment.
 *
 *                The ALPDU is stored in the internal context of the RLE transmitter.
 *                Call this function to retrieve a fragment of the ALDPU. Use function
 *                \ref rle_transmitter_stats_get_queue_size to determine if there is
 *                some ALDPU data to fragment.
 *
 * @param[in,out] transmitter             The transmitter module.
 * @param[in]     frag_id                 Identify the ALPDU to which belongs the datas to fragment.
 * @param[in]     remaining_burst_size    Remaining size in the burst.
 * @param[out]    ppdu                    Extracted Payload-adapted PDU (fragment of ALPDU).
 * @param[out]    ppdu_length             Size of the extracted PPDU.
 *
 * @return        Fragmentation status.
 *
 * @ingroup       RLE transmitter
 */
enum rle_frag_status rle_fragment(struct rle_transmitter *const transmitter, const uint8_t frag_id,
                                  const size_t remaining_burst_size, unsigned char *const ppdu,
                                  size_t *const ppdu_length);

/**
 * @brief         RLE frame packing. Pack the given PPDU in the given FPDU.
 *
 * @param[in]     ppdu                    A PPDU to pack.
 * @param[in]     ppdu_length             The PPDU size.
 * @param[in]     label                   The FPDU label fields.
 * @param[in]     label_size              Size of the FPDU label fields.
 * @param[in,out] fpdu                    Generated/modified Frame PDU.
 * @param[in,out] fpdu_current_pos        Current position in the FPDU.
 * @param[in,out] fpdu_remaining_size     Remaining size in the FPDU.
 *
 * @return        Frame packing status.
 *
 * @ingroup       RLE transmitter
 */
enum rle_pack_status rle_pack(const unsigned char *const ppdu, const size_t ppdu_length,
                              const unsigned char *const label, const size_t label_size,
                              unsigned char *const fpdu,
                              size_t *const fpdu_current_pos,
                              size_t *const fpdu_remaining_size);

/**
 * @brief         RLE decapsulation function. Decapsulate the given FPDU into zero or more SDUs.
 *
 *                The function returns all of the SDUs that are fully decapsulated.
 *                If some PPDU fragments are missing for some of them, the fragments
 *                that are already received are kept in the internal contexts of the
 *                library. Next calls to the function may complete them, they will
 *                then be added to \ref sdus.
 *                The payload label is extracted in a preallocated buffer depending on the size
 *                given by the caller. This size is known by the type of fpdu awaited and the
 *                predefined size given by ETSI EN 301 545-2 V1.2.1, tab. 7-10 p. 119.
 *
 * @param[in,out] receiver                The receiver module.
 * @param[in]     fpdu                    The FPDU to decapsulate.
 * @param[in]     fpdu_length             The size of the FPDU.
 * @param[in,out] sdus                    The SDUs array to extract from the FPDU, preallocated.
 * @param[in]     sdus_max_nr             The SDUs array size, max number of extractable SDUs.
 * @param[out]    sdus_nr                 The current number of SDUs in the SDUs array.
 * @param[in,out] payload_label           The identifier of the RCST, preallocated.
 * @param[in]     payload_label_size      The size of the paylod label.
 *
 * @return        decapsulation status.
 *
 * @ingroup       RLE receiver
 */
enum rle_decap_status rle_decapsulate(struct rle_receiver *const receiver,
                                      const unsigned char *const fpdu, const size_t fpdu_length,
                                      struct rle_sdu sdus[],
                                      const size_t sdus_max_nr, size_t *const sdus_nr,
                                      unsigned char *const payload_label,
                                      const size_t payload_label_size);

/**
 * @brief         Get occupied size of a queue (frag_id) in a RLE transmitter module.
 *
 * @param[in]     transmitter             The transmitter module. Must be initialize.
 * @param[in]     fragment_id             Fragment id to use. Must be valid.
 *
 * @return        Number of octets present in a queue.
 *
 * @ingroup       RLE transmitter statistics
 */
size_t rle_transmitter_stats_get_queue_size(const struct rle_transmitter *const transmitter,
                                            const uint8_t fragment_id);

/**
 * @brief         Get total number of successfully sent SDU in a RLE transmitter module.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 *
 * @return        Number of SDUs sent successfully.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_ok(const struct rle_transmitter *const transmitter);

/**
 * @brief         Get total number of dropped SDU in a RLE transmitter module.
 *
 *                In transmission, a SDU may be dropped during encapsulation, fragmentation or
 *                packing in error cases.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 *
 * @return        Number of dropped SDUs.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_dropped(const struct rle_transmitter *const transmitter);

/**
 * @brief         Get total number of sent octets in a RLE transmitter module.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 *
 * @return        Number of octets sent.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_bytes(const struct rle_transmitter *const transmitter);

/**
 * @brief         Get occupied size of a queue (frag_id) in a RLE receiver module.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              Fragment id to use. Must be valid.
 *
 * @return        Number of octets prereceived in a queue.
 *
 * @ingroup       RLE receiver statistics
 */
size_t rle_receiver_stats_get_queue_size(const struct rle_receiver *const receiver,
                                         const uint8_t fragment_id);

/**
 * @brief         Get total number of successfully received SDUs in a RLE receiver module.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 *
 * @return        Number of SDUs received successfully.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_ok(const struct rle_receiver *const receiver);

/**
 * @brief         Get total number of dropped SDUs in a RLE receiver module.
 *
 *                In reception, a SDU may be dropped in decapsulation in error cases.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 *
 * @return        Number of dropped SDUs.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_dropped(const struct rle_receiver *const receiver);

/**
 * @brief         Get total number of lost SDUs in a RLE receiver module.
 *
 *                In reception, a SDU may be lost in decapsulation if the Seq numbers or the CRC
 *                are not the expected ones. When the CRC is wrong, one packet is count as lost,
 *                but when the SeqNo is not the expected one, the difference between them is
 *                compute and the counter is increase by the number of missing SeqNos.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 *
 * @return        Number of lost SDUs.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_lost(const struct rle_receiver *const receiver);

/**
 * @brief         Get total number of received octets in a RLE receiver module.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 *
 * @return        Number of octets received.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_bytes(const struct rle_receiver *const receiver);

#endif /* __RLE_H__ */

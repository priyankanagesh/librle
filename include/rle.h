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

#ifndef __KERNEL__

#include <stddef.h>
#include <stdint.h>

#else

#include <linux/stddef.h>
#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/** Max size of input packet (PDU) in Bytes */
#define RLE_MAX_PDU_SIZE                        4088

/** Max size of PPDU Payload (PPDU_PL) in Bytes */
#define RLE_MAX_PPDU_PL_SIZE                    2047

/**  Max value of fragment_id */
#define RLE_MAX_FRAG_ID                         7

/**  Max number of fragment id */
#define RLE_MAX_FRAG_NUMBER                     (RLE_MAX_FRAG_ID + 1)

/** Status of the encapsulation. */
enum rle_encap_status {
	RLE_ENCAP_OK,                /**< Ok.                                    */
	RLE_ENCAP_ERR,               /**< Default error. SDU should be dropped.  */
	RLE_ENCAP_ERR_NULL_TRMT,     /**< Error. The transmitter is NULL.        */
	RLE_ENCAP_ERR_NULL_F_BUFF,   /**< Error. Fragmentation buffer is NULL.   */
	RLE_ENCAP_ERR_N_INIT_F_BUFF, /**< Error. Fragmentation buffer not init.  */
	RLE_ENCAP_ERR_SDU_TOO_BIG    /**< Error. SDU too big to be encapsulated. */
};

/** Status of the fragmentation. */
enum rle_frag_status {
	RLE_FRAG_OK,                  /**< Ok.                                                    */
	RLE_FRAG_ERR,                 /**< Default error. SDU should be dropped.                  */
	RLE_FRAG_ERR_NULL_TRMT,       /**< Error. The transmitter is NULL.                        */
	RLE_FRAG_ERR_NULL_F_BUFF,     /**< Error. Fragmentation buffer is NULL.                   */
	RLE_FRAG_ERR_N_INIT_F_BUFF,   /**< Error. Fragmentation buffer not init.                  */
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

/** Status of RLE header size. */
enum rle_header_size_status {
	RLE_HEADER_SIZE_OK,                    /**< OK. */
	RLE_HEADER_SIZE_ERR,                   /**< Default error, returned size may be false. */
	RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC, /**< Error. Size cannot be calculated.*/
};

/** Different kind of FPDUs */
enum rle_fpdu_types {
	RLE_LOGON_FPDU,        /**< Log on FPDU. */
	RLE_CTRL_FPDU,         /**< Control FPDU. */
	RLE_TRAFFIC_FPDU,      /**< Traffic only FPDU. */
	RLE_TRAFFIC_CTRL_FPDU, /**< Traffic and control FPDU. */
};

/** Protocol types field values compressed. */
enum {
	/* for signaling. */
	RLE_PROTO_TYPE_SIGNAL_COMP              = 0x42,
	/* for VLAN. */
	RLE_PROTO_TYPE_VLAN_COMP                = 0x0f,
	RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD = 0x31,
	RLE_PROTO_TYPE_VLAN_QINQ_COMP           = 0x19,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_COMP    = 0x1a,
	/* for IPv4/v6. */
	RLE_PROTO_TYPE_IP_COMP                  = 0x30,
	RLE_PROTO_TYPE_IPV4_COMP                = 0x0d,
	RLE_PROTO_TYPE_IPV6_COMP                = 0x11,
	/* for ARP. */
	RLE_PROTO_TYPE_ARP_COMP                 = 0x0e,
	RLE_PROTO_TYPE_FALLBACK                 = 0xff,
};

/** Protocol types field values uncompressed. */
enum {
	/* for signaling */
	RLE_PROTO_TYPE_SIGNAL_UNCOMP            = 0x0082,
	/* for VLAN */
	RLE_PROTO_TYPE_VLAN_UNCOMP              = 0x8100,
	RLE_PROTO_TYPE_VLAN_QINQ_UNCOMP         = 0x88a8,
	RLE_PROTO_TYPE_VLAN_QINQ_LEGACY_UNCOMP  = 0x9100,
	/* for IPv4/v6 */
	RLE_PROTO_TYPE_IPV4_UNCOMP              = 0x0800,
	RLE_PROTO_TYPE_IPV6_UNCOMP              = 0x86dd,
	/* for ARP */
	RLE_PROTO_TYPE_ARP_UNCOMP               = 0x0806,
};

/**
 * Special procotol type values.
 *
 * Chosen from among reserved values in IEEE public EtherType list.
 * May evolve in the future.
 *
 * @see http://standards.ieee.org/develop/regauth/ethertype/eth.txt
 */
enum {
	RLE_PROTO_TYPE_RESERVED                 = 0x0b04,
	RLE_PROTO_TYPE_USER_DEFINED,
	RLE_PROTO_TYPE_IPV4_OR_IPV6,
	RLE_PROTO_TYPE_ADJACENT_2BYTES_PTYPE
};


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------- PROTECTED STRUCTS AND TYPEDEFS --------------------------------*/
/*------------------------------------------------------------------------------------------------*/

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
 * Fragmentation buffer.
 * Used to stock an SDU, encapsulate it in ALPDU and fragment it in PPDU.
 * Automaticaly manipulated in RLE context, but can be manually used, for traffics that don't need
 * fragmentation context for instance.
 */
struct rle_frag_buf;


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PUBLIC STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

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
 * RLE configuration
 *
 * Interface for the configuration initialisation in transmitter and receiver "new" functions.
 */
struct rle_config {

	/**
	 * @brief Whether RLE may use omit the protocol type
	 *
	 * If set to 1, the protocol type is omitted for ALPDUs whose protocol type
	 * matches the implicit_protocol_type.
	 */
	int allow_ptype_omission;

	/**
	 * @brief Whether RLE may compress the protocol type to 1 byte
	 *
	 * If set to 1, RLE tries to compress protocol types from 2 bytes to 1 byte.
	 * If compression is not possible (compressed value for a protocol type is
	 * not known), then 3 bytes are required.
	 */
	int use_compressed_ptype;

	/**
	 * @brief Whether RLE may use CRC for protection or not
	 *
	 * If set to 1, RLE may use CRC for protection. If set to 0, RLE may not.
	 *
	 * If both allow_alpdu_crc and allow_alpdu_sequence_number are set to 1,
	 * RLE uses sequence number.
	 */
	int allow_alpdu_crc;

	/**
	 * @brief Whether RLE may use sequence number for protection or not
	 *
	 * If set to 1, RLE may use sequence number for protection. If set to 0,
	 * RLE may not.
	 *
	 * If both allow_alpdu_crc and allow_alpdu_sequence_number are set to 1,
	 * RLE uses sequence number.
	 */
	int allow_alpdu_sequence_number;

	/**
	 * @brief Whether the optional first byte of the payload header is present
	 *
	 * If set to 1, the optional first byte of the payload header is present. If
	 * set to 0, the first byte is not present.
	 *
	 * Only value 0 is supported at the moment.
	 */
	int use_explicit_payload_header_map;

	/**
	 * @brief The implicit protocol type
	 *
	 * The implicit protocol type is used for protocol omission if
	 * allow_ptype_omission is set to 1.
	 */
	uint8_t implicit_protocol_type;

	/**
	 * @brief The size of the PPDU label when not explicitly indicated
	 *
	 * This is a value on 4 bits.
	 *
	 * Not used at the moment.
	 */
	uint8_t implicit_ppdu_label_size;

	/**
	 * @brief The size of the payload label when not explicitly indicated
	 *
	 * This is a value on 4 bits.
	 *
	 * Not used at the moment.
	 */
	uint8_t implicit_payload_label_size;

	/**
	 * @brief The size of the ALPDU label for label type 0
	 *
	 * The size of the ALPDU label associated with the indication of the
	 * configurable-size ALPDU label type '0'.
	 *
	 * This is a value on 4 bits.
	 *
	 * Not used at the moment.
	 */
	uint8_t type_0_alpdu_label_size;
};

/**
 * RLE transmitter statistics.
 */
struct rle_transmitter_stats {
	uint64_t sdus_in;       /**< Number of SDUs received for sending.   */
	uint64_t sdus_sent;     /**< Number of SDUs sent.                   */
	uint64_t sdus_dropped;  /**< Number of SDUs dropped.                */
	uint64_t bytes_in;      /**< Number of octets received for sending. */
	uint64_t bytes_sent;    /**< Number of octets sent.                 */
	uint64_t bytes_dropped; /**< Number of octets dropped.              */
};

/**
 * RLE receiver statistics.
 */
struct rle_receiver_stats {
	uint64_t sdus_received;     /**< Number of SDUs received.               */
	uint64_t sdus_reassembled;  /**< Number of SDUs reassembled in SDUs.    */
	uint64_t sdus_dropped;      /**< Number of SDUs dropped.                */
	uint64_t sdus_lost;         /**< Number of SDUs lost.                   */
	uint64_t bytes_received;    /**< Number of octets received for sending. */
	uint64_t bytes_reassembled; /**< Number of octets sent.                 */
	uint64_t bytes_dropped;     /**< Number of octets dropped.              */
};


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PUBLIC FUNCTIONS ---------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 * @brief         Create and initialize a RLE transmitter module.
 *
 * @param[in]     conf  The configuration of the RLE transmitter.
 *
 * @return        A pointer to the transmitter module.
 *
 * @ingroup       RLE transmitter
 */
struct rle_transmitter *rle_transmitter_new(const struct rle_config *const conf)
	__attribute__((warn_unused_result));

/**
 * @brief         Destroy a RLE transmitter module.
 *
 * @param[in,out] transmitter              The transmitter to destroy.
 *
 * @ingroup       RLE transmitter
 */
void rle_transmitter_destroy(struct rle_transmitter **const transmitter);

/**
 * @brief         Create and initialize a RLE receiver module.
 *
 * @param[in]     conf  The configuration of the RLE receiver.
 *
 * @return        A pointer to the receiver module.
 *
 * @ingroup       RLE receiver
 */
struct rle_receiver *rle_receiver_new(const struct rle_config *const conf)
	__attribute__((warn_unused_result));

/**
 * @brief         Destroy a RLE receiver module.
 *
 * @param[in,out] receiver                 The receiver to destroy.
 *
 * @ingroup       RLE receiver
 */
void rle_receiver_destroy(struct rle_receiver **const receiver);

/**
 * @brief         Create a new fragmentation buffer.
 *
 * @return        The fragmentation buffer if OK, else NULL
 *
 * @ingroup       RLE Fragmentation buffer
 */
struct rle_frag_buf *rle_frag_buf_new(void)
	__attribute__((warn_unused_result));

/**
 * @brief         Destroy a fragmentation buffer.
 *
 * @param[in,out] f_buff                   The fragmentation buffer to destroy.
 *
 * @ingroup       RLE Fragmentation buffer
 */
void rle_frag_buf_del(struct rle_frag_buf **const f_buff);

/**
 * @brief         Initialize (eventually reinitialize) a fragmentation buffer.
 *
 * @param[in,out] f_buff                   The fragmentation buffer to (re)initialize.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer
 */
int rle_frag_buf_init(struct rle_frag_buf *const f_buff)
	__attribute__((warn_unused_result));

/**
 * @brief         Copy an SDU in a fragmentation buffer.
 *
 *                SDU is copied in context when given for encapsulation, thus, the SDU given
 *                as argument to this function can be freed once encapsulation is done.
 *
 * @param[in,out] f_buff   The fragmentation buffer. Must contains an SDU and be
 *                         initialized.
 * @param[in]     sdu      The SDU to copy.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE Fragmentation buffer
 */
int rle_frag_buf_cpy_sdu(struct rle_frag_buf *const f_buff,
                         const struct rle_sdu *const sdu)
	__attribute__((warn_unused_result));

/**
 * @brief         RLE encapsulation. Encapsulate a SDU in a RLE ALPDU frame.
 *
 *                The ALPDU is stored in the internal context of the RLE transmitter
 *                waiting for eventual fragmentation. The fragments are retrieved
 *                by one or more calls to the \ref rle_fragment API function.
 *                SDU is copied in context when given for encapsulation, thus, the SDU given
 *                as argument to this function can be freed once encapsulation is done.
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
                                      const struct rle_sdu *const sdu,
                                      const uint8_t frag_id)
	__attribute__((warn_unused_result));

/**
 * @brief         RLE encapsulation. Encapsulate a SDU in a RLE ALPDU frame.
 *
 * @param[in,out] transmitter             The transmitter module. Used for its conf only, its
 *                                        context is not use.
 * @param[in,out] f_buff                  The fragmentation buffer (containing an SDU).
 *
 * @return        Encapsulation status.
 *
 * @ingroup       RLE transmitter
 */
enum rle_encap_status rle_encap_contextless(struct rle_transmitter *const transmitter,
                                            struct rle_frag_buf *const f_buff)
	__attribute__((warn_unused_result));

/**
 * @brief         RLE fragmentation. Get the next PPDU fragment.
 *
 *                The ALPDU is stored in the internal context of the RLE transmitter.
 *                Call this function to retrieve a fragment of the ALDPU. Use function
 *                \ref rle_transmitter_stats_get_queue_size to determine if there is
 *                some ALDPU data to fragment.
 *
 * @warning       /!\ REAL ZERO COPY /!\ The PPDU returned belongs to the fragmentation buffer.
 *                If the library user does not copy nor send it before asking for another one, the
 *                first PPDU might be corrupted by the PPDU header of the second one.
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
enum rle_frag_status rle_fragment(struct rle_transmitter *const transmitter,
                                  const uint8_t frag_id,
                                  const size_t remaining_burst_size,
                                  unsigned char *ppdu[],
                                  size_t *const ppdu_length)
	__attribute__((warn_unused_result));

/**
 * @brief         RLE fragmentation. Get the next PPDU fragment.
 *
 *                RLE fragmentation of ALPDU created without context.
 *                As there is not context, only COMPLETE PPDU is supported.
 *
 * @warning       /!\ REAL ZERO COPY /!\ The PPDU returned belongs to the fragmentation buffer.
 *                If the library user does not copy nor send it before asking for another one, the
 *                first PPDU might be corrupted by the PPDU header of the second one.
 *
 * @param[in,out] transmitter             The transmitter module. Used for its conf only, its
 *                                        context is not use.
 * @param[in,out] f_buff                  The fragmentation buffer (containing an ALPDU).
 * @param[out]    ppdu                    Extracted Payload-adapted PDU (fragment of ALPDU).
 * @param[in,out] ppdu_length             Asked size of the extracted PPDU. The size returned is the
 *                                        one really extracted.
 *                                        for instance, if the caller wants a 100 octets PPDU, but
 *                                        the RLE library can only return 80 octets PPDU,
 *                                        ppdu_length will be overwritten with 80.
 *
 * @return        Fragmentation status.
 *
 * @ingroup       RLE transmitter
 */
enum rle_frag_status rle_frag_contextless(struct rle_transmitter *const transmitter,
                                          struct rle_frag_buf *const f_buff,
                                          unsigned char **const ppdu,
                                          size_t *const ppdu_length)
	__attribute__((warn_unused_result));

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
enum rle_pack_status rle_pack(const unsigned char *const ppdu,
                              const size_t ppdu_length,
                              const unsigned char *const label,
                              const size_t label_size,
                              unsigned char *const fpdu,
                              size_t *const fpdu_current_pos,
                              size_t *const fpdu_remaining_size)
	__attribute__((warn_unused_result));

/**
 * @brief         RLE padding. Pad the given FPDU with 0x00 octets.
 *
 * @param[in,out] fpdu                    Frame PDU to pad.
 * @param[in]     fpdu_current_pos        Current position in the FPDU.
 * @param[in]     fpdu_remaining_size     Remaining size in the FPDU.
 *
 * @ingroup       RLE transmitter
 */
void rle_pad(unsigned char *const fpdu,
             const size_t fpdu_current_pos,
             const size_t fpdu_remaining_size);

/**
 * @brief         RLE decapsulation function. Decapsulate the given FPDU into zero or more SDUs.
 *
 *                The function returns all of the SDUs that are fully decapsulated.
 *                If some PPDU fragments are missing for some of them, the fragments
 *                that are already received are kept in the internal contexts of the
 *                library. Next calls to the function may complete them, they will
 *                then be added to the \e sdus output parameter.
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
                                      const unsigned char *const fpdu,
                                      const size_t fpdu_length,
                                      struct rle_sdu sdus[],
                                      const size_t sdus_max_nr,
                                      size_t *const sdus_nr,
                                      unsigned char *const payload_label,
                                      const size_t payload_label_size)
	__attribute__((warn_unused_result));

/**
 * @brief         Get occupied size of a queue (frag_id) in an RLE transmitter module.
 *
 * @param[in]     transmitter             The transmitter module. Must be initialize.
 * @param[in]     fragment_id             Fragment id to use. Must be valid.
 *
 * @return        Number of octets present in a queue.
 *
 * @ingroup       RLE transmitter statistics
 */
size_t rle_transmitter_stats_get_queue_size(const struct rle_transmitter *const transmitter,
                                            const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of ready to be sent SDU of an RLE transmitter queue.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of SDUs sent successfully.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_sdus_in(const struct rle_transmitter *const transmitter,
                                                   const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of successfully sent SDU of an RLE transmitter queue.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of SDUs sent successfully.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_sdus_sent(const struct rle_transmitter *const transmitter,
                                                     const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of dropped SDU of an RLE transmitter queue.
 *
 *                In transmission, a SDU may be dropped during encapsulation, fragmentation or
 *                packing in error cases.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of dropped SDUs.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_sdus_dropped(const struct rle_transmitter *const transmitter,
                                                        const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of ready to be sent octets of an RLE transmitter queue.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of octets sent.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_bytes_in(const struct rle_transmitter *const transmitter,
                                                    const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of sent octets of an RLE transmitter queue.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of octets sent.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_bytes_sent(const struct rle_transmitter *const transmitter,
                                                      const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of dropped octetsof an RLE transmitter queue.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of octets sent.
 *
 * @ingroup       RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_bytes_dropped(const struct rle_transmitter *const transmitter,
                                                         const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Dump all the statistics of a given RLE transmitter queue in an RLE stats
 *                structure.
 *
 * @param[in]     transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 * @param[out]    stats                    The RLE stats structure.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE transmitter statistics
 */
int rle_transmitter_stats_get_counters(const struct rle_transmitter *const transmitter,
                                       const uint8_t fragment_id,
                                       struct rle_transmitter_stats *const stats)
	__attribute__((warn_unused_result));

/**
 * @brief         Reset all the statistics of a given RLE transmitter queue in an RLE stats
 *
 * @param[in,out] transmitter              The transmitter module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @ingroup       RLE transmitter statistics
 */
void rle_transmitter_stats_reset_counters(struct rle_transmitter *const transmitter,
                                          const uint8_t fragment_id);

/**
 * @brief         Get occupied size of a queue (frag_id) in a RLE receiver queue.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              Fragment id to use. Must be valid.
 *
 * @return        Number of octets prereceived in a queue.
 *
 * @ingroup       RLE receiver statistics
 */
size_t rle_receiver_stats_get_queue_size(const struct rle_receiver *const receiver,
                                         const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of partially received SDUs of an RLE receiver queue.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of SDUs received successfully.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_sdus_received(const struct rle_receiver *const receiver,
                                                      const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of successfully reassembled SDUs of an RLE receiver queue.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of SDUs received successfully.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_sdus_reassembled(const struct rle_receiver *const receiver,
                                                         const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of dropped SDUs of an RLE receiver queue.
 *
 *                In reception, a SDU may be dropped in decapsulation in error cases.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of dropped SDUs.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_sdus_dropped(const struct rle_receiver *const receiver,
                                                     const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of lost SDUs of an RLE receiver queue.
 *
 *                In reception, a SDU may be lost in decapsulation if the Seq numbers or the CRC
 *                are not the expected ones. When the CRC is wrong, one packet is count as lost,
 *                but when the SeqNo is not the expected one, the difference between them is
 *                compute and the counter is increase by the number of missing SeqNos.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of lost SDUs.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_sdus_lost(const struct rle_receiver *const receiver,
                                                  const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of received octets of partially received SDUs of an RLE receiver
 *                queue.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of octets received.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_bytes_received(const struct rle_receiver *const receiver,
                                                       const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of received octets of successfully reassembled in SDUs of an RLE
 *                receiver queue.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of octets received.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_bytes_reassembled(const struct rle_receiver *const receiver,
                                                          const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Get total number of received octets of dropped SDUs of an RLE receiver queue.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @return        Number of octets received.
 *
 * @ingroup       RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_bytes_dropped(const struct rle_receiver *const receiver,
                                                      const uint8_t fragment_id)
	__attribute__((warn_unused_result));

/**
 * @brief         Dump all the statistics of a given RLE receiver queue in an RLE stats
 *                structure.
 *
 * @param[in]     receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 * @param[out]    stats                    The RLE stats structure.
 *
 * @return        0 if OK, else 1.
 *
 * @ingroup       RLE receiver statistics
 */
int rle_receiver_stats_get_counters(const struct rle_receiver *const receiver,
                                    const uint8_t fragment_id,
                                    struct rle_receiver_stats *const stats)
	__attribute__((warn_unused_result));

/**
 * @brief         Reset all the statistics of a given RLE receiver queue in an RLE stats
 *
 * @param[in,out] receiver                 The receiver module. Must be initialize.
 * @param[in]     fragment_id              The fragment id of the queue.
 *
 * @ingroup       RLE receiver statistics
 */
void rle_receiver_stats_reset_counters(struct rle_receiver *const receiver,
                                       const uint8_t fragment_id);

/**
 * @brief       RLE header decompression of protocol type function.
 *
 * @param[in]   compressed_ptype                A compressed protocol type to uncompress.
 *
 * @return      The uncompressed protocol type.
 *
 * @ingroup     RLE header
 */
uint16_t rle_header_ptype_decompression(uint8_t compressed_ptype)
	__attribute__((warn_unused_result));

/**
 * @brief       RLE header check if protocol type is compressible function.
 *
 * @param[in]   uncompressed_ptype  An uncompressed protocol type to compress.
 *
 * @return      0 if the protocol type is compressible else 1.
 *
 * @ingroup     RLE header
 */
int rle_header_ptype_is_compressible(uint16_t uncompressed_ptype)
	__attribute__((warn_unused_result));

/**
 * @brief       RLE header compression of protocol type function.
 *
 * @param[in]   uncompressed_ptype  An uncompressed protocol type to compress.
 * @param[in]   frag_buf            The SDU to encapsulate
 *
 * @return      The compressed protocol type.
 *
 * @ingroup     RLE header
 */
uint8_t rle_header_ptype_compression(const uint16_t uncompressed_ptype,
                                     const struct rle_frag_buf *const frag_buf)
	__attribute__((warn_unused_result, nonnull(2)));

/**
 * @brief         Get the size of an RLE headers overhead (ALPDU + PPDU + FPDU headers).
 *                Those header sizes are known only for signal fpdus, and traffic-control fpdus.
 *
 * @param[in]     conf               The rle module configuration (unused for the
 *                                   moment, may be used for evolution or adaption
 *                                   of RLE)
 * @param[in]     fpdu_type          The type of the FPDU.
 * @param[out]    rle_header_size    The size of the RLE header in octets.
 *
 * @return        RLE_HEADER_SIZE_OK if size is calculated,
 *                RLE_HEADER_SIZE_ERR on generic errors,
 *                RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC when size cannot be calculated due
 *                to RLE prediction limitations (for instance, on traffic only burst).
 *
 */
enum rle_header_size_status rle_get_header_size(const struct rle_config *const conf,
                                                const enum rle_fpdu_types fpdu_type,
                                                size_t *const rle_header_size)
	__attribute__((warn_unused_result));


#endif /* __RLE_H__ */

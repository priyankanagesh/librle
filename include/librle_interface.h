/**
 * @file   librle_interface.h
 * @brief  Interface file for the librle library.
 * @author Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __LIBRLE_INTERFACE_H__
#define __LIBRLE_INTERFACE_H__

#include <stddef.h>
#include <stdint.h>

#include "rle_transmitter.h"
#include "rle_receiver.h"

/** Different kind of network access for transmission context. */
enum rle_network_accesses {
	RLE_TRANSPARENT_STAR_ALOHA_ACCESS,    /**< Transparent star network with ALOHA slot access. */
	RLE_TRANSPARENT_STAR_DEDICATED_ACCESS /**< Transparent star network with dedicated access. */
};

/** States of SDU protocol type. */
enum rle_pdu_protocol_type_states {
	RLE_SDU_PROTOCOL_TYPE_OMITTED,      /**< The protocol type is omitted. */
	RLE_SDU_PROTOCOL_TYPE_UNCOMPRESSED, /**< The protocol type is uncompressed. */
	RLE_SDU_PROTOCOL_TYPE_COMPRESSED    /**< The protocol type is compressed. */
};

/** Types of burst. */
enum rle_burst_types {
	RLE_BURST_CONTROL,        /**< Control. */
	RLE_BURST_LOGON,          /**< Logon. */
	RLE_BURST_TRAFFIC,        /**< Traffic. */
	RLE_BURST_TRAFFIC_CONTROL /**< Traffic and control. */
};

/** Status of the encapsulation. */
enum rle_encapsulation_status {
	RLE_ENCAPSULATION_OK,   /**< Ok. */
	RLE_ENCAPSULATION_ERROR /**< Error. Packet should be drop. */
};

/** Status of the fragmentation. */
enum rle_fragmentation_status {
	RLE_FRAGMENTATION_OK,   /**< Ok. */
	RLE_FRAGMENTATION_ERROR /**< Error. Packet should be drop. */
};

/** Status of the frame packing. */
enum rle_frame_packing_status {
	RLE_FRAME_PACKING_OK,   /**< Ok. */
	RLE_FRAME_PACKING_ERROR /**< Error. Packet should be drop. */
};

/** Status of the decapsulation. */
enum rle_decapsulation_status {
	RLE_DECAPSULATION_OK,   /**< Ok. */
	RLE_DECAPSULATION_ERROR /**< Error. Packet should be drop. */
};

/**
 * RLE transmitter module.
 * For encapsulation, fragmentation and packing.
 */
typedef struct transmitter_module *rle_transmitter_module;

/**
 * RLE receiver module.
 * For decapsulation.
 */
typedef struct receiver_module *rle_receiver_module;

/**
 * RLE Service Data Unit.
 * Interface for the encapsulation and decapsulation functions.
 */
struct rle_sdu {
	unsigned char *rle_sdu_buffer;   /**< The buffer containing the RLE SDU. */
	size_t rle_sdu_size;             /**< The size of the previous buffer. */
	uint16_t rle_sdu_protocol_type;  /**< The protocol type (uncompressed) of the RLE SDU. */
}

/**
 * @brief			Create a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 * @return			A pointer to the transmitter module.
 *
 * @ingroup			RLE transmitter
 */
rle_transmitter_module *rle_transmitter_module_new(void);

/**
 * @brief			Initialize a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 *	@param[in,out]	transmitter					The transmitter to initialize.
 *
 * @ingroup			RLE transmitter
 */
void rle_transmitter_module_init(rle_transmitter_module *const transmitter);

/**
 * @brief			Destroy a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 *	@param[in,out]	transmitter					The transmitter to destroy.
 *
 * @ingroup			RLE transmitter
 */
void rle_transmitter_module_destroy(rle_transmitter_module *const transmitter);

/**
 * @brief			Create a RLE receiver module.
 *
 * @warning			TODO Body
 *
 * @return			A pointer to the receiver module.
 *
 * @ingroup			RLE receiver
 */
rle_receiver_module *rle_receiver_module_new(void);

/**
 * @brief			Initialize a RLE receiver module.
 *
 * @warning			TODO Body
 *
 *	@param[in,out]	receiver						The receiver to initialize.
 *
 * @ingroup			RLE receiver
 */
void rle_receiver_module_init(rle_receiver_module *const receiver);

/**
 * @brief			Destroy a RLE receiver module.
 *
 * @warning			TODO Body
 *
 *	@param[in,out]	receiver						The receiver to destroy.
 *
 * @ingroup			RLE receiver
 */
void rle_receiver_module_destroy(rle_receiver_module *const receiver);

/**
 * @brief			RLE encapsulation function.
 *
 * @warning			TODO Body
 *
 * @param[in,out]	transmitter					The transmitter module.
 * @param[in]		sdu							The RLE Service data unit to encapsulate.
 *
 * @return			Encapsulation status.
 *
 * @ingroup			RLE transmitter
 */
enum rle_encapsulation_status rle_encapsulation(rle_transmitter_module *const transmitter,
                                                const struct rle_sdu sdu);

/**
 * @brief			RLE fragmentation function.
 *
 * @warning			TODO Body + more status.
 *
 * @param[in,out]	transmitter					The transmitter module.
 * @param[in]		frag_id						Identify the ALPDU to wich belongs the datas to fragment.
 * @param[in]		burst_configuration		Configuration of the protocol type.
 * @param[in]		remaining_burst_size		Remaining ALPDU datas size.
 * @param[out]		ppdu							Extracted Payload-adapted PDU (fragment of ALPDU).
 * @param[out]		ppdu_length					Size of the extracted PPDU.
 *
 * @return			Fragmentation status.
 *
 * @ingroup			RLE transmitter
 */
enum rle_fragmentation_status rle_fragmentation(rle_transmitter_module *const transmitter,
                                                const uint8_t frag_id,
                                                const enum burst_types burst_configuration,
                                                const size_t remaining_burst_size,
                                                unsigned char *const ppdu,
                                                size_t *const ppdu_length);

/**
 * @brief			RLE frame packing function.
 *
 * @warning			TODO Body + more status.
 *
 * @param[in,out]	transmitter					The transmitter module.
 * @param[in]		frag_id						Identify the ALPDU to wich belongs the datas to pack.
 * @param[in]		ppdu							A PPDU to pack.
 * @param[in]		ppdu_length					The PPDU size.
 * @param[in]		burst_size					Size of the burst.
 * @param[in]		burst_type					Type of burst.
 * @param[in]		label							The FPDU label fields.
 * @param[in]		label_size					Size of the FPDU label fields.
 * @param[in,out]	fpdu							Generated/modified Frame PDU.
 * @param[in,out] current_pos					Current position in the FPDU.
 * @param[out]		remaining_size				Remaining size in the FPDU.
 *
 * @return			Frame packing status.
 *
 * @ingroup			RLE transmitter
 */
enum rle_frame_packing_status rle_frame_packing(rle_transmitter_module *const transmitter,
                                                const uint8_t frag_id, const unsigned char *ppdu,
                                                const size_t ppdu_length, const size_t burst_size,
                                                const enum burst_types burst_type,
                                                const char *const label, const size_t label_size,
                                                unsigned char *const fpdu,
                                                size_t *const current_pos,
                                                size_t *const remaining_size);
/**
 * @brief			RLE decapsulation function.
 *
 * @warning			TODO Body + More status.
 *
 * @param[in,out]	receiver						The receiver module.
 * @param[in]		fpdu							The FPDU to decapsulate.
 * @param[in]		fpdu_length					The size of the FPDU.
 * @param[in]		sdu_array_size				The size of the SDU array.
 * @param[in,out]	rle_sdu_array				The SDU list extracted from the FPDU, preallocated.
 * @param[out]		number_of_sdu				The number of SDU in the SDU list.
 * @param[out]		payload_label				The identifier of the RCST.
 * @param[out]		payload_label_size		The size of the paylod label.
 *
 * @return			decapsulation status.
 *
 * @ingroup			RLE receiver
 */
enum rle_decapsulation_status rle_decapsulation(rle_receiver_module *const receiver,
                                                const unsigned char *const fpdu, size_t fpdu_length,
                                                const size_t sdu_array_size,
                                                struct rle_sdu rle_sdu_array[],
                                                size_t *const number_of_sdu,
                                                unsigned char *const payload_label,
                                                size_t *const payload_label_size);

/**
 * @brief			Get occupied size of a queue (frag_id) in a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 * @param[in]		transmitter					The transmitter module.
 * @param[in]		fragment_id					Fragment id to use.
 *
 * @return			Number of octets present in a queue.
 *
 * @ingroup			RLE transmitter statistics
 */
size_t rle_transmitter_stats_get_queue_size(const rle_transmitter_module *const transmitter,
                                            const uint8_t fragment_id);

/**
 * @brief			Get total number of successfully sent packets in a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 * @param[in]		transmitter					The transmitter module.
 *
 * @return			Number of packets sent successfully.
 *
 * @ingroup			RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_ok(const rle_transmitter_module *const transmitter);

/**
 * @brief			Get total number of dropped packets in a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 * @param[in]		transmitter					The transmitter module.
 *
 * @return			Number of dropped packets.
 *
 * @ingroup			RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_dropped(const rle_transmitter_module *const transmitter);

/**
 * @brief			Get total number of lost packets in a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 * @param[in]		transmitter					The transmitter module.
 *
 * @return			Number of lost packets.
 *
 * @ingroup			RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_lost(const rle_transmitter_module *const transmitter);

/**
 * @brief			Get total number of sent octets in a RLE transmitter module.
 *
 * @warning			TODO Body
 *
 * @param[in]		transmitter					The transmitter module.
 *
 * @return			Number of octets sent.
 *
 * @ingroup			RLE transmitter statistics
 */
uint64_t rle_transmitter_stats_get_counter_bytes(const rle_transmitter_module *const transmitter);

/**
 * @brief			Get occupied size of a queue (frag_id) in a RLE receiver module.
 *
 * @warning			TODO Body
 *
 * @param[in]		receiver						The receiver module.
 * @param[in]		fragment_id					Fragment id to use.
 *
 * @return			Number of octets prereceived in a queue.
 *
 * @ingroup			RLE receiver statistics
 */
size_t rle_receiver_stats_get_queue_size(const rle_receiver_module *const receiver,
                                         uint8_t fragment_id);

/**
 * @brief			Get total number of successfully received packets in a RLE receiver module.
 *
 * @warning			TODO Body
 *
 * @param[in]		receiver						The receiver module.
 *
 * @return			Number of packets received successfully.
 *
 * @ingroup			RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_ok(const rle_receiver_module *const receiver);

/**
 * @brief			Get total number of dropped packets in a RLE receiver module.
 *
 * @warning			TODO Body
 *
 * @param[in]		receiver						The receiver module.
 *
 * @return			Number of dropped packets.
 *
 * @ingroup			RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_dropped(const rle_receiver_module *const receiver);

/**
 * @brief			Get total number of lost packets in a RLE receiver module.
 *
 * @warning			TODO Body
 *
 * @param[in]		receiver						The receiver module.
 *
 * @return			Number of lost packets.
 *
 * @ingroup			RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_lost(const rle_receiver_module *const receiver);

/**
 * @brief			Get total number of received octets in a RLE receiver module.
 *
 * @warning			TODO Body
 *
 * @param[in]		receiver						The receiver module.
 *
 * @return			Number of octets received.
 *
 * @ingroup			RLE receiver statistics
 */
uint64_t rle_receiver_stats_get_counter_bytes(const rle_receiver_module *const receiver);

#endif /* __LIBRLE_INTERFACE_H__ */

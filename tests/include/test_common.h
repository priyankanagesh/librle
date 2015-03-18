/**
 * @file   test_common.h
 * @brief  Definition of test for the RLE library
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_COMMON_H__
#define __TEST_COMMON_H__

#include "rle_transmitter.h"
#include "rle_receiver.h"

#define LINUX_COOKED_HDR_LEN  16

#define FAKE_BURST_MAX_SIZE 4096

/* Size of an Ethernet Mac address and position of its protocol type field defined for simple and
 * explicit manipulation in our tests. */
#define ETHER_MAC_ADDR_SIZE 6
#define ETHER_PTYPE_POS (2 * (ETHER_MAC_ADDR_SIZE))

enum options {
	DISABLE_FRAGMENTATION = 0,
	ENABLE_FRAGMENTATION,
	DISABLE_CRC,
	ENABLE_CRC,
	DISABLE_SEQ,
	ENABLE_SEQ /* 5 */
};

/* RLE modules */
struct transmitter_module *transmitter;
struct receiver_module *receiver;
int opt_verbose_flag;

/* RLE statistics */
uint64_t TX_total_sent_size;
uint64_t TX_total_sent_pkt;
uint64_t TX_total_lost_pkt;
uint64_t TX_total_drop_pkt;
uint64_t RX_total_received_size;
uint64_t RX_total_received_pkt;
uint64_t RX_total_lost_pkt;
uint64_t RX_total_drop_pkt;

int create_rle_modules(void);
int destroy_rle_modules(void);
void compare_packets(char *pkt1, char *pkt2, int size1, int size2 __attribute__ ((unused)));

void clear_tx_stats(void);
void print_tx_stats(void);
void clear_rx_stats(void);
void print_rx_stats(void);

/* Simple encapsulation/deencapsulation test */
int init_test_encap_deencap(char *pcap_file_name, int nb_fragment_id);
int init_test_frag_rea(char *pcap_file_name, uint32_t param_ptype, uint16_t param_bsize,
                       int nb_fragment_id,
                       int use_crc);
int init_test_frag_rea_min_max(char *pcap_file_name, int nb_fragment_id, int use_crc);

enum protocol_type_state {
	PROTOCOL_TYPE_UNCOMPRESSED,
	PROTOCOL_TYPE_COMPRESSED,
	PROTOCOL_TYPE_SUPPRESSED
};

void test_common_set_protocol_type_state(uint32_t value);

#endif /* __TEST_COMMON_H__ */

#ifndef _TEST_COMMON_H
#define _TEST_COMMON_H

#include "rle_transmitter.h"
#include "rle_receiver.h"

#define LINUX_COOKED_HDR_LEN  16

#define FAKE_BURST_MAX_SIZE 4096

#define DISABLE_FRAGMENTATION 0
#define ENABLE_FRAGMENTATION 1

#define DISABLE_CRC 0
#define ENABLE_CRC 1

#define DISABLE_SEQ 0
#define ENABLE_SEQ 1

/* RLE modules */
struct transmitter_module *transmitter;
struct receiver_module *receiver;
int opt_verbose_flag;

/* RLE statistics */
uint64_t TX_total_sent_size;
uint64_t TX_total_sent_pkt;
uint64_t TX_total_lost_pkt;
uint64_t TX_total_drop_pkt;

int create_rle_modules(void);
int destroy_rle_modules(void);
void compare_packets(char *pkt1, char *pkt2, int size1, int size2 __attribute__ ((unused)));

void clear_stats(void);
void print_stats(void);

/* Simple encapsulation/deencapsulation test */
int init_test_encap_deencap(char *pcap_file_name, int nb_fragment_id);
int init_test_frag_rea(char *pcap_file_name, uint32_t param_ptype,
		uint16_t param_bsize,
		int nb_fragment_id, int use_crc);
int init_test_frag_rea_min_max(char *pcap_file_name, int nb_fragment_id,
		int use_crc);


#endif /* _TEST_COMMON_H */

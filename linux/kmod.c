/**
 * @file   kmdo.c
 * @brief  Export the RLE library to the Linux kernel
 * @author Henrick Deschamps
 * @date   05/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <linux/module.h>
#include "rle.h"

#define PACKAGE_NAME    "RLE library"
#define PACKAGE_VERSION "0.0.1"
#define PACKAGE_LICENSE "Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved"

MODULE_VERSION(PACKAGE_VERSION);
MODULE_LICENSE(PACKAGE_LICENSE);
MODULE_AUTHOR("Didier Barvaux, Henrick Deschamps, "
              "Thales Alenia Space France, Viveris Technologies");
MODULE_DESCRIPTION(PACKAGE_NAME ", version " PACKAGE_VERSION);

EXPORT_SYMBOL(rle_transmitter_new);
EXPORT_SYMBOL(rle_transmitter_destroy);
EXPORT_SYMBOL(rle_receiver_new);
EXPORT_SYMBOL(rle_receiver_destroy);
EXPORT_SYMBOL(rle_encapsulate);
EXPORT_SYMBOL(rle_fragment);
EXPORT_SYMBOL(rle_pack);
EXPORT_SYMBOL(rle_pad);
EXPORT_SYMBOL(rle_decapsulate);
EXPORT_SYMBOL(rle_transmitter_stats_get_queue_size);
EXPORT_SYMBOL(rle_transmitter_stats_get_counter_sdus_in);
EXPORT_SYMBOL(rle_transmitter_stats_get_counter_sdus_sent);
EXPORT_SYMBOL(rle_transmitter_stats_get_counter_sdus_dropped);
EXPORT_SYMBOL(rle_transmitter_stats_get_counter_bytes_in);
EXPORT_SYMBOL(rle_transmitter_stats_get_counter_bytes_sent);
EXPORT_SYMBOL(rle_transmitter_stats_get_counter_bytes_dropped);
EXPORT_SYMBOL(rle_transmitter_stats_get_counters);
EXPORT_SYMBOL(rle_transmitter_stats_reset_counters);
EXPORT_SYMBOL(rle_receiver_stats_get_queue_size);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_sdus_received);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_sdus_reassembled);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_sdus_dropped);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_sdus_lost);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_bytes_received);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_bytes_reassembled);
EXPORT_SYMBOL(rle_receiver_stats_get_counter_bytes_dropped);
EXPORT_SYMBOL(rle_receiver_stats_get_counters);
EXPORT_SYMBOL(rle_receiver_stats_reset_counters);
EXPORT_SYMBOL(rle_header_ptype_decompression);
EXPORT_SYMBOL(rle_header_ptype_is_compressible);
EXPORT_SYMBOL(rle_header_ptype_compression);
EXPORT_SYMBOL(rle_get_header_size);
EXPORT_SYMBOL(rle_f_buff_new);
EXPORT_SYMBOL(rle_f_buff_del);
EXPORT_SYMBOL(rle_f_buff_init);
EXPORT_SYMBOL(rle_f_buff_cpy_sdu);
EXPORT_SYMBOL(rle_encap_contextless);
EXPORT_SYMBOL(rle_frag_contextless);

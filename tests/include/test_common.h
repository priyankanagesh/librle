#ifndef _TEST_COMMON_H
#define _TEST_COMMON_H

#include "rle_transmitter.h"
#include "rle_receiver.h"

/* RLE modules */
struct transmitter_module *transmitter;
struct receiver_module *receiver;

int create_rle_modules(void);
int destroy_rle_modules(void);
void compare_packets(char *pkt1, char *pkt2, int size1, int size2 __attribute__ ((unused)));

#endif /* _TEST_COMMON_H */

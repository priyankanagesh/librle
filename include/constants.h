/**
 * @file   constants.h
 * @author Aurelien Castanie
 *
 * @brief  Definition of RLE context and status structure, functions and variables
 *
 *
 */

#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#ifndef __KERNEL__

#include <stdlib.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#else

#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif

#define C_TRUE		1
#define C_FALSE		0

#define C_OK		0
#define C_REASSEMBLY_OK 1
#define C_ERROR		-1
#define C_ERROR_DROP	-2
#define C_ERROR_BUF	-3

#define IP_VERSION_4	4
#define IP_VERSION_6	6

#define SIZEOF_PTR	sizeof(char *)

/** Type of payload in RLE packet */
enum {
	RLE_PDU_COMPLETE,    /** Complete PDU */
	RLE_PDU_START_FRAG,  /** START packet/fragment of PDU */
	RLE_PDU_CONT_FRAG,   /** CONTINUATION packet/fragment of PDU */
	RLE_PDU_END_FRAG,   /** END packet/fragment of PDU */
} rle_payload_type;

#ifndef __KERNEL__

#define MALLOC(size_bytes)	malloc(size_bytes);
#define FREE(buf_addr)		free(buf_addr);
#define PRINT(x...)	do { \
				printf(x); \
			} while(0)

#else

/* vmalloc allocates size with 4K modulo so for 8*2565 = 20520B it would alloc 24K
 * kmalloc allocates size with power of two so for 20520B it would alloc 32K */
#define MALLOC(size_bytes)	kmalloc(size_bytes); /* vmalloc(size_bytes); */
#define FREE(buf_addr)		kfree(buf_addr); /* vfree(buf_addr); */
#define PRINT(x...)		printk(x);

#endif

#endif /* _CONSTANTS_H */


/**
 * @file   constants.h
 * @brief  Definition of RLE context and status structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#ifndef __KERNEL__

#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#else

#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif


/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define C_TRUE          1
#define C_FALSE         0

#define C_OK            0
#define C_REASSEMBLY_OK 1
#define C_ERROR         -1
#define C_ERROR_DROP    -2
#define C_ERROR_BUF     -3
#define C_ERROR_TOO_MUCH_FRAG -4
#define C_ERROR_FRAG_SIZE -5

#define IP_VERSION_4    4
#define IP_VERSION_6    6

#define SIZEOF_PTR      sizeof(char *)

/** Type of payload in RLE packet */
enum {
	RLE_PDU_COMPLETE,    /** Complete PDU */
	RLE_PDU_START_FRAG,  /** START packet/fragment of PDU */
	RLE_PDU_CONT_FRAG,   /** CONTINUATION packet/fragment of PDU */
	RLE_PDU_END_FRAG,   /** END packet/fragment of PDU */
};

#ifndef __KERNEL__

#define MALLOC(size_bytes)      malloc(size_bytes)
#define FREE(buf_addr)          free(buf_addr)
#define PRINT(x ...)     do { \
		printf(x); \
} while (0)

#else

#define MOD_NAME                "RLE: "
/* vmalloc allocates size with 4K modulo so for 8*2565 = 20520B it would alloc 24K
 * kmalloc allocates size with power of two so for 20520B it would alloc 32K */
#define MALLOC(size_bytes)      kmalloc(size_bytes, GFP_KERNEL) /* vmalloc(size_bytes); */
#define FREE(buf_addr)          kfree(buf_addr) /* vfree(buf_addr); */
#define PRINT(x ...)     do { \
		printk(KERN_ERR x); \
} while (0)

#define assert BUG_ON

#endif

#define __FILENAME__ \
	(strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#endif /* __CONSTANTS_H__ */

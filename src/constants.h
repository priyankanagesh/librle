/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#else

#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/stddef.h>
#include <linux/string.h>

#endif

#ifndef _REENTRANT
#define _REENTRANT
#endif


/*------------------------------------------------------------------------------------------------*/
/*---------------------------------- PUBLIC CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define C_OK            0
#define C_REASSEMBLY_OK 1
#define C_ERROR         -1

/** Type of payload in RLE packet */
enum {
	RLE_PDU_COMPLETE,    /** Complete PDU */
	RLE_PDU_START_FRAG,  /** START packet/fragment of PDU */
	RLE_PDU_CONT_FRAG,   /** CONTINUATION packet/fragment of PDU */
	RLE_PDU_END_FRAG,   /** END packet/fragment of PDU */
};

#define PRINT_LOG(level, x, ...) \
	do { \
		rle_trace_callback_t the_cb = rle_get_trace_callback(); \
		if (the_cb != NULL) { \
			the_cb(MODULE_ID, level, __FILE__, __LINE__, __func__, x, ## __VA_ARGS__); \
		} \
	} while(0)
#define PRINT_RLE_DEBUG(x, ...) PRINT_LOG(RLE_LOG_LEVEL_DEBUG, x, ## __VA_ARGS__)
#define PRINT_RLE_WARNING(x, ...) PRINT_LOG(RLE_LOG_LEVEL_WARNING, x, ## __VA_ARGS__)
#define PRINT_RLE_ERROR(x, ...) PRINT_LOG(RLE_LOG_LEVEL_ERROR, x, ## __VA_ARGS__)

#ifndef __KERNEL__

#define MALLOC(size_bytes)      malloc(size_bytes)
#define FREE(buf_addr)          free(buf_addr)

#else

/* vmalloc allocates size with 4K modulo so for 8*2565 = 20520B it would alloc 24K
 * kmalloc allocates size with power of two so for 20520B it would alloc 32K */
#define MALLOC(size_bytes)      kmalloc(size_bytes, GFP_KERNEL) /* vmalloc(size_bytes); */
#define FREE(buf_addr)          kfree(buf_addr) /* vfree(buf_addr); */

#define assert BUG_ON

/** 10Mb/s ethernet header */
struct ether_header
{
  u_int8_t  ether_dhost[ETH_ALEN];	/**< destination ethernet address */
  u_int8_t  ether_shost[ETH_ALEN];	/**< source ethernet address */
  u_int16_t ether_type;		         /**< packet type ID field	*/
} __attribute__((__packed__));

#endif

#endif /* __CONSTANTS_H__ */

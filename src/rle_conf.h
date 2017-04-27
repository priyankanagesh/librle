/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file   rle_conf.h
 * @brief  definition of rle configuration module.
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __RLE_CONF_H__
#define __RLE_CONF_H__

#include "rle.h"

#ifndef __KERNEL__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#else

#include <linux/stddef.h>
#include <linux/types.h>

#endif

/**
 * @brief Check the validity of the RLE configuration
 *
 * @param conf  The RLE configuration to check
 * @return      true if configuration is OK, false if KO
 */
bool rle_config_check(const struct rle_config *const conf)
	__attribute__((warn_unused_result));

/**
 *  @brief	Check if a given protocol type is omissible depending of the conf
 *
 *  @warning
 *
 *  @param	ptype    The protocol type
 *  @param	rle_conf The configuration
 *  @param  frag_buf The SDU to encapsulate
 *
 *  @return	true if omissible, else false
 *
 *  @ingroup
 */
bool ptype_is_omissible(const uint16_t ptype,
                        const struct rle_config *const rle_conf,
                        const struct rle_frag_buf *const frag_buf)
	__attribute__((warn_unused_result, nonnull(2, 3)));

#endif /* __RLE_CONF_H__ */

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
 *
 *  @return	true if omissible, else false
 *
 *  @ingroup
 */
int ptype_is_omissible(const uint16_t ptype, const struct rle_config *const rle_conf);

#endif /* __RLE_CONF_H__ */

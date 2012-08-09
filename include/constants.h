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

#define C_TRUE		1
#define C_FALSE		1

#define C_ERROR		-1
#define C_OK		0

#define IP_VERSION_4	4
#define IP_VERSION_6	6

enum rle_packet_type {
	RLE_COMPLETE_PACKET = 0,
	RLE_START_PACKET,
	RLE_CONT_PACKET,
	RLE_END_PACKET
};

#endif /* _CONSTANTS_H */


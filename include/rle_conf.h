/**
 * @file   rle_conf.h
 * @author aurelien castanie
 *
 * @brief  definition of rle configuration module.
 *
 *
 */

#ifndef _RLE_CONF_H
#define _RLE_CONF_H

/** Default protocol type */
#define RLE_CONF_DEFAULT_PTYPE	RLE_PROTO_TYPE_IPV4_UNCOMP
/** Default protocol type compression flag */
#define RLE_CONF_COMPRESS_PTYPE	C_FALSE
/** Default protocol type suppression flag */
#define RLE_CONF_SUPPRESS_PTYPE	C_FALSE

/** RLE configuration structure
 * to keep track of various RLE
 * flags and values */
struct rle_configuration;

/**
 *  @brief	Allocate memory for a new RLE configuration
 *
 *  @warning
 *
 *  @param	_this   Pointer to the new RLE configuration
 *
 *  @return	NULL	Allocation failed
 *		Pointer to the new RLE configuration otherwise
 *
 *  @ingroup
 */
struct rle_configuration *rle_conf_new(struct rle_configuration *_this);

/**
 *  @brief	Free memory used for a RLE configuration
 *
 *  @warning
 *
 *  @param	_this   Pointer to the RLE configuration to free
 *
 *  @return	C_ERROR Free memory failed
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
int rle_conf_destroy(struct rle_configuration *_this);

/**
 *  @brief	Initialize a RLE configuration
 *
 *  @warning
 *
 *  @param	protocol_type   New default protocol type
 *
 *  @return	C_ERROR protocol_type is an invalid protocol type value
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
void rle_conf_init(struct rle_configuration *_this);

/**
 *  @brief	Set the default protocol type
 *
 *  @warning
 *
 *  @param	protocol_type   New default protocol type
 *
 *  @return	C_ERROR protocol_type is an invalid protocol type value
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
int rle_conf_set_default_ptype(struct rle_configuration *_this,
				uint16_t protocol_type);

/**
 *  @brief	Get the current default protocol type
 *
 *  @warning
 *
 *  @param
 *
 *  @return	Current default protocol type
 *
 *  @ingroup
 */
int rle_conf_get_default_ptype(struct rle_configuration *_this);

/**
 *  @brief	Set the protocol type compression flag
 *
 *  @warning
 *
 *  @param	enable_ptype_compression Protocol type compression flag
 *
 *  @return	C_ERROR enable_ptype_compression is an invalid compression flag
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
int rle_conf_set_ptype_compression(struct rle_configuration *_this,
				int enable_ptype_compression);

/**
 *  @brief	Get current protocol type compression flag
 *
 *  @warning
 *
 *  @param
 *
 *  @return	Current protocol type compression flag
 *
 *  @ingroup
 */
int rle_conf_get_ptype_compression(struct rle_configuration *_this);

/**
 *  @brief	Set the protocol type suppression flag
 *
 *  @warning
 *
 *  @param	enable_ptype_suppression Protocol type suppression flag
 *
 *  @return	C_ERROR enable_ptype_suppression is an invalid suppression flag
 *		C_OK	Otherwise
 *
 *  @ingroup
 */
int rle_conf_set_ptype_suppression(struct rle_configuration *_this,
				int enable_ptype_suppression);

/**
 *  @brief	Get current protocol type suppression flag
 *
 *  @warning
 *
 *  @param
 *
 *  @return	Current protocol type suppression flag
 *
 *  @ingroup
 */
int rle_conf_get_ptype_suppression(struct rle_configuration *_this);

#endif /* _RLE_CONF_H */

/**
 * @file   ksat_rle.c
 * @author Aurelien Castanie
 *
 * @brief  RLE kernel module
 *
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <satdrv.h>
#include "constants.h"

int ksat_rle_tx_new(struct transmitter_module *_tx_rle)
{
	int ret_val = 0;
	struct transmitter_module *tx_rle = NULL;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	tx_rle = rle_transmitter_new();
	if (tx_rle == NULL) {
		PRINT(KERN_WARNING MOD_NAME "RLE module initialisation failed\n");
		goto fail;
	}

	/* TODO init create_sysfs_tree */

	_tx_rle = tx_rle;
	PRINT(KERN_INFO MOD_NAME "RLE module initialized\n");

	return C_OK;

fail:
	_tx_rle = NULL;
	module_put(THIS_MODULE);
	return C_ERROR;
}
EXPORT_SYMBOL_GPL(ksat_rle_tx_new);

void ksat_rle_tx_delete(struct transmitter_module *_tx_rle)
{
	int ret_val = 0;
	struct transmitter_module *tx_rle = NULL;

	PRINT(KERN_INFO MOD_NAME "Removing RLE module\n");
	tx_rle = _tx_rle;

	/* TODO remove_sysfs_tree */

	rle_transmitter_destroy(tx_rle);

	module_put(THIS_MODULE);
	PRINT(KERN_INFO MOD_NAME "RLE module removed\n");
}
EXPORT_SYMBOL_GPL(ksat_rle_tx_delete);

int ksat_rle_tx_encapsulation(const void *_rle_ctx, struct sk_buff *skb)
{

}
EXPORT_SYMBOL_GPL(ksat_rle_tx_encapsulation);

int ksat_rle_tx_get_fragment(const void *_rle_ctx, struct sk_buff *skb)
{

}
EXPORT_SYMBOL_GPL(ksat_rle_tx_get_fragment);

static void __init ksat_rle_module_init(void)
{
	/* TODO initialization of sysfs & callbacks code here */
}

static void __exit ksat_rle_module_exit(void)
{
	/* TODO cleanup of sysfs & callbacks code here */
}

module_init(ksat_rle_module_init);
module_exit(ksat_rle_module_exit);

MODULE_DESCRIPTION("Return Link Encapsulation for ksatdriver");
MODULE_AUTHOR("Aurelien Castanie");
MODULE_LICENSE("GPL");

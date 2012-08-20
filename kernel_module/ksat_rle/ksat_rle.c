/**
 * @file   ksat_rle.c
 * @author Aurelien Castanie
 *
 * @brief  RLE kernel module
 *
 *
 */

#include <linux/module.h>
#include <satdrv.h>

int __init ksat_rle_module_init(void)
{
	/* TODO initialization code here */
}

void __exit ksat_rle_module_exit(void)
{
	/* TODO cleanup code here */
}

module_init(ksat_rle_module_init);
module_exit(ksat_rle_module_exit);

MODULE_DESCRIPTION("Return Link Encapsulation for ksatdriver");
MODULE_AUTHOR("Aurelien Castanie");
MODULE_LICENSE("GPL");

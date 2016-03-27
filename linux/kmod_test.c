/**
 * @file    kmod_test.c
 * @brief   A small module for the Linux kernel to test RLE encapsulation / decapsulation.
 * @author  Henrick Deschamps <henrick.deschamps@toulouse.viveris.com>
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include "rle.h"

#define PACKAGE_NAME "librle_mod_test_non_reg_mod"

#define PACKAGE_VERSION "0.0.1"

/** The name of the file to read/write. */
#define PROC_NAME "librle_test_interface"

/** The maximal size for the FPDU packets */
#define MAX_FPUD_SIZE 10000

/** Max lenght of an SDU */
#define MAX_SDU_LENGTH 4088

/** Max length of an FPDU */
#define MAX_FPDU_SIZE 5000

/** Number of fragmentation/reassembly context */
#define MAX_FRAG_ID 8

/** Max number of SDUs to extract (1 per frag id) */
#define MAX_SDUS_NR MAX_FRAG_ID

/** Module parameter - size of the bursts for fragmentation (not packing). */
static int param_burst_size = 14;

/** Module parameters - modules configuration. */
static int param_implicit_protocol_type = 0x30; /** IP per default.          */
static int param_use_alpdu_crc = 0;             /** Seq No per default.      */
static int param_use_ptype_omission = 1;        /** Ommission per default.   */
static int param_use_compressed_ptype = 1;      /** Compression per default. */

/** A couple of RLE transmitter/receiver and the related buffers */
struct rle_couple {
	/** The RLE transmitter created by the module */
	struct rle_transmitter *transmitter;
	/** The RLE receiver created by the module */
	struct rle_receiver *receiver;

	/** The RLE context configuration interface for the modules */
	struct rle_config conf;

	/** The sdu in */
	struct rle_sdu sdu_in;
	/** The buffer in which to store the SDU to encap/frag/pack */
	unsigned char rle_sdu_in_buffer[MAX_SDU_LENGTH];

	/** The file to read/write */
	struct proc_dir_entry *proc_file;
};


/** The couple of RLE transmitter/receiver */
static struct rle_couple couple;

/** The buffer in which to store the FPDU to create */
static unsigned char fpdu[MAX_FPDU_SIZE];
/** The current position in the FPDU */
static size_t fpdu_current_pos = 0;
/** The remaining size in the FPDU */
static size_t fpdu_remaining_size = MAX_FPDU_SIZE;

/** Number of SDUs to read from the userspace trought the proc interface. */
static size_t number_of_sdus_to_read = 0;

/** Current SDU to read from the userspace trought the proc interface. */
static size_t current_sdu = 0;

/** buffers for the SDUs to read from the userspace. */
static unsigned char sdus_out_buffers[MAX_SDUS_NR][MAX_SDU_LENGTH];

/** SDUs to read from the userspace */
static struct rle_sdu sdus_out[MAX_SDUS_NR];

/** Frag ID for fragmentation/reassembly context. */
static uint8_t frag_id = 0;

/**
 * @brief Is the couple of RLE transmitter/receiver initialized ?
 *
 * This boolean value is used to create (or not create) the couple when
 * the /proc file is opened. The couple is created only when the /proc file is opened.
 */
static int couple_initialized = 0;


/**
 * @brief Init a RLE couple
 *
 * @param couple  The couple of RLE transmitter/receiver to initialize
 * @return        0 in case of success, non-zero otherwise
 */
int rle_couple_init(struct rle_couple *couple)
{
	pr_info("[%s] init RLE couple\n", THIS_MODULE->name);

	memset(couple, '\0', sizeof(struct rle_couple));

	couple->conf.allow_ptype_omission = param_use_ptype_omission > 0 ? 1 : 0;
	couple->conf.use_compressed_ptype = param_use_compressed_ptype > 0 ? 1 : 0;
	couple->conf.allow_alpdu_crc = param_use_alpdu_crc > 0 ? 1 : 0;
	couple->conf.allow_alpdu_sequence_number = param_use_alpdu_crc > 0 ? 0 : 1;
	couple->conf.use_explicit_payload_header_map = 0;
	couple->conf.implicit_protocol_type = (uint8_t)param_implicit_protocol_type;
	couple->conf.implicit_ppdu_label_size = 0;
	couple->conf.implicit_payload_label_size = 0;
	couple->conf.type_0_alpdu_label_size = 0;

	/* create the transmitter */
	couple->transmitter = rle_transmitter_new(&couple->conf);

	if (couple->transmitter == NULL) {
		pr_info("[%s] \t Error: RLE transmitter not created\n",
		        THIS_MODULE->name);
		goto error;
	}

	pr_info("[%s] \t RLE transmitter successfully created\n",
	        THIS_MODULE->name);

	/* create the receiver */
	couple->receiver = rle_receiver_new(&couple->conf);

	if (couple->receiver == NULL) {
		pr_info("[%s] \t Error: RLE receiver not created\n",
		        THIS_MODULE->name);
		goto free_transmitter;
	}

	pr_info("[%s] \t RLE receiver successfully created\n",
	        THIS_MODULE->name);


	couple->sdu_in.buffer = couple->rle_sdu_in_buffer;
	couple->sdu_in.size = 0;

	couple_initialized = 1;

	return 0;

free_transmitter:
	rle_transmitter_destroy(&couple->transmitter);
error:
	return 1;
}


/**
 * @brief Release a RLE couple
 *
 * @param couple  The couple of RLE transmitter/receiver to release
 */
void rle_couple_release(struct rle_couple *couple)
{
	pr_info("[%s] release RLE couple...\n", THIS_MODULE->name);

	/* destroy modules */
	if (couple->transmitter != NULL) {
		rle_transmitter_destroy(&couple->transmitter);
	}
	if (couple->receiver != NULL) {
		rle_receiver_destroy(&couple->receiver);
	}

	pr_info("[%s] RLE couple successfully released\n", THIS_MODULE->name);

	return;
}

/**
 * @brief Called when a /proc file is opened by userspace
 *
 * Initialize the RLE couples if not already done upon another /proc open.
 *
 * @param inode  The inode information on the /proc file
 * @param file   The file information on the /proc file
 * @param        0 in case of success, -EFAULT in case of error
 */
static int rle_proc_open(struct inode *inode, struct file *file)
{
	pr_info("[%s] proc file '%s' opened\n", THIS_MODULE->name,
	        file->f_path.dentry->d_name.name);

	/* initialize the RLE couple only if this is the first /proc file opened
	 * since the last close() */
	if (!couple_initialized) {
		int ret;

		/* initialize the compressor of the RLE couple */
		ret = rle_couple_init(&couple);
		if (ret != 0) {
			pr_err("[%s] \t failed to init RLE couple\n", THIS_MODULE->name);
			goto error;
		}
	}

	/* give the right couple object as private data for next file operations */
	file->private_data = (void *)&couple;

	return 0;

error:
	return -EFAULT;
}


/**
 * @brief Handle a write to /proc/libre_test_interface file from userspace
 *
 * @param file    The /proc file userspace writes to
 * @param buffer  The data userspace writes
 * @param count   The number of bytes of data
 * @param ppos    
 * @return        The number of bytes of data handled by the function,
 *                -EFAULT if another error occurs
 */
ssize_t rle_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
	enum rle_encap_status encap_status = RLE_ENCAP_ERR;
	enum rle_frag_status frag_status = RLE_FRAG_ERR;
	enum rle_pack_status pack_status = RLE_PACK_ERR;

	struct rle_couple *couple = file->private_data;
	size_t ret_copy = 0;
	int err = -ENOMEM;

	const size_t burst_size = (size_t)param_burst_size;
	const size_t payload_label_size = 3;
	unsigned char payload_label[3] = { 0x01, 0x02, 0x03 };



	/* new packet */
	couple->sdu_in.size = count;

	pr_info("[%s] start receiving a %zd-byte SDU\n", THIS_MODULE->name,
	        couple->sdu_in.size);

	ret_copy = copy_from_user((void *)couple->sdu_in.buffer, (const void *)buffer,
	                          couple->sdu_in.size);
	if (ret_copy != 0) {
		pr_err("[%s] cannot retrieve SDU from userspace: "
		       "copy_from_user failed.\n", THIS_MODULE->name);
		goto error;
	}
	err = -EFAULT;

	/* Start encapsulation */
	encap_status = rle_encapsulate(couple->transmitter, &couple->sdu_in, frag_id);
	if (encap_status != RLE_ENCAP_OK) {
		pr_err("[%s] failed to encapsulate the SDU\n", THIS_MODULE->name);
		goto error;
	}
	pr_info("[%s] SDU successfully encapsulated\n", THIS_MODULE->name);

	while (rle_transmitter_stats_get_queue_size(couple->transmitter, frag_id) != 0) {
		size_t ppdu_length = 0;
		unsigned char *ppdu;
		size_t fpdu_prev_pos = fpdu_current_pos + payload_label_size;

		/* Start fragmentation */
		frag_status =
		        rle_fragment(couple->transmitter, frag_id, burst_size, &ppdu,
		                     &ppdu_length);
		if (frag_status != RLE_FRAG_OK) {
			pr_err("[%s] failed to fragment the ALPDU\n", THIS_MODULE->name);
			goto error;
		}
		pr_info("[%s] ALPDU successfully fragmented\n", THIS_MODULE->name);

		/* Start packing */
		pack_status = rle_pack(ppdu, ppdu_length, payload_label, payload_label_size,
		                       fpdu, &fpdu_current_pos, &fpdu_remaining_size);
		if (pack_status != RLE_PACK_OK) {
			pr_err("[%s] failed to pack an FPDU (%d)\n", THIS_MODULE->name,
			       (int)pack_status);
			goto error;
		}
		pr_info("[%s] %zu-octets PPDU successfully packed. Current FPDU size: %zu\n",
		        THIS_MODULE->name, fpdu_current_pos - fpdu_prev_pos,
		        fpdu_current_pos);
	}
	frag_id = (frag_id + 1) % MAX_FRAG_ID;

	rle_pad(fpdu, fpdu_current_pos, fpdu_remaining_size);
	pr_info("[%s] FPDU padded\n", THIS_MODULE->name); 

	couple->sdu_in.size = 0;

	/* everything went fine */
	return count;

error:
	couple->sdu_in.size = 0;
	return err;
}


/**
 * @brief Handle a read from /proc/libre_test_interface file from userspace
 *
 * @param file    The /proc file userspace reads from
 * @param buffer  The data userspace reads
 * @param count   The number of bytes of data
 * @param ppos    
 * @return        The number of bytes of data handled by the function,
 *                -EFAULT if another error occurs
 */
ssize_t rle_proc_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos)
{
	enum rle_decap_status decap_status = RLE_DECAP_ERR;

	struct rle_couple *couple = file->private_data;
	int err = -EFAULT;
	size_t sdu_read_size = 0;
	size_t ret_copy = 0;

	if (number_of_sdus_to_read == 0) {
		size_t sdus_nr = 0;
		const size_t payload_label_out_size = 3;
		unsigned char payload_label_out[payload_label_out_size];
		size_t iterator;

		/* if one reads a packet when none is available, return an error */
		if (fpdu_current_pos == 0) {
			pr_err("[%s] cannot send SDU to userspace: "
			       "no FPDU available, write an SDU in the interface to provide the module an FPDU\n",
			       THIS_MODULE->name);
			goto error;
		}

		/* Init. the SDUs out buffers. */
		for (iterator = 0; iterator < MAX_SDUS_NR; ++iterator) {
			memset(sdus_out_buffers[iterator], '\0', MAX_SDU_LENGTH);
			sdus_out[iterator].buffer = sdus_out_buffers[iterator];
			sdus_out[iterator].size = 0;
		}

		/* Start decapsulating */
		decap_status = rle_decapsulate(couple->receiver, fpdu, MAX_FPDU_SIZE, sdus_out, MAX_SDUS_NR,
				         &sdus_nr, payload_label_out, payload_label_out_size);

		if (decap_status != RLE_DECAP_OK) {
			pr_err("[%s] failed to decapsulate an FPDU\n", THIS_MODULE->name);
			goto error;
		}
		pr_info("[%s] FPDU successfully decapsulated\n", THIS_MODULE->name);


		pr_info("[%s] %zu SDU%s decapsulated\n", THIS_MODULE->name, sdus_nr,
		        sdus_nr == 1 ? "" : "s");
		for (iterator = 0; iterator < sdus_nr; ++iterator) {
			pr_info("[%s] %zu-octets SDU decapsulated\n", THIS_MODULE->name,
			        sdus_out[iterator].size);
		}

		/* Reinit. FPDU */
		memset((void *)fpdu, '\0', MAX_FPDU_SIZE);
		fpdu_current_pos = 0;
		fpdu_remaining_size = MAX_FPDU_SIZE;

		/* Init. SDUs out iterator. */
		current_sdu = 0;
		number_of_sdus_to_read = sdus_nr;
	}

	/* userspace should provides a buffer that is large enough
	 * for the whole compressed packet */
	if (count < sdus_out[current_sdu].size) {
		pr_err("[%s] cannot send SDU to userspace: too large\n", THIS_MODULE->name);
		goto error;
	}

	/* send data to userspace */
	ret_copy = copy_to_user(buffer, (const void *)sdus_out[current_sdu].buffer, 
			                  sdus_out[current_sdu].size);

	if (ret_copy != 0) {
		pr_err("[%s] cannot send SDU to userspace: "
		       "copy_to_user failed. %zu-octets SDU n° %zu not copied.\n",
		       THIS_MODULE->name, ret_copy, current_sdu + 1);
		goto error;
	}
	pr_info("[%s] %zu-octets SDU n° %zu copied to user\n", THIS_MODULE->name,
	        sdus_out[current_sdu].size, current_sdu + 1);

	sdu_read_size = sdus_out[current_sdu].size;

	++current_sdu;
	--number_of_sdus_to_read;

   /* everything went fine */
	return sdu_read_size;

error:
	return err;
}


/**
 * @brief Handle a close() from userspace on a /proc file
 *
 * First close on one /proc entry, release the resources of the module,
 * so userspace should avoid using the /proc files after one of them
 * is closed. This could be improved by releasing resources when
 * the last /proc file is closed.
 *
 * @param inode  The inode information on the /proc file
 * @param file   The file information on the /proc file
 * @param        Always return 0 (success)
 */
static int rle_proc_close(struct inode *inode, struct file *file)
{
	if (couple_initialized) {
		rle_couple_release(&couple);
		couple_initialized = 0;
	}

	return 0;
}


/** File operations for /proc file */
static const struct file_operations rle_proc_fops = {
	.owner = THIS_MODULE,
	.open = rle_proc_open,
	.write = rle_proc_write,
	.read = rle_proc_read,
	.release = rle_proc_close,
};


/**
 * @brief Create /proc entry
 *
 * @param couple  The RLE couple for which to create the /proc entries
 * @return        0 in case of success, 1 in case of error
 */
int rle_proc_init(struct rle_couple *couple)
{
	pr_info("[%s] \t create interface /proc/%s...\n", THIS_MODULE->name, PROC_NAME);
	couple->proc_file = proc_create(PROC_NAME, S_IFREG | S_IRUSR | S_IWUSR, NULL, &rle_proc_fops);
	if (couple->proc_file == NULL) {
		pr_err("[%s] \t failed to create /proc/%s\n", THIS_MODULE->name, PROC_NAME);
		goto err;
	}

	return 0;

err:
	return 1;
}


/**
 * @brief Release the /proc entry
 */
void rle_proc_release(void)
{
	/* remove the /proc entry of the couple */
	remove_proc_entry(PROC_NAME, NULL);
}


/**
 * @brief The entry point of the kernel module
 *
 * @return  0 in case of success, non-zero otherwise
 */
int __init rle_test_init(void)
{
	int ret;

	pr_info("[%s] loading RLE test module...\n", THIS_MODULE->name);

	/* create /proc entry for the RLE couple */
	ret = rle_proc_init(&couple);
	if (ret != 0) {
		pr_err("[%s] failed to create /proc entry\n", THIS_MODULE->name);
		goto error;
	}

	pr_info("[%s] RLE test module successfully loaded\n", THIS_MODULE->name);
	pr_info("[%s] parameters:\n", THIS_MODULE->name);
	pr_info("[%s]\tPPDU segment sizes(burst size): %zu\n", THIS_MODULE->name,
			  (size_t)param_burst_size);
	pr_info("[%s]\timplicit protocol type:         0x%02x\n", THIS_MODULE->name,
			  (uint8_t)param_implicit_protocol_type);
	pr_info("[%s]\tuse alpdu CRC ?                 %s\n", THIS_MODULE->name,
			  param_use_alpdu_crc ? "True" : "False");
	pr_info("[%s]\tuse compression ?               %s\n", THIS_MODULE->name,
			  param_use_compressed_ptype ? "True" : "False");
	pr_info("[%s]\tuse omission ?                  %s\n", THIS_MODULE->name,
			  param_use_ptype_omission ? "True" : "False");

	memset((void *)fpdu, '\0', MAX_FPDU_SIZE);

	return 0;

error:
	return 1;
}


/**
 * @brief The exit point of the kernel module
 */
void __exit rle_test_exit(void)
{
	pr_info("[%s] unloading RLE test module...\n", THIS_MODULE->name);
	rle_proc_release();
	pr_info("[%s] RLE test module successfully unloaded\n",
	        THIS_MODULE->name);
}

module_param(param_burst_size, int, 0);
module_param(param_implicit_protocol_type, int, 0);
module_param(param_use_alpdu_crc, int, 0);
module_param(param_use_ptype_omission, int, 0);
module_param(param_use_compressed_ptype, int, 0);

MODULE_VERSION(PACKAGE_VERSION);
MODULE_LICENSE("Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved");
MODULE_AUTHOR("Didier Barvaux, Henrick Deschamps, "
              "Thales Alenia Space France, Viveris Technologies");
MODULE_DESCRIPTION("Module for testing " PACKAGE_NAME " " PACKAGE_VERSION);

module_init(rle_test_init);
module_exit(rle_test_exit);

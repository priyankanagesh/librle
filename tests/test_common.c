#include <stdio.h>
#include <string.h>
#include "constants.h"
#include "test_common.h"

struct transmitter_module *transmitter = NULL;
struct receiver_module *receiver = NULL;

int create_rle_modules(void)
{
	transmitter = rle_transmitter_new();

	if (transmitter == NULL) {
		PRINT("ERROR while creating a new RLE transmitter\n");
		return -1;
	}

	receiver = rle_receiver_new();

	if (receiver == NULL) {
		PRINT("ERROR while creating a new RLE receiver\n");
		rle_transmitter_destroy(transmitter);
		return -1;
	}

	return 0;
}

int destroy_rle_modules(void)
{
	if (transmitter != NULL)
		rle_transmitter_destroy(transmitter);

	if (receiver != NULL)
		rle_receiver_destroy(receiver);

	return 0;
}

void compare_packets(char *pkt1, char *pkt2, int size1, int size2 __attribute__ ((unused)))
{
	uint32_t j = 0;
	uint32_t i = 0;
	uint32_t k = 0;
	uint8_t nb_bytes_print = 16;
	uint32_t nb_bytes = nb_bytes_print;
	uint32_t nb_lines = size1 / nb_bytes_print;
	uint32_t remainder_bytes = size1 % nb_bytes_print;
	int byte_diff = C_FALSE;
	unsigned char str_pkt1[5 * nb_bytes_print];
	unsigned char str_pkt2[5 * nb_bytes_print];
	unsigned char str_byte1[8];
	unsigned char str_byte2[8];
	unsigned char str_sep[8];
	unsigned char str_diff[nb_bytes_print];

	memset((void *)str_pkt1, 0, (5 * nb_bytes_print));
	memset((void *)str_pkt2, 0, (5 * nb_bytes_print));

	sprintf((char *)str_sep, "\t|\t");

	/* print packets with nb_bytes_print bytes per line */
	for (i = 0; i < nb_lines; i++) {
		while (j < nb_bytes) {
			if (pkt1[j] != pkt2[j])
				byte_diff = C_TRUE;

			sprintf((char *)str_byte1, " %.02x ", (unsigned char)pkt1[j]);
			sprintf((char *)str_byte2, " %.02x ", (unsigned char)pkt2[j]);
			strcat((char *)str_pkt1, (char *)str_byte1);
			strcat((char *)str_pkt2, (char *)str_byte2);
			j++;
		}

		if (byte_diff == C_TRUE)
			sprintf((char *)str_diff, " # ");
		else
			sprintf((char *)str_diff, "   ");

		PRINT("[0x%08x] ", i * nb_bytes_print);
		PRINT("%s", str_diff);
		PRINT("%s", str_pkt1);
		PRINT("%s", str_sep);
		PRINT("%s", str_pkt2);
		PRINT("\n");

		nb_bytes += nb_bytes_print;
		byte_diff = C_FALSE;

		memset((void *)str_pkt1, 0, (5 * nb_bytes_print));
		memset((void *)str_pkt2, 0, (5 * nb_bytes_print));
	}

	/* print left over bytes */
	if (remainder_bytes != 0) {
		for (k = j; k < (j + remainder_bytes); k++) {
			if (pkt1[k] != pkt2[k])
				byte_diff = C_TRUE;

			sprintf((char *)str_byte1, " %.02x ", (unsigned char)pkt1[k]);
			sprintf((char *)str_byte2, " %.02x ", (unsigned char)pkt2[k]);
			strcat((char *)str_pkt1, (char *)str_byte1);
			strcat((char *)str_pkt2, (char *)str_byte2);
		}

		/* pad with whitespaces for missing bytes */
		for (k = 0; k < (nb_bytes_print - remainder_bytes); k++) {
			sprintf((char *)str_byte1, "    ");
			sprintf((char *)str_byte2, "    ");
			strcat((char *)str_pkt1, (char *)str_byte1);
			strcat((char *)str_pkt2, (char *)str_byte2);
		}

		if (byte_diff == C_TRUE)
			sprintf((char *)str_diff, " # ");
		else
			sprintf((char *)str_diff, "   ");

		PRINT("[0x%08x] ", (i + 1) * nb_bytes_print);
		PRINT("%s", str_diff);
		PRINT("%s", str_pkt1);
		PRINT("%s", str_sep);
		PRINT("%s", str_pkt2);
		PRINT("\n");

		byte_diff = C_FALSE;

		memset((void *)str_pkt1, 0, (5 * nb_bytes_print));
		memset((void *)str_pkt2, 0, (5 * nb_bytes_print));
	}
}

void clear_tx_stats(void)
{
	TX_total_sent_size = 0L;
	TX_total_sent_pkt = 0L;
	TX_total_lost_pkt = 0L;
	TX_total_drop_pkt = 0L;
}

void print_tx_stats(void)
{
	float avg_pkt_size = 0.0;

	TX_total_sent_size += rle_transmitter_get_counter_bytes(transmitter);
	TX_total_sent_pkt += rle_transmitter_get_counter_ok(transmitter);
	TX_total_lost_pkt += rle_transmitter_get_counter_lost(transmitter);
	TX_total_drop_pkt += rle_transmitter_get_counter_dropped(transmitter);

	/* avoid division by 0 */
	if (TX_total_sent_pkt != 0)
		avg_pkt_size = (float)(TX_total_sent_size/TX_total_sent_pkt);

	PRINT("INFO: TX status:\n"
			"\tTX total sent size \t\t\t%10lu\n"
			"\tTX total sent packets \t\t\t%10lu\n"
			"\tTX total lost packets \t\t\t%10lu\n"
			"\tTX total dropped packets \t\t%10lu\n"
			"\tTX average size per packet \t\t%10.2f\n",
			TX_total_sent_size,
			TX_total_sent_pkt,
			TX_total_lost_pkt,
			TX_total_drop_pkt,
			avg_pkt_size);
}

void clear_rx_stats(void)
{
	RX_total_received_size = 0L;
	RX_total_received_pkt = 0L;
	RX_total_lost_pkt = 0L;
	RX_total_drop_pkt = 0L;
}

void print_rx_stats(void)
{
	float avg_pkt_size = 0.0;

	RX_total_received_size += rle_receiver_get_counter_bytes(receiver);
	RX_total_received_pkt += rle_receiver_get_counter_ok(receiver);
	RX_total_lost_pkt += rle_receiver_get_counter_lost(receiver);
	RX_total_drop_pkt += rle_receiver_get_counter_dropped(receiver);

	/* avoid division by 0 */
	if (RX_total_received_pkt != 0)
		avg_pkt_size = (float)(RX_total_received_size/RX_total_received_pkt);

	PRINT("INFO: RX status:\n"
			"\tRX total received size \t\t\t%10lu\n"
			"\tRX total received packets \t\t%10lu\n"
			"\tRX total lost packets \t\t\t%10lu\n"
			"\tRX total dropped packets \t\t%10lu\n"
			"\tRX average size per packet \t\t%10.2f\n",
			RX_total_received_size,
			RX_total_received_pkt,
			RX_total_lost_pkt,
			RX_total_drop_pkt,
			avg_pkt_size);
}


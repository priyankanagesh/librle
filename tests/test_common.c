#include <stdio.h>
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
	int j = 0;
	int i = 0;
	int k = 0;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

	for(i = 0; i < size1; i++)
	{
		if(pkt1[i] != pkt2[i])
		{
			sep1 = '#';
			sep2 = '#';
		}
		else
		{
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

		/* make the output human readable */
		if(j >= 3 || (i + 1) >= size1)
		{
			for(k = 0; k < 4; k++)
			{
				if(k < (j + 1))
					PRINT("-> %s  ", str1[k]);
				else /* fill the line with blanks if nothing to print */
					PRINT("        ");
			}

			PRINT("      ");

			for(k = 0; k < (j + 1); k++)
				PRINT("--> %s  ", str2[k]);

			PRINT("\n");

			j = 0;
		}
		else
		{
			j++;
		}
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
	TX_total_sent_size += rle_transmitter_get_counter_bytes(transmitter);
	TX_total_sent_pkt += rle_transmitter_get_counter_ok(transmitter);
	TX_total_lost_pkt += rle_transmitter_get_counter_lost(transmitter);
	TX_total_drop_pkt += rle_transmitter_get_counter_dropped(transmitter);

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
			(float)(TX_total_sent_size/TX_total_sent_pkt));
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
	RX_total_received_size += rle_receiver_get_counter_bytes(receiver);
	RX_total_received_pkt += rle_receiver_get_counter_ok(receiver);
	RX_total_lost_pkt += rle_receiver_get_counter_lost(receiver);
	RX_total_drop_pkt += rle_receiver_get_counter_dropped(receiver);

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
			(float)(RX_total_received_size/RX_total_received_pkt));
}


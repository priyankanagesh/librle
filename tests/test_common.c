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


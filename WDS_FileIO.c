/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _CRT_SECURE_NO_WARNINGS
#include "WDS.h"

int Exist(const char* Filename)
{
	FILE *fil = fopen(Filename, "r");

	if (fil != NULL)
	{
		fclose(fil);
		return 0;
	}
	else
		return -1;
}

int GetClientRule(const unsigned char* hwadr, const unsigned char* cguid)
{
	unsigned char* MAC[6];
	int found = 0;
	int MacsFound = 0;
	int GuidsFound = 0;

	FILE *fil = fopen("Clients.txt", "r");

	if (fil != NULL)
	{
		while (!feof(fil))
		{
			if (fscanf(fil, "%02X-%02X-%02X-%02X-%02X-%02X\n",
				&MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5]));

			if (MAC[0] == hwadr[0] && MAC[1] == hwadr[1] && MAC[2] == hwadr[2] && \
				MAC[3] == hwadr[3] && MAC[4] == hwadr[4] && MAC[5] == hwadr[5])
				MacsFound = MacsFound + 1;
		}

		fclose(fil);

		if (MacsFound > 0)
		{
			if (MacsFound > 1) /* Only allow ONE MAC! */
				return 0;

			if (MacsFound == 1)
				return 1;
		}
		else
			return 0;
	}
	return 0;
}

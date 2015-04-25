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
	unsigned char* MAC[6] = { "" };
	int Action = WDSBP_OPTVAL_ACTION_ABORT;
	int MacsFound = 0;
	int GuidsFound = 0;

	FILE *fil = fopen("Clients.txt", "r");

	if (fil != NULL)
	{
		while (!feof(fil))
		{
			fscanf(fil, "%02X-%02X-%02X-%02X-%02X-%02X | %d\n", &MAC[0], &MAC[1], &MAC[2], &MAC[3], &MAC[4], &MAC[5], &Action);

			if (memcmp(&MAC[0], &hwadr[0], 1) == 0 && memcmp(&MAC[1], &hwadr[1], 1) == 0 && memcmp(&MAC[2], &hwadr[2], 1) == 0 && \
				memcmp(&MAC[3], &hwadr[3], 1) == 0 && memcmp(&MAC[4], &hwadr[4], 1) == 0 && memcmp(&MAC[5], &hwadr[5], 1) == 0)

				MacsFound = MacsFound + 1;
		}

		fclose(fil);

		if (MacsFound > 0)
		{
			
			if (MacsFound > 1) /* Only allow ONE MAC! */
				return WDSBP_OPTVAL_ACTION_ABORT;

			if (MacsFound == 1)
				return Action;
			else
				return WDSBP_OPTVAL_ACTION_ABORT;
		}
		else
			return WDSBP_OPTVAL_ACTION_ABORT;
	}
	else
		return WDSBP_OPTVAL_ACTION_ABORT;
}

int GetServerSettings()
{
	FILE *fil = fopen("Settings.txt", "r");

	if (fil != NULL)
	{
		while (!feof(fil))
		{
			fscanf(fil, "CurrentIDs: %d\n", &Server.RequestID);
			fscanf(fil, "PollIntervall: %d\n", &config.PollIntervall);
			fscanf(fil, "TFTPRetryCount: %d\n", &config.TFTPRetryCount);
			fscanf(fil, "AllowUnknownClients: %d\n", &config.AllowUnknownClients);
			fscanf(fil, "VersionQuery: %d\n", &config.AllowUnknownClients);
			fscanf(fil, "DefaultAction: %d\n", &config.DefaultAction);
		}

		fclose(fil);
	}

	return 0;
}
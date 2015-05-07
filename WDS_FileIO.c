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
		if (fclose(fil) == 0)
			return 0;
		else
			return 1;
	else
		return 1;
}

int GetClientRule(const unsigned char* MACb, const unsigned char* cguid)
{
	unsigned char* MACa[6] = { "" };
	int Action = config.DefaultAction;
	int MacsFound = 0;
	int GuidsFound = 0;
	int Mode = 0;
	int i = 0;
	int result = 0;

	FILE *fil = fopen(WDS_CLIENTS_FILE, "r");

	if (fil != NULL)
	{
		while (!feof(fil))
		{
			if (fscanf(fil, "%X-%X-%X-%X-%X-%X | %d | %d\n", &MACa[0], &MACa[1], &MACa[2], &MACa[3], &MACa[4], &MACa[5], &Action, &Mode) > 3)
			{
				for (i = 0; i < 6; i++)
					MACa[i] = (unsigned char)MACa[i];

				if (memcmp(&MACa[0], &MACb[0], 1) == 0 && \
					memcmp(&MACa[1], &MACb[1], 1) == 0 && \
					memcmp(&MACa[2], &MACb[2], 1) == 0 && \
					memcmp(&MACa[3], &MACb[3], 1) == 0 && \
					memcmp(&MACa[4], &MACb[4], 1) == 0 && \
					memcmp(&MACa[5], &MACb[5], 1) == 0)
				{
					MacsFound = MacsFound + 1;
					switch (Mode)
					{
					case WDS_MODE_RIS:
						Client.WDSMode = WDS_MODE_RIS;
						break;
					case WDS_MODE_WDS:
						Client.WDSMode = WDS_MODE_WDS;
						break;
					case WDS_MODE_UNK:
						Client.WDSMode = WDS_MODE_UNK;
						break;
					default:
						Client.WDSMode = config.DefaultMode;
						break;
					}
				}
			}
		}

		if (fclose(fil) == 0)
		{
			if (MacsFound > 0)
			{
				if (MacsFound > 1) /* Only allow ONE MAC! */
				{
#ifdef _WIN32
					sprintf(logbuffer, "[I] Lookup Device... failed! (Macs: %d - Action: %d)\n", MacsFound, Action);
					logger(logbuffer);
#endif
					Client.WDSMode = WDS_MODE_WDS;
					return WDSBP_OPTVAL_ACTION_ABORT;
				}
				else
					if (MacsFound == 1)
						return Action;
			}
			else
			{
#ifdef _WIN32
				sprintf(logbuffer, "[E] Client not found!\n");
				logger(logbuffer);
#endif
				Client.WDSMode = WDS_MODE_WDS;
				return WDSBP_OPTVAL_ACTION_ABORT;
			}
		}
		else
		{
#ifdef _WIN32
			sprintf(logbuffer, "[E] FileIO Error (while closing the file)!\n");
			logger(logbuffer);
#endif
			Client.WDSMode = WDS_MODE_WDS;
			return WDSBP_OPTVAL_ACTION_ABORT;
		}
	}
	else
	{
#ifdef _WIN32
		sprintf(logbuffer, "[E] File not found!\n");
		logger(logbuffer);
#endif
		Client.WDSMode = config.DefaultMode;
		return config.DefaultAction;
	}

	return 0;
}

int GetServerSettings()
{
	FILE *fil = fopen(WDS_SETTINGS_FILE, "r");

	if (fil != NULL)
	{
		while (!feof(fil))
		{
			fscanf(fil, "CurrentIDs: %d\n", &Server.RequestID);
			fscanf(fil, "PollIntervall: %d\n", &config.PollIntervall);
			fscanf(fil, "TFTPRetryCount: %d\n", &config.TFTPRetryCount);
			fscanf(fil, "AllowUnknownClients: %d\n", &config.AllowUnknownClients);
			fscanf(fil, "VersionQuery: %d\n", &config.AllowUnknownClients);
			fscanf(fil, "ShowClientRequests: %d\n", &config.ShowClientRequests);
			fscanf(fil, "DefaultAction: %d\n", &config.DefaultAction);
		}

		if (fclose(fil) == 0)
			return 0;
		else
			return 1;
	}
	else
		return 1;
}
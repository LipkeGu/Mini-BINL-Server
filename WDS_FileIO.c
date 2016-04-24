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
		return fclose(fil);
	else
		return 1;
}

uint8_t GetClientRule(const uint8_t* MACb)
{
	uint32_t MACa[6];
	uint8_t mac[6];

	memset(mac, 0, sizeof(mac));
	memset(MACa, 0, sizeof(MACa));

	int Action = Config.DefaultAction;
	int Mode = Config.DefaultMode;
	int Prompt = 0;
	int i = 0;
	int found = 0;

	FILE *fil = fopen(WDS_CLIENTS_FILE, "r");

	if (fil == NULL)
		return 1;

	while (!feof(fil) && found == 0)
		if (fscanf(fil, "%X-%X-%X-%X-%X-%X | %d | %d | %d\n",
			&MACa[0], &MACa[1], &MACa[2], &MACa[3], &MACa[4], &MACa[5], &Action, &Mode, &Prompt) > 3)
		{
			for (i = 0; i < 6; i++)
				mac[i] = (unsigned char)MACa[i];

			if (memcmp(&mac[0], &MACb[0], 1) == 0 && memcmp(&mac[1], &MACb[1], 1) == 0 && \
				memcmp(&mac[2], &MACb[2], 1) == 0 && memcmp(&mac[3], &MACb[3], 1) == 0 && \
				memcmp(&mac[4], &MACb[4], 1) == 0 && memcmp(&mac[5], &MACb[5], 1) == 0)

				found = 1;
		}

	if (fil != NULL)
		fclose(fil);

	if (found == 1)
	{
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
			Client.WDSMode = Config.DefaultMode;
			break;
		}

		switch (Prompt)
		{
		case WDSBP_OPTVAL_PXE_PROMPT_OPTIN:
			wdsnbp.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_OPTIN;
			break;
		case WDSBP_OPTVAL_PXE_PROMPT_OPTOUT:
			wdsnbp.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_OPTOUT;
			break;
		case WDSBP_OPTVAL_PXE_PROMPT_NOPROMPT:
			wdsnbp.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_NOPROMPT;
			break;
		default:
			if (Config.AllowUnknownClients == 1)
				wdsnbp.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_OPTIN;
			else
				wdsnbp.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_NOPROMPT;
			break;
		}

		switch (Action)
		{
		case  WDSBP_OPTVAL_ACTION_APPROVAL:
			wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_APPROVAL;
			break;
		case WDSBP_OPTVAL_ACTION_REFERRAL:
			wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_REFERRAL;
			break;
		case WDSBP_OPTVAL_ACTION_ABORT:
			wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_ABORT;
			break;
		default:
			wdsnbp.NextAction = Config.DefaultAction;
			break;
		}

		return 1;
	}
	else
		if (Config.AllowUnknownClients == 0)
			return 0;
		else
		{
			wdsnbp.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_OPTIN;
			Client.WDSMode = WDSBP_OPTVAL_ACTION_APPROVAL;

			return 1;
		}	
}

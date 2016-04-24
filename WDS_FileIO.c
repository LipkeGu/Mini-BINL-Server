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

int GetClientRule(const unsigned char* MACb)
{
	unsigned int MACa[6];
	unsigned char mac[6];

	int Action = Config.DefaultAction;
	int Mode = Config.DefaultMode;
	int Prompt = 0;
	int i = 0;
	int found = 0;

	FILE *fil = fopen(WDS_CLIENTS_FILE, "r");

	ZeroOut(mac, sizeof(mac));

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

int GetServerSettings()
{
	FILE *fil = fopen(WDS_SETTINGS_FILE, "r");

	if (fil != NULL)
	{
		while (!feof(fil))
		{
			if (fscanf(fil, "DropUnkownClients: %d\n", &Config.DropUnkownClients) < 1)
				Config.DropUnkownClients = 0;

			if (fscanf(fil, "CurrentIDs: %d\n", &Server.RequestID) < 1)
				Server.RequestID = htonl(1);

			if (fscanf(fil, "PollIntervall: %hu\n", &Config.PollIntervall) < 1)
				Config.PollIntervall = htons(SETTINGS_DEFAULT_POLLINTERVALL);
			
			if (fscanf(fil, "TFTPRetryCount: %hu\n", &Config.TFTPRetryCount) < 1)
				Config.TFTPRetryCount = htons(SETTINGS_DEFAULT_RETRYCOUNT);
			
			if (fscanf(fil, "AllowUnknownClients: %d\n", &Config.AllowUnknownClients) < 1)
				Config.AllowUnknownClients = SETTINGS_DEFAULT_ALLOWUNKCLIENTS;

			if (fscanf(fil, "VersionQuery: %c\n", &Config.VersionQuery) < 1)
				Config.VersionQuery = SETTINGS_DEFAULT_VERSIONQUERY;

			if (fscanf(fil, "ShowClientRequests: %d\n", &Config.ShowClientRequests) < 1)
				Config.ShowClientRequests = SETTINGS_DEFAULT_SHOWREQS;

			if (fscanf(fil, "DefaultAction: %c\n", &Config.DefaultAction) < 1)
				Config.DefaultAction = WDSBP_OPTVAL_ACTION_ABORT;

			if (fscanf(fil, "DefaultMode: %d\n", &Config.DefaultMode) < 1)
				Config.DefaultMode = SETTINGS_DEFAULT_WDSMODE;

			if (fscanf(fil, "PXEClientPrompt: %c\n", &Config.PXEClientPrompt) < 1)
				Config.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_OPTIN;

			if (fscanf(fil, "AllowServerSelection: %c\n", &Config.AllowServerSelection) < 1)
				Config.AllowServerSelection = 0;
		}

		return fclose(fil);
	}
	else
		return 1;
}

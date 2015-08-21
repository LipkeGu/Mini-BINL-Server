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
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "WDS.h"

int GetClientinfo(int arch, unsigned char* hwadr, int found)
{
	if (wdsnbp.RequestID == 200)
		wdsnbp.RequestID = 1;

	if (found == 1 && Client.isWDSRequest == 1 && wdsnbp.ActionDone == 1)
	{
		switch (Client.WDSMode)
		{
		case WDS_MODE_RIS:
			wdsnbp.RequestID = wdsnbp.RequestID + 1;

			sprintf(logbuffer, "============== RIS Client (%d) ==============\n", wdsnbp.RequestID);
			logger(logbuffer);

			if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
				sprintf(Client.Bootfile, RIS_BOOTFILE_DEFAULT);
			else
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X86);

			sprintf(Client.BCDPath, "\0");
			break;
		case WDS_MODE_WDS:
			wdsnbp.RequestID = wdsnbp.RequestID + 1;

			sprintf(logbuffer, "============== WDS Client (%d) ==============\n", wdsnbp.RequestID);
			logger(logbuffer);

			switch (arch)
			{
			case SYSARCH_INTEL_X86:
				sprintf(logbuffer, "ARCH: x86\n");
				logger(logbuffer);
				
				if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
					sprintf(Client.Bootfile, WDS_BOOTFILE_X86);
				else
					sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X86);

				sprintf(Client.BCDPath, WDS_BOOTSTORE_X86);
				break;
			case SYSARCH_INTEL_X64:
				sprintf(logbuffer, "ARCH: x64\n");
				logger(logbuffer);

				if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
					sprintf(Client.Bootfile, WDS_BOOTFILE_X64);
				else
					sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X64);

				sprintf(Client.BCDPath, WDS_BOOTSTORE_X64);
				break;
			case SYSARCH_INTEL_EFI:
				sprintf(logbuffer, "ARCH: x64 EFI\n");
				logger(logbuffer);

				if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
					sprintf(Client.Bootfile, WDS_BOOTFILE_EFI);
				else
					sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_EFI);

				sprintf(Client.BCDPath, WDS_BOOTSTORE_EFI);
				break;
			case SYSARCH_INTEL_IA64:
				sprintf(logbuffer, "ARCH: IA64\n");
				logger(logbuffer);

				if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
					sprintf(Client.Bootfile, WDS_BOOTFILE_EFI);
				else
					sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_EFI);
			
				sprintf(Client.BCDPath, WDS_BOOTSTORE_EFI);
				break;
			}
			break;
		case WDS_MODE_UNK:
			wdsnbp.RequestID = wdsnbp.RequestID + 1;

			sprintf(logbuffer, "============== PXE Client (%d) ==============\n", wdsnbp.RequestID);
			logger(logbuffer);

			sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
			break;
		default:
			sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
			break;
		}

		sprintf(logbuffer, "HWADDR: %02X:%02X:%02X:%02X:%02X:%02X\n", hwadr[0], hwadr[1], hwadr[2], hwadr[3], hwadr[4], hwadr[5]);
		logger(logbuffer);

		sprintf(logbuffer, "CLIENT IP: %s\n", inet_ntoa(from.sin_addr));
		logger(logbuffer);

		switch (wdsnbp.PXEClientPrompt)
		{
		case WDSBP_OPTVAL_PXE_PROMPT_OPTIN:
			sprintf(logbuffer, "PROMPT: OptIn\n");
			break;
		case WDSBP_OPTVAL_PXE_PROMPT_OPTOUT:
			sprintf(logbuffer, "PROMPT: OptOut\n");
			break;
		case WDSBP_OPTVAL_PXE_PROMPT_NOPROMPT:
			sprintf(logbuffer, "PROMPT: NoPrompt\n");
			break;
		default:
			sprintf(logbuffer, "PROMPT: Unknown\n");
			break;
		}

		logger(logbuffer);

		switch (wdsnbp.NextAction)
		{
		case WDSBP_OPTVAL_ACTION_ABORT:
			sprintf(logbuffer, "ACTION: Abort\n");
			break;
		case WDSBP_OPTVAL_ACTION_APPROVAL:
			sprintf(logbuffer, "ACTION: Approval\n");
			break;
		case WDSBP_OPTVAL_ACTION_REFERRAL:
			sprintf(logbuffer, "ACTION: Referral\n");
			break;
		default:
			sprintf(logbuffer, "ACTION: Unknown\n");
			break;
		}

		logger(logbuffer);

		if (Config.ShowClientRequests == 1)
		{
			sprintf(logbuffer, "FILE: %s\n", Client.Bootfile);
			logger(logbuffer);

			if (Client.WDSMode == WDS_MODE_WDS && wdsnbp.NextAction == WDSBP_OPTVAL_ACTION_APPROVAL && 
				strlen(Client.BCDPath) > 3)
			{
				sprintf(logbuffer, "BCD: %s\n", Client.BCDPath);
				logger(logbuffer);
			}
		}

		wdsnbp.PXEPromptDone = 1;
		wdsnbp.ActionDone = 1;
		
		sprintf(logbuffer, "============================================\n");
		logger(logbuffer);
		
		return 1;
	}
	else
		return 0;
}

int Handle_DHCP_Request(int con, char* Data, int found, int mode)
{
	char ZeroIP[IPV4_ADDR_LENGTH] = { 0x00, 0x00, 0x00, 0x00 };
	char Bootreply[1] = { BOOTP_REPLY };
	char DHCP_ACK[3] = { 0x35, 0x01, setDHCPRespType(found, mode) };
	char Vendoropt[2] = { 0x3C, strlen(VENDORIDENT) };
	char DHCPEnd[1] = { 0xff };
	char idtopt[2] = { 0x36, IPV4_ADDR_LENGTH };
	char Rtropt[2] = { 0x03, IPV4_ADDR_LENGTH };
	char netopt[2] = { 0x01, IPV4_ADDR_LENGTH };

	if (memcmp(&Data[BOOTP_OFFSET_CLIENTIP], ZeroIP, IPV4_ADDR_LENGTH) != 0 &&
		memcmp(&Data[BOOTP_OFFSET_NEXTSERVER], ZeroIP, IPV4_ADDR_LENGTH) == 0)
		return 0;

	RESPsize = 0;

	/* BOOTP Message Type */
	memcpy(&RESPData[RESPsize], Bootreply, sizeof(Bootreply));
	Set_Size(sizeof(Bootreply));

	/* Hardware Type */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_HWTYPE], 1);
	Set_Size(1);

	/* Hardware-Address-Length */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_MACLEN], 1);
	Set_Size(1);

	/* Hops */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_HOPS], 1);
	Set_Size(1);

	/* Transaction-ID */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_TRANSID], 4);
	Set_Size(4);

	/* Elapsed Seconds */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_SECONDS], 2);
	Set_Size(2);

	/* BOOTP Flags */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_BOOTPFLAGS], 2);
	Set_Size(2);

	/* Client-IP */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_YOURIP], IPV4_ADDR_LENGTH);
	Set_Size(IPV4_ADDR_LENGTH);

	/* Your-IP */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_CLIENTIP], IPV4_ADDR_LENGTH);
	Set_Size(IPV4_ADDR_LENGTH);

	/* Next Server-IP */
	memcpy(&RESPData[RESPsize], &Config.ServerIP, sizeof(Config.ServerIP));
	Set_Size(sizeof(Config.ServerIP));

	/* Relay Agent-IP */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_RELAYIP], IPV4_ADDR_LENGTH);
	Set_Size(IPV4_ADDR_LENGTH);

	/* Client Mac-Address */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_MACADDR], Data[BOOTP_OFFSET_MACLEN]);
	Set_Size(Data[2]);

	/* Address Padding */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_MACPADDING], 10);
	Set_Size(10);

	/* Server Hostname */
	memcpy(&RESPData[RESPsize], Server.nbname, sizeof(Server.nbname));
	Set_Size(sizeof(Server.nbname));

	if (Client.isWDSRequest == 0)
		sprintf(Client.Bootfile, DHCP_BOOTFILE);

	memcpy(&RESPData[RESPsize], Client.Bootfile, sizeof(Client.Bootfile));
	Set_Size(sizeof(Client.Bootfile));

	/* MAGIC COOKIE */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_COOKIE], 4);
	Set_Size(4);

	/* DHCP Response Type (53) */
	memcpy(&RESPData[RESPsize], DHCP_ACK, sizeof(DHCP_ACK));
	Set_Size(sizeof(DHCP_ACK));

	/* Option Server Ident (54) */
	memcpy(&RESPData[RESPsize], idtopt, sizeof(idtopt));
	Set_Size(sizeof(idtopt));

	memcpy(&RESPData[RESPsize], &Config.ServerIP, sizeof(Config.ServerIP));
	Set_Size(sizeof(Config.ServerIP));

	/* DHCP-Option "Vendor-Class" (60) */
	memcpy(&RESPData[RESPsize], Vendoropt, 2);
	Set_Size(2);

	sprintf(&RESPData[RESPsize], VENDORIDENT);
	Set_Size(9);

	/* Send option 1 & 3 only when we have an WDS request... */

	if (Client.isWDSRequest == 1)
	{
		/* Option Netmask (1) */
		memcpy(&RESPData[RESPsize], netopt, sizeof(netopt));
		Set_Size(sizeof(netopt));

		memcpy(&RESPData[RESPsize], &Config.SubnetMask, sizeof(Config.SubnetMask));
		Set_Size(sizeof(Config.SubnetMask));

		/* Option Router (3) */
		memcpy(&RESPData[RESPsize], Rtropt, sizeof(Rtropt));
		Set_Size(sizeof(Rtropt));

		memcpy(&RESPData[RESPsize], &Config.ServerIP, sizeof(Config.ServerIP));
		Set_Size(sizeof(Config.ServerIP));
	}

	if (found == 1)
	{
		if (Client.WDSMode == WDS_MODE_WDS)
		{
			/* Boot Configuration Store (252) */
			char bcdopt[2] = { 0xfc, strlen(Client.BCDPath) };

			memcpy(&RESPData[RESPsize], bcdopt, sizeof(bcdopt));
			Set_Size(sizeof(bcdopt));

			memcpy(&RESPData[RESPsize], Client.BCDPath, strlen(Client.BCDPath));
			Set_Size(strlen(Client.BCDPath));
		}
	}
	else
	{
		if (Config.AllowUnknownClients == 0)
		{
			/* TODO Assign types instead of hardcoding! */
			char aprovalmsg[29] = {
				WDSBP_OPT_NEXT_ACTION, 0x01, wdsnbp.NextAction,
				WDSBP_OPT_REQUEST_ID, 0x04, 0x00, 0x00, 0x00, wdsnbp.RequestID,
				WDSBP_OPT_POLL_INTERVAL, 0x02, 0x00, wdsnbp.PollIntervall,
				WDSBP_OPT_POLL_RETRY_COUNT, 0x02, 0x00, wdsnbp.RetryCount,
				WDSBP_OPT_ACTION_DONE, 0x01, wdsnbp.ActionDone,
				WDSBP_OPT_VERSION_QUERY, 0x01, wdsnbp.VersionQuery,
				WDSBP_OPT_PXE_CLIENT_PROMPT, 0x01, wdsnbp.PXEClientPrompt,
				WDSBP_OPT_PXE_PROMPT_DONE, 0x01, wdsnbp.PXEPromptDone };

			char admopt[2] = { 0xfa, sizeof(aprovalmsg) };

			memcpy(&RESPData[RESPsize], admopt, sizeof(admopt));
			Set_Size(sizeof(admopt));

			memcpy(&RESPData[RESPsize], aprovalmsg, sizeof(aprovalmsg));
			Set_Size(sizeof(aprovalmsg));
		}
	}
			
	/* End of DHCP-Options */
	memcpy(&RESPData[RESPsize], DHCPEnd, sizeof(DHCPEnd));
	Set_Size(sizeof(DHCPEnd));

	return Send(con, RESPData, RESPsize, mode);
}

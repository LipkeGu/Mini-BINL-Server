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


void GetBootFile(uint16_t arch)
{
	switch (Client.WDSMode)
	{
	case WDS_MODE_RIS:
		wdsnbp.RequestID += htonl(1);

		sprintf(logbuffer, "============== RIS Client (%d) ==============\n", ntohl(wdsnbp.RequestID));
		logger(logbuffer);

		if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
			sprintf(Client.Bootfile, RIS_BOOTFILE_DEFAULT);
		else
			sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X86);

		sprintf(Client.BCDPath, "\0");
		break;
	case WDS_MODE_WDS:
		switch (arch)
		{
		case SYSARCH_INTEL_X86:
			if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
				sprintf(Client.Bootfile, WDS_BOOTFILE_X86);
			else
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X86);

			sprintf(Client.BCDPath, WDS_BOOTSTORE_X86);
			break;
		case SYSARCH_INTEL_X64:
			if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
				sprintf(Client.Bootfile, WDS_BOOTFILE_X64);
			else
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X64);

			sprintf(Client.BCDPath, WDS_BOOTSTORE_X64);
			break;
		case SYSARCH_INTEL_EFI:
			if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
				sprintf(Client.Bootfile, WDS_BOOTFILE_EFI);
			else
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_EFI);

			sprintf(Client.BCDPath, WDS_BOOTSTORE_EFI);
			break;
		case SYSARCH_INTEL_IA64:
			if (wdsnbp.NextAction != WDSBP_OPTVAL_ACTION_ABORT)
				sprintf(Client.Bootfile, WDS_BOOTFILE_EFI);
			else
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_EFI);

			sprintf(Client.BCDPath, WDS_BOOTSTORE_EFI);
			break;
		}
		break;
	case WDS_MODE_UNK:
		sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
		break;
	default:
		sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
		break;
	}
}

uint8_t GetClientinfo(uint16_t arch, uint8_t* hwadr, uint8_t found)
{
	if (found == 1)
	{
		wdsnbp.RequestID += htonl(1);


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

		sprintf(logbuffer, "============================================\n");
		logger(logbuffer);
	}

	Client.ClientArch = arch;
	return wdsnbp.ActionDone = found;
}

int Handle_DHCP_Request(int con, const char* Data, uint8_t found, uint8_t mode)
{
	uint32_t zeroip = 0;

	uint8_t reply = BOOTP_REPLY;
	uint8_t DHCPEnd = 255;
	char DHCP_ACK[3];

	DHCP_ACK[0] = 53;
	DHCP_ACK[1] = 1;
	DHCP_ACK[2] = setDHCPRespType();

	char Vendoropt[2] = { 0x3C, 0x09 };
	char idtopt[2] = { 0x36, IPV4_ADDR_LENGTH };
	char Rtropt[2] = { 0x03, IPV4_ADDR_LENGTH };

	if (memcmp(&Data[BOOTP_OFFSET_CLIENTIP], &zeroip, sizeof(zeroip)) != 0 &&
		memcmp(&Data[BOOTP_OFFSET_NEXTSERVER], &zeroip, sizeof(zeroip)) == 0)
		return 0;

	RESPsize = 0;

	/* BOOTP Message Type */
	memcpy(&RESPData[RESPsize], &reply, sizeof(reply));
	Set_Size(sizeof(reply));

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

	if (mode == 1)
		sprintf(Client.Bootfile, DHCP_BOOTFILE);
	else
		GetBootFile(Client.ClientArch);

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
	Set_Size(strlen(VENDORIDENT));

	/* Option Router (3) */
	memcpy(&RESPData[RESPsize], Rtropt, sizeof(Rtropt));
	Set_Size(sizeof(Rtropt));

	memcpy(&RESPData[RESPsize], &Config.ServerIP, sizeof(Config.ServerIP));
	Set_Size(sizeof(Config.ServerIP));

	if (found == 1)
	{
		if (Client.WDSMode == WDS_MODE_WDS)
		{
			/* Boot Configuration Store (252) */
			char bcdopt[2];
			sprintf(bcdopt,"%c%c",252, strlen(Client.BCDPath));
			memcpy(&RESPData[RESPsize], bcdopt, sizeof(bcdopt));
			Set_Size(sizeof(bcdopt));

			memcpy(&RESPData[RESPsize], Client.BCDPath, strlen(Client.BCDPath));
			Set_Size(strlen(Client.BCDPath));
		}
	}
	else
	{
		char tmpbuffer[512];
		uint8_t offset = 2;
		uint8_t length = 0;
		uint8_t option = 0;

		memset(tmpbuffer, 0, sizeof(tmpbuffer));

		// Next Action
		option = WDSBP_OPT_NEXT_ACTION;
		length = (uint8_t)sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &option, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &length, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &wdsnbp.NextAction, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		// RequestID
		option = WDSBP_OPT_REQUEST_ID;
		length = (uint8_t)sizeof(uint32_t);

		memcpy(&tmpbuffer[offset], &option, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		
		memcpy(&tmpbuffer[offset], &length, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &wdsnbp.RequestID, sizeof(uint32_t));
		offset += sizeof(uint32_t);

		// Poll Interval
		option = WDSBP_OPT_POLL_INTERVAL;
		length = (uint8_t)sizeof(uint16_t);

		memcpy(&tmpbuffer[offset], &option, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &length, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &wdsnbp.PollIntervall, sizeof(uint16_t));
		offset += sizeof(uint16_t);

		// Poll Retry Count
		option = WDSBP_OPT_POLL_RETRY_COUNT;
		length = (uint8_t)sizeof(uint16_t);

		memcpy(&tmpbuffer[offset], &option, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &length, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &wdsnbp.RetryCount, sizeof(uint16_t));
		offset += sizeof(uint16_t);

		// Action Done
		option = WDSBP_OPT_ACTION_DONE;
		length = (uint8_t)sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &option, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &length, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &wdsnbp.ActionDone, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		
		// Admin Message
		option = WDSBP_OPT_MESSAGE;
		length = (uint8_t)strlen(WDS_MSG_LOOKING_FOR_POLICY);

		memcpy(&tmpbuffer[offset], &option, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		memcpy(&tmpbuffer[offset], &length, sizeof(uint8_t));
		offset += sizeof(uint8_t);

		strncpy(&tmpbuffer[offset], WDS_MSG_LOOKING_FOR_POLICY, strlen(WDS_MSG_LOOKING_FOR_POLICY) + 1);
		offset += (uint8_t)strlen(WDS_MSG_LOOKING_FOR_POLICY) + 1;

		memcpy(&tmpbuffer[offset], &DHCPEnd, sizeof(DHCPEnd));
		offset += sizeof(uint8_t);

		tmpbuffer[0] = 250;

		uint8_t realsize = offset - 2;
		memcpy(&tmpbuffer[1], &realsize, sizeof(uint8_t));

		memcpy(&RESPData[RESPsize], tmpbuffer, offset);
		Set_Size(offset);
	}
			
	/* End of DHCP-Options */
	memcpy(&RESPData[RESPsize], &DHCPEnd, sizeof(DHCPEnd));
	Set_Size(sizeof(DHCPEnd));

	return Send(con, RESPData, RESPsize, mode);
}

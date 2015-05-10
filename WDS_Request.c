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

int GetClientinfo(int arch, unsigned char* hwadr, unsigned char* guid, int found)
{
	if (found == 1)
	{
		sprintf(logbuffer, "============== WDS Client ==============\n");
		logger(logbuffer);

		sprintf(logbuffer, "MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
			hwadr[0], hwadr[1], hwadr[2], hwadr[3], hwadr[4], hwadr[5]);
		logger(logbuffer);

		sprintf(logbuffer, "CLIENT IP: %s\n", inet_ntoa(from.sin_addr));
		logger(logbuffer);

		sprintf(logbuffer, "GUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
			guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7],
			guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]);
		logger(logbuffer);

		switch (Client.Action)
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

		switch (Client.WDSMode)
		{
		case WDS_MODE_RIS:
			sprintf(logbuffer, "MODE: RIS\n");
			break;
		case WDS_MODE_WDS:
			sprintf(logbuffer, "MODE: WDS\n");
			break;
		case WDS_MODE_UNK:
			sprintf(logbuffer, "MODE: PXELinux\n");
			break;
		default:
			sprintf(logbuffer, "MODE: Unknown\n");
			break;
		}

		logger(logbuffer);

		switch (arch)
		{
		case SYSARCH_INTEL_X86:
			if (Client.ClientArch != arch)
				sprintf(logbuffer, "ARCH: x86 (DHCP reports %d!)\n", Client.ClientArch);
			else
				sprintf(logbuffer, "ARCH: x86\n");

			logger(logbuffer);

			if (Client.Action != WDSBP_OPTVAL_ACTION_ABORT)
				if (Client.WDSMode == WDS_MODE_WDS)
				{
					sprintf(Client.Bootfile, WDS_BOOTFILE_X86);
					sprintf(Client.BCDPath, WDS_BOOTSTORE_X86);
				}
				else
				{
					sprintf(Client.Bootfile, RIS_BOOTFILE_DEFAULT);
					sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);
				}
			else
			{
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X86);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_X86);
			}
			
			Client.WDSMode = WDS_MODE_WDS;
			break;
#ifdef ALLOWALLARCHES
		case SYSARCH_NEC_PC98:
			if (Client.ClientArch != arch)
			{
				sprintf(logbuffer, "ARCH: NEC PC98 (DHCP reports %d!)\n", Client.ClientArch);
				logger(logbuffer);
			}
			else
			{
				sprintf(logbuffer, "ARCH: NEC PC98\n");
				logger(logbuffer);
			}

			sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
			sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);

			Client.WDSMode = WDS_MODE_UNK;
			break;
#endif
		case SYSARCH_INTEL_IA64:
			if (Client.ClientArch != arch)
				sprintf(logbuffer, "ARCH: IA64 (DHCP reports %d!)\n", Client.ClientArch);
			else
				sprintf(logbuffer, "ARCH: IA64\n");

			logger(logbuffer);
			Client.WDSMode = WDS_MODE_WDS;
			break;
#ifdef ALLOWALLARCHES
		case SYSARCH_DEC_ALPHA:
			if (Client.ClientArch != arch)
				sprintf(logbuffer, "ARCH: DEC Alpha (DHCP reports %d!)\n", Client.ClientArch);
			else
				sprintf(logbuffer, "ARCH: DEC Alpha\n");

			logger(logbuffer);

			sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
			sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);

			Client.WDSMode = WDS_MODE_UNK;
			break;
		case SYSARCH_ARC_x86:
			sprintf(logbuffer, "ARCH: ARC x86\n");
			logger(logbuffer);
			
			sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
			sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);

			Client.WDSMode = WDS_MODE_UNK;
			break;
		case SYSARCH_INTEL_LEAN:
			sprintf(logbuffer, "ARCH: Intel Lean\n");
			logger(logbuffer);

			Client.WDSMode = WDS_MODE_UNK;
			break;
#endif
		case SYSARCH_INTEL_X64:
			if (Client.ClientArch != arch)
				sprintf(logbuffer, "ARCH: x64 (DHCP reports %d!)\n", Client.ClientArch);
			else
				sprintf(logbuffer, "ARCH: x64\n");

			logger(logbuffer);

			if (Client.Action != WDSBP_OPTVAL_ACTION_ABORT)
			{
				sprintf(Client.Bootfile, WDS_BOOTFILE_X64);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_X64);
			}
			else
			{
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X64);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_X64);
			}

			Client.WDSMode = WDS_MODE_WDS;
			break;
		case SYSARCH_INTEL_EFI:
			if (Client.ClientArch != arch)
				sprintf(logbuffer, "ARCH: x64 EFI (DHCP reports %d!)\n", Client.ClientArch);
			else
				sprintf(logbuffer, "ARCH: x64 EFI\n");

			logger(logbuffer);

			if (Client.Action != WDSBP_OPTVAL_ACTION_ABORT)
			{
				sprintf(Client.Bootfile, WDS_BOOTFILE_EFI);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_EFI);
			}
			else
			{
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_EFI);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_EFI);
			}

			Client.WDSMode = WDS_MODE_WDS;
			break;
		default:
#ifdef ALLOWALLARCHES
			sprintf(logbuffer, "ARCH: unknown (%d)\n");
			logger(logbuffer);

			switch (Client.WDSMode)
			{
			case WDS_MODE_RIS:
				sprintf(Client.Bootfile, RIS_BOOTFILE_DEFAULT);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);
				break;
			case WDS_MODE_WDS:
				sprintf(Client.Bootfile, WDS_ABORT_BOOTFILE_X86);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_X86);
				break;
			case WDS_MODE_UNK:
				sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);
				break;
			default:
				sprintf(Client.Bootfile, WDS_BOOTFILE_UNKNOWN);
				sprintf(Client.BCDPath, WDS_BOOTSTORE_DEFAULT);
				break;
			}

			Client.WDSMode = WDS_MODE_UNK;
#endif
			break;
		}

		Server.RequestID = Server.RequestID + 1;

		if (Server.RequestID == 99)
			Server.RequestID = 1;

		return 1;
	}
	else
	{
		if (config.AllowUnknownClients == 0 && config.ShowClientRequests == 1)
		{
			sprintf(logbuffer, "======== WDS (Request #%d) ========\n", Server.RequestID);
			logger(logbuffer);

			sprintf(logbuffer, "MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
				hwadr[0], hwadr[1], hwadr[2], hwadr[3], hwadr[4], hwadr[5]);
			logger(logbuffer);

			sprintf(logbuffer, "====================================\n");
			logger(logbuffer);
		}
		
		return 0;
	}
}

int Handle_NBP_Request(int con, char* Data, size_t Packetlen, int found)
{
	RESPsize = 0;

	gethostname(Server.nbname, sizeof(Server.nbname));
	config.ServerIP = IP2Bytes(hostname_to_ip(Server.nbname));

	/* BOOTP Type */
	char Bootreply[1] = { BOOTP_REPLY };
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
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_CLIENTIP], IPV4_ADDR_LENGTH);
	Set_Size(IPV4_ADDR_LENGTH);

	/* Your-IP */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_YOURIP], IPV4_ADDR_LENGTH);
	Set_Size(IPV4_ADDR_LENGTH);

	/* Next Server-IP */
	memcpy(&RESPData[RESPsize], &config.ServerIP, sizeof(config.ServerIP));
	Set_Size(sizeof(config.ServerIP));

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

	if (found == 1)
	{
		memcpy(&RESPData[RESPsize], Client.Bootfile, sizeof(Client.Bootfile));
		Set_Size(sizeof(Client.Bootfile));
	}
	else
		Set_Size(128);

	/* MAGIC COOKIE */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_COOKIE], 4);
	Set_Size(4);

	/* Option Netmask (1) */
	char netopt[2] = { 0x01, IPV4_ADDR_LENGTH };

	memcpy(&RESPData[RESPsize], netopt, sizeof(netopt));
	Set_Size(sizeof(netopt));

	memcpy(&RESPData[RESPsize], &config.SubnetMask, sizeof(config.SubnetMask));
	Set_Size(sizeof(config.SubnetMask));

	/* Option Router (3) */
	char Rtropt[2] = { 0x03, IPV4_ADDR_LENGTH };

	memcpy(&RESPData[RESPsize], Rtropt, sizeof(Rtropt));
	Set_Size(sizeof(Rtropt));

	memcpy(&RESPData[RESPsize], &config.ServerIP, sizeof(config.ServerIP));
	Set_Size(sizeof(config.ServerIP));

	/* DNS-Server (6) */
	char DNSopt[2] = { 0x06, IPV4_ADDR_LENGTH };

	memcpy(&RESPData[RESPsize], DNSopt, sizeof(DNSopt));
	Set_Size(sizeof(DNSopt));

	memcpy(&RESPData[RESPsize], &config.ServerIP, sizeof(config.ServerIP));
	Set_Size(sizeof(config.ServerIP));

	/* Option Netbios Name Server (44) */
	char WINSopt[2] = { 0x2c, IPV4_ADDR_LENGTH };

	memcpy(&RESPData[RESPsize], WINSopt, sizeof(WINSopt));
	Set_Size(sizeof(WINSopt));

	memcpy(&RESPData[RESPsize], &config.ServerIP, sizeof(config.ServerIP));
	Set_Size(sizeof(config.ServerIP));

	/* DHCP Response Type */
	char DHCP_ACK[3] = { 0x35, 0x01, setDHCPRespType(found) };

	memcpy(&RESPData[RESPsize], DHCP_ACK, sizeof(DHCP_ACK));
	Set_Size(sizeof(DHCP_ACK));

	/* Option Server Ident (54) */
	char idtopt[2] = { 0x36, IPV4_ADDR_LENGTH };

	memcpy(&RESPData[RESPsize], idtopt, sizeof(idtopt));
	Set_Size(sizeof(idtopt));

	memcpy(&RESPData[RESPsize], &config.ServerIP, sizeof(config.ServerIP));
	Set_Size(sizeof(config.ServerIP));

	/* DHCP-Option "Vendor-Class" (60) */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_VENOPTION], 2);
	Set_Size(2);

	memcpy(&RESPData[RESPsize], &Data[(BOOTP_OFFSET_VENOPTION + 2)], Data[(BOOTP_OFFSET_VENOPTION + 1)]);
	Set_Size(Data[(BOOTP_OFFSET_VENOPTION + 1)]);

	if (found == 1)
	{
		/* TFTP Server Hostname (66) */
		char TFTPopt[2] = { 0x42, strlen(Server.nbname) };

		memcpy(&RESPData[RESPsize], TFTPopt, sizeof(TFTPopt));
		Set_Size(sizeof(TFTPopt));

		memcpy(&RESPData[RESPsize], Server.nbname, strlen(Server.nbname));
		Set_Size(strlen(Server.nbname));
	}
		
	/* Client System Architecture (93) */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_CARCH], 2);
	Set_Size(Data[(BOOTP_OFFSET_CARCH + 1)]);

	memcpy(&RESPData[RESPsize], &Data[(BOOTP_OFFSET_CARCH + 2)], Data[(BOOTP_OFFSET_CARCH + 1)]);
	Set_Size(Data[(BOOTP_OFFSET_CARCH + 1)]);

	/* DHCP-UUID / GUID (97) */
	memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_GUID], 2);
	Set_Size(2);

	memcpy(&RESPData[RESPsize], &Data[(BOOTP_OFFSET_GUID + 3)], Data[(BOOTP_OFFSET_GUID + 1)]);
	Set_Size(Data[(BOOTP_OFFSET_GUID + 1)]);
		
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

		sprintf(logbuffer, "========================================\n");
		logger(logbuffer);
	}
	else
	{
		/* WDSNBP related informations */
		if (Client.ActionDone == 0)
			Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;

		if (config.AllowUnknownClients == 0)
		{
			char aprovalmsg[29] = {
				WDSBP_OPT_NEXT_ACTION, 0x01, Client.Action,
				WDSBP_OPT_REQUEST_ID, 0x04, 0x00, 0x00, 0x00, Server.RequestID,
				WDSBP_OPT_POLL_INTERVAL, 0x02, 0x00, config.PollIntervall,
				WDSBP_OPT_POLL_RETRY_COUNT, 0x02, 0x00, config.TFTPRetryCount,
				WDSBP_OPT_ACTION_DONE, 0x01, Client.ActionDone,
				WDSBP_OPT_VERSION_QUERY, 0x01, config.VersionQuery,
				WDSBP_OPT_PXE_CLIENT_PROMPT, 0x01, config.PXEClientPrompt, 
				WDSBP_OPT_PXE_PROMPT_DONE, 0x01, config.PXEClientPrompt };

			char admopt[2] = { 0xfa, sizeof(aprovalmsg) };

			memcpy(&RESPData[RESPsize], admopt, sizeof(admopt));
			Set_Size(sizeof(admopt));

			memcpy(&RESPData[RESPsize], aprovalmsg, sizeof(aprovalmsg));
			Set_Size(sizeof(aprovalmsg));
		}
	}

	/* End of DHCP-Options */
	char DHCPEnd[1] = { 0xff };
	memcpy(&RESPData[RESPsize], DHCPEnd, sizeof(DHCPEnd));
	Set_Size(sizeof(DHCPEnd));

	return WDS_Send(con, RESPData, RESPsize);
}

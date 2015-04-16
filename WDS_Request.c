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
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "WDS.h"

int GetClientinfo(int Device, int arch, unsigned char* hwadr, unsigned char* guid, unsigned char* wds_options)
{
	if (Device != -1)
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

		if (arch == 0)
		{
			sprintf(logbuffer, "ARCH: x86\n");
			logger(logbuffer);
		}

		if (arch == 6)
		{
			sprintf(logbuffer, "ARCH: x64\n");
			logger(logbuffer);
		}

		if (arch == 7)
		{
			sprintf(logbuffer, "ARCH: EFI x64\n");
			logger(logbuffer);
		}

		#ifdef _WIN32		
			print_wdsnbp_options(wds_options);
		#endif

		Server.RequestID = Server.RequestID + 1;

		if (Server.RequestID == 99)
			Server.RequestID = 1;

		return 1;
	}
	else
		return 0;
				
}

void selectBootFile(int arch, char* Bootfile, char* BootStore)
{
	if (arch == 6)
	{
		sprintf(Bootfile, "\\Boot\\x64\\pxeboot.n12");
		sprintf(BootStore, "\\Boot\\x64\\default.bcd");
	}
	else
		if (arch == 0)
		{
			sprintf(Bootfile, "\\Boot\\x86\\pxeboot.n12");
			sprintf(BootStore, "\\Boot\\x86\\default.bcd");
		}
		else
			sprintf(Bootfile, "\\startrom.0");
}

int GetPacketType(int con, char* Data, size_t Packetlen)
{
#define PKT_NCQ		0x51434e81	/* Network Card Query */
#define PKT_WDS		0x63825363	/* WDS BOOTP Packet */

	int retval = 0;

	uint32_t Packettype = 0;
	unsigned char DHCP_MAGIC_COOKIE[4] = { 0x63, 0x82, 0x53, 0x63 };
	unsigned char WDSC_Client_Info[1] = { 0xFA };
	unsigned char mac[6] = "";
	unsigned char guid[16] = "";
	unsigned char options[12] = "";
	
	memcpy(&Packettype, Data, sizeof(Packettype));

	switch (SWAB32(Packettype))
	{
	case PKT_NCQ:
		retval = Handle_NCQ_Request(con, Data, Packetlen);
		break;
	default:
		if (memcmp(DHCP_MAGIC_COOKIE, &Data[BOOTP_OFFSET_COOKIE], sizeof(DHCP_MAGIC_COOKIE)) == 0)
		{
			memcpy(&mac, &Data[BOOTP_OFFSET_MACADDR], sizeof(mac));
			memcpy(&guid, &Data[BOOTP_OFFSET_GUID], sizeof(guid));
			memcpy(&options, &Data[BOOTP_OFFSET_OPTIONS], 12);

			if (Packetlen >= DHCP_MINIMAL_PACKET_SIZE && memcmp(WDSC_Client_Info, &Data[BOOTP_OFFSET_WDSNBP], sizeof(WDSC_Client_Info)) == 0)
			{
				retval = Handle_NBP_Request(con, Data, Packetlen,
					Data[BOOTP_OFFSET_SYSARCH], GetClientinfo(Data[287],
					Data[BOOTP_OFFSET_SYSARCH], mac, guid, options));
				return retval;
			}
			else
			{
				retval = Handle_NBP_Request(con, Data, Packetlen, 0, 0);
				return retval;
			}
		}
		break;
	}
	
	return retval;
}

int setDHCPRespType(int found)
{
	if (found == 1)
		return DHCP_RESP_ACK;
	else
		return DHCP_RESP_OFF;
}

int Handle_NBP_Request(int con, char* Data, size_t Packetlen, int arch, int found)
{
	
	selectBootFile(arch, Bootfile, BootStore);

	RESPsize = 0;

	char ZeroIPAddr[4] = { 0x00, 0x00, 0x00, 0x00 };

	if (memcmp(ZeroIPAddr, &Data[BOOTP_OFFSET_YOURIP], sizeof(ZeroIPAddr)) != 0 && 
		memcmp(ZeroIPAddr, &Data[BOOTP_OFFSET_CLIENTIP], sizeof(ZeroIPAddr)) == 0)
	{
		gethostname(Server.nbname, sizeof(Server.nbname));
		uint32_t MyServerIP = IP2Bytes(hostname_to_ip(Server.nbname));

		/* Boot-Reply */
		char Bootreply[1] = { BOOTP_REPLY };
		memcpy(&RESPData[RESPsize], Bootreply, sizeof(Bootreply));
		Set_Size(sizeof(Bootreply));

		/*Hardware Type */
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

		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_ADDRPADD], 2);
		Set_Size(2);

		/* Client-IP */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_CLIENTIP], 4);
		Set_Size(4);

		/* Your-IP */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_YOURIP], 4);
		Set_Size(4);

		/* Next Server-IP */
		memcpy(&RESPData[RESPsize], &MyServerIP, sizeof(MyServerIP));
		Set_Size(sizeof(MyServerIP));

		/* Relay Agent-IP */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_RELAYIP], 4);
		Set_Size(4);

		/* Client Mac-Address */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_MACADDR], 6);
		Set_Size(6);

		/* Address Padding */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_MACPADDING], 10);
		Set_Size(10);

		/* Server Hostname */
		memcpy(&RESPData[RESPsize], Server.nbname, sizeof(Server.nbname));
		Set_Size(sizeof(Server.nbname));

		/* Bootfile */
		memcpy(&RESPData[RESPsize], Bootfile, sizeof(Bootfile));
		Set_Size(sizeof(Bootfile));
		
		/* MAGIC COOKIE */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_COOKIE], 4);
		Set_Size(4);

		/* DHCP-Response (ACK) */
		char DHCP_ACK[3] = { 0x35, 0x01, setDHCPRespType(found) };

		memcpy(&RESPData[RESPsize], DHCP_ACK, sizeof(DHCP_ACK));
		Set_Size(sizeof(DHCP_ACK));

		/* Option Netmask (1) */
		char netopt[6] = { 0x01, 0x04, 0xff, 0xff, 0xff, 0x00 };

		memcpy(&RESPData[RESPsize], netopt, sizeof(netopt));
		Set_Size(sizeof(netopt));

		/* Option Router (3) */
		char Rtropt[2] = { 0x03, 0x04 };

		memcpy(&RESPData[RESPsize], Rtropt, sizeof(Rtropt));
		Set_Size(sizeof(Rtropt));

		memcpy(&RESPData[RESPsize], &MyServerIP, sizeof(MyServerIP));
		Set_Size(sizeof(MyServerIP));

		/* DNS-Server (6) */
		char DNSopt[2] = { 0x06, 0x04 };

		memcpy(&RESPData[RESPsize], DNSopt, sizeof(DNSopt));
		Set_Size(sizeof(DNSopt));

		memcpy(&RESPData[RESPsize], &MyServerIP, sizeof(MyServerIP));
		Set_Size(sizeof(MyServerIP));

		/* DHCP-Option "Vendor-Class" (60) */
		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_VENOPTION], 11);
		Set_Size(11);

		/* DHCP-UUID/GUID */
		memcpy(&RESPData[RESPsize], &Data[254], 2);
		Set_Size(2);

		memcpy(&RESPData[RESPsize], &Data[BOOTP_OFFSET_GUID], 17);
		Set_Size(17);

		/* Option Server Ident (54) */
		char idtopt[2] = { 0x36, 0x04 };

		memcpy(&RESPData[RESPsize], idtopt, sizeof(idtopt));
		Set_Size(sizeof(idtopt));

		memcpy(&RESPData[RESPsize], &MyServerIP, sizeof(MyServerIP));
		Set_Size(sizeof(MyServerIP));

		/* Option Netbios Name Server (44) */
		char WINSopt[2] = { 0x2c, 0x04 };

		memcpy(&RESPData[RESPsize], WINSopt, sizeof(WINSopt));
		Set_Size(sizeof(WINSopt));

		memcpy(&RESPData[RESPsize], &MyServerIP, sizeof(MyServerIP));
		Set_Size(sizeof(MyServerIP));

		if (found == 1)
		{
			sprintf(logbuffer, "FILE: %s\n", Bootfile);
			logger(logbuffer);

			/* TFTP Server Hostname (66) */
			char TFTPopt[2] = { 0x42, strlen(Server.nbname) };

			memcpy(&RESPData[RESPsize], TFTPopt, sizeof(TFTPopt));
			Set_Size(sizeof(TFTPopt));

			memcpy(&RESPData[RESPsize], Server.nbname, strlen(Server.nbname));
			Set_Size(strlen(Server.nbname));
		
			/* Boot Configuration Store (BCD) */
			char bcdopt[2] = { 0xfc, strlen(BootStore) };

			memcpy(&RESPData[RESPsize], bcdopt, sizeof(bcdopt));
			Set_Size(sizeof(bcdopt));

			memcpy(&RESPData[RESPsize], BootStore, strlen(BootStore));
			Set_Size(strlen(BootStore));

			sprintf(logbuffer, "BCD: %s\n", BootStore);
			logger(logbuffer);

			sprintf(logbuffer, "========================================\n");
			logger(logbuffer);
		}
		else
		{
			char aprovalmsg[18] = { 
			0x02, 0x01, 0x01, 0x05, 0x04, 
			0x00, 0x00, 0x00, Server.RequestID, 0x03, 
			0x02, 0x00, 0x14, 0x04, 0x02, 0x00, 0xba 
			};

			char admopt[2] = { 0xfa, sizeof(aprovalmsg) };

			memcpy(&RESPData[RESPsize], admopt, sizeof(admopt));
			Set_Size(sizeof(admopt));

			memcpy(&RESPData[RESPsize], aprovalmsg, sizeof(aprovalmsg));
			Set_Size(sizeof(aprovalmsg));
		}

		/* End of DHCP-Options */
		char DHCPEnd[1] = { 0xff };
		memcpy(&RESPData[RESPsize], DHCPEnd, sizeof(DHCPEnd));
		Set_Size(sizeof(DHCPEnd));

		return WDS_Send(con, RESPData, RESPsize);
	}
	else
		return 1;
}

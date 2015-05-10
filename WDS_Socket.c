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

#ifdef _WIN32
int startWinsock(void)
{
	WSADATA wsa;
	return WSAStartup(MAKEWORD(2, 0), &wsa);
}
#endif

int CreateSocketAndBind(uint16_t port)
{
#ifdef _WIN32
	long rc;
	rc = startWinsock();

	if (rc != 0)
		return -1;

#endif
	int sockfd = SOCKET_ERROR;
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sockfd == -1)
		return -1;
	else
	{
		ZeroOut((char*)&serv_addr, sizeof(serv_addr));

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(port);

		if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
			sockfd = -1;
		else
		{
			getnameinfo((struct sockaddr *)&serv_addr, sizeof(serv_addr), Server.nbname, sizeof(Server.nbname), NULL, 0, 0);
			config.ServerIP = IP2Bytes(hostname_to_ip(Server.nbname));
			config.SubnetMask = IP2Bytes("255.255.255.0");
		}
	}

	return sockfd;
}

int bootp_start()
{
	int m_socket = SOCKET_ERROR; 
	
	m_socket = CreateSocketAndBind(config.BOOTPPort);
	
	if (m_socket != SOCKET_ERROR)
		return WDS_Recv_bootp(m_socket);
	else
		return m_socket;
}

int tftp_start()
{
	int m_socket = SOCKET_ERROR;

	m_socket = CreateSocketAndBind(69);

	if (m_socket != SOCKET_ERROR)
		return WDS_Recv_bootp(m_socket);
	else
		return m_socket;
}

int WDS_Recv_bootp(int con)
{
	char Buffer[1024];
	int load = 0;
	int retval = 0;
	int found = 0;
	uint32_t Packettype = 0;
	char DHCP_MAGIC_COOKIE[4] = { 0x63, 0x82, 0x53, 0x63 };
	char WDSNBP_INDICATOR[1] = { 0xfa };
	ZeroOut(RESPData, sizeof(RESPData));
	
	while (load == 0)
	{
		fromlen = sizeof(from);
		retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr *) &from, &fromlen);

		if (retval > 0)
		{
			if (memcmp(DHCP_MAGIC_COOKIE, &Buffer[BOOTP_OFFSET_COOKIE], 4) == 0 && Buffer[BOOTP_OFFSET_BOOTPTYPE] == BOOTP_REQUEST)
				if (isValidDHCPType(Buffer[242]) == 0)
				{
					memcpy(&Client.hw_address, &Buffer[BOOTP_OFFSET_MACADDR], Buffer[BOOTP_OFFSET_MACLEN]);
					memcpy(&Client.ClientGuid, &Buffer[(BOOTP_OFFSET_GUID + 3)], Buffer[(BOOTP_OFFSET_GUID + 1)]);
					memcpy(&Client.ClientArch, &Buffer[(BOOTP_OFFSET_CARCH + 2)], Buffer[(BOOTP_OFFSET_CARCH + 1)]);

					if (retval > DHCP_MINIMAL_PACKET_SIZE && memcmp(WDSNBP_INDICATOR, &Buffer[BOOTP_OFFSET_WDSNBP], 1) == 0)
						if (Client.ActionDone == 1)	/* Server is done */
							retval = Handle_NBP_Request(con, Buffer, retval, \
							GetClientinfo(Buffer[BOOTP_OFFSET_SYSARCH], Client.hw_address, Client.ClientGuid, Client.ActionDone));
						else /* Look up Server Rules / Settings */
							if (config.AllowUnknownClients == 0 && GetClientRule(Client.hw_address) == 0)
								Client.ActionDone = 1;
							else
								Client.ActionDone = 0;
					else /* Prepare an initial Approval */
					{
						Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;
						Client.ActionDone = 0;

						retval = Handle_NBP_Request(con, Buffer, retval, GetClientinfo(Buffer[BOOTP_OFFSET_SYSARCH], Client.hw_address, Client.ClientGuid, 0));
					}
				}
			else
			{
				memcpy(&Packettype, Buffer, sizeof(Packettype));

				switch (SWAB32(Packettype))
				{
				case PKT_NCQ:
					retval = Handle_NCQ_Request(con, Buffer, retval);
					break;
				default:
					break;
				}
			}
			
			ZeroOut(RESPData, sizeof(RESPData));
		}
	}
	
	return 0;
}

int WDS_Send(int con, char* data, size_t length)
{
	return sendto(con, data, length, 0, (struct sockaddr *) &from, sizeof(from));
}

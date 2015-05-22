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

int CreateUnicastSocketAndBind(uint16_t port, in_addr_t in_addr)
{
	int enabled = 1;

#ifdef _WIN32
	long rc;
	rc = startWinsock();

	if (rc != 0)
		return -1;

#endif
	int sockfd = SOCKET_ERROR;
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sockfd == -1)
		return -1;
	else
	{
		ZeroOut((char*)&Userv_addr, sizeof(Userv_addr));
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) == 0 &&
			setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof enabled) == 0)
		{

			memset(&Userv_addr, 0, sizeof(Userv_addr));
			Userv_addr.sin_family = AF_INET;
			Userv_addr.sin_addr.s_addr = htonl(in_addr);
			Userv_addr.sin_port = htons(4011);

			if (bind(sockfd, (struct sockaddr*)&Userv_addr, sizeof(Userv_addr)) < 0)
			{
				sockfd = -1;
				printf("Cant open unicast socket...\n");
			}
		}
	}

	return sockfd;
}

int CreateBroadCastSocketAndBind(uint16_t port, in_addr_t in_addr)
{
	int enabled = 1;
	struct hostent *he;
	int sockfd = SOCKET_ERROR;

	ZeroOut((char*)&Bserv_addr, sizeof(Bserv_addr));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd == -1)
		return -1;
	else
	{

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof enabled) == 0 &&
				setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof enabled) == 0)
		{
			memset(&Bserv_addr, 0, sizeof(Bserv_addr));

			Bserv_addr.sin_family = AF_INET;
			Bserv_addr.sin_addr.s_addr = INADDR_ANY;
			Bserv_addr.sin_port = htons(67);

			if (bind(sockfd, (struct sockaddr*)&Bserv_addr, sizeof(Bserv_addr)) < 0)
			{
				sockfd = -1;
				Config.DHCPReqDetection = 0;
			}
		}
	}

	return sockfd;
}

int bootp_start()
{
	int bootp_socket = SOCKET_ERROR;
	int dhcp_socket = SOCKET_ERROR;

	gethostname(Server.nbname, sizeof(Server.nbname));
	Config.ServerIP = IP2Bytes(hostname_to_ip(Server.nbname));
	Config.SubnetMask = IP2Bytes("255.255.255.0");

	pid_t pid = fork();

	if (pid > 0)
	{
		bootp_socket = CreateUnicastSocketAndBind(Config.BOOTPPort, INADDR_ANY);

		if (bootp_socket != SOCKET_ERROR)
			return WDS_Recv_bootp(bootp_socket);
		else
			return bootp_socket;
	}
	else if (pid == 0)
	{
		dhcp_socket = CreateBroadCastSocketAndBind(Config.DHCPPort, INADDR_BROADCAST);

		if (dhcp_socket != SOCKET_ERROR)
			return WDS_Recv_DHCP(dhcp_socket);
		else
			return dhcp_socket;
	}
	return 1;
}

int WDS_Recv_DHCP(int con)
{
	char Buffer[1024];
	int load = 0;
	int retval = 0;

	uint32_t Packettype = 0;
	char DHCP_MAGIC_COOKIE[4] = { 0x63, 0x82, 0x53, 0x63 };

	ZeroOut(RESPData, sizeof(RESPData));

	while (load == 0)
	{
		bfromlen = sizeof(bfrom);
		retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr *) &bfrom, &bfromlen);

		if (retval > 0)
		{
			if (Buffer[242] == 1)
			{
				Client.inDHCPMode = 1;
				retval = Handle_DHCP_Request(con, Buffer, retval, 0);
			}

			ZeroOut(RESPData, sizeof(RESPData));
		}
	}

	return 0;
}

int WDS_Recv_bootp(int con)
{
	char Buffer[1024];
	int load = 0;
	int retval = 0;

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
			if (memcmp(DHCP_MAGIC_COOKIE, &Buffer[BOOTP_OFFSET_COOKIE], 4) == 0)
			{
				Client.inDHCPMode = 0;

				if (isValidDHCPType(Buffer[242]) == 0)
				{
					if (Buffer[291] == 55 && Buffer[292] == 11)
						Client.isWDSRequest = 1;
					else
						Client.isWDSRequest = 0;

					if (Client.isWDSRequest == 1)
					{
							memcpy(&Client.hw_address, &Buffer[BOOTP_OFFSET_MACADDR], Buffer[BOOTP_OFFSET_MACLEN]);
							memcpy(&Client.ClientGuid, &Buffer[(BOOTP_OFFSET_GUID + 3)], Buffer[(BOOTP_OFFSET_GUID + 1)]);
							memcpy(&Client.ClientArch, &Buffer[(BOOTP_OFFSET_CARCH + 2)], Buffer[(BOOTP_OFFSET_CARCH + 1)]);

							if (Client.ActionDone == 1)
								retval = Handle_NBP_Request(con, Buffer, retval, GetClientinfo(Buffer[BOOTP_OFFSET_SYSARCH], Client.hw_address, Client.ClientGuid, Client.ActionDone));
							else
								if (Config.AllowUnknownClients == 0 && GetClientRule(Client.hw_address) == 0)
									Client.ActionDone = 1;
								else
									Client.Action = WDSBP_OPTVAL_ACTION_ABORT;
									Client.ActionDone = 1;
					}
					else
					{
						Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;
						Client.ActionDone = 0;

						retval = Handle_NBP_Request(con, Buffer, retval, 0);
					}
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

int DHCP_Send(int con, char* data, size_t length)
{
	int send_length = 0;
	bfrom.sin_addr .s_addr = inet_addr("255.255.255.255");
	send_length = sendto(con, data, length, 0, (struct sockaddr*)&bfrom, sizeof(bfrom));

	return 0;
}

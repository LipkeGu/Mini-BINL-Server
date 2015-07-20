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

int CreateUnicastSocketAndBind(int port, in_addr_t in_addr)
{
	char enabled[1] = { 0x01 };
	int sockfd = SOCKET_ERROR;

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sockfd == SOCKET_ERROR)
		return SOCKET_ERROR;
	else
	{
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, enabled, sizeof(int)) == 0 &&
			setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, enabled, sizeof(int)) == 0)
		{

			memset(&from, 0, sizeof(from));
			memset(&Userv_addr, 0, sizeof(Userv_addr));

			Userv_addr.sin_family = AF_INET;
			Userv_addr.sin_addr.s_addr = in_addr;
			Userv_addr.sin_port = htons(port);

			if (bind(sockfd, (struct sockaddr*)&Userv_addr, sizeof(Userv_addr)) < 0)
			{
				sockfd = SOCKET_ERROR;
				printf("Cant open unicast socket...\n");
			}
		}
		else
		{
			printf("[E] CreateUnicastSocketAndBind(): %s\n", strerror(errno));
			return SOCKET_ERROR;
		}

	}

	return sockfd;
}

int CreateBroadCastSocketAndBind(int port, in_addr_t in_addr)
{
	char  enabled[1] = { 0x01 };
	int sockfd = SOCKET_ERROR;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd != SOCKET_ERROR)
	{

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, enabled, sizeof(int)) == 0 &&
			setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, enabled, sizeof(int)) == 0)
		{
			memset(&Bserv_addr, 0, sizeof(Bserv_addr));
			memset(&bfrom, 0, sizeof(bfrom));

			Bserv_addr.sin_family = AF_INET;
			Bserv_addr.sin_addr.s_addr = in_addr;
			Bserv_addr.sin_port = htons(port);

			if (bind(sockfd, (struct sockaddr*)&Bserv_addr, sizeof(Bserv_addr)) < 0)
			{
				sockfd = SOCKET_ERROR;
				printf("[E] Cant open Broadcast Socket!\n");
			}
		}
		else
			return SOCKET_ERROR;
	}

	return sockfd;
}

int bootp_start()
{

#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 0), &wsa);
#endif

	int bootp_socket = SOCKET_ERROR;
#ifndef _WIN32
	int dhcp_socket = SOCKET_ERROR;
#endif
	int hostretval = 0;

	hostretval = gethostname(Server.nbname, sizeof(Server.nbname));
	Config.ServerIP = IP2Bytes(hostname_to_ip(Server.nbname));
	Config.SubnetMask = IP2Bytes("255.255.255.0");
#ifndef _WIN32
	pid_t pid = fork();
	if (pid > 0)
	{
#endif
		bootp_socket = CreateUnicastSocketAndBind(Config.BOOTPPort, INADDR_ANY);

		if (bootp_socket != SOCKET_ERROR)
			return BOOTP_listening(bootp_socket, (saddr*)&from, 0);
		else
			return bootp_socket;
#ifndef _WIN32
	}
	else
	{
		dhcp_socket = CreateBroadCastSocketAndBind(Config.DHCPPort, INADDR_ANY);

		if (dhcp_socket != SOCKET_ERROR)
			return DHCP_listening(dhcp_socket, (saddr*)&bfrom, 1);
		else
			return dhcp_socket;
	}
#endif
	return 1;
}

int DHCP_listening(int con, saddr* socket, int mode)
{
	if (socket == NULL)
		return 1;

	Client.inDHCPMode = 1;
	int retval = 0, load = 0, i = 0, hasflag = 0;
	
	char Buffer[1460];

	ZeroOut(Buffer, sizeof(Buffer));

	while (load == 0)
	{
		socketlen = sizeof(bfrom);
		retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&bfrom, &socketlen);

		for (i; i < sizeof(Buffer); i = i++)
			if (memcmp("PXEClient", &Buffer[i], 9) == 0)
				hasflag = 1;

		if (hasflag == 1)
			if (retval < 0)
				return errno;
			else
			{
				retval = Handle_DHCP_Request(con, Buffer, 0, NULL, mode);

				ZeroOut(&Client, sizeof(Client));

				if (retval == SOCKET_ERROR)
				{
					printf("[E] Handle_DHCP_Request(): %s\n", strerror(errno));
					return SOCKET_ERROR;
				}
			}
	}
}

int BOOTP_listening(int con, saddr* socket, int mode)
{
	if (socket == NULL)
		return 1;

	Client.inDHCPMode = 0;
	int retval = 0, load = 0;
	char Buffer[1460];
	int found = 0;

	ZeroOut(Buffer, sizeof(Buffer));

	while (load == 0)
	{
		socketlen = sizeof(from);
		retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&from, &socketlen);

		/* Detect the WDS fingerprint... WDSNBP writes the table 14 bytes to the end of the packet and is always 11 bytes in size */

		if (Buffer[(retval - 14)] == 55 && Buffer[(retval - 13)] == 11)
			Client.isWDSRequest = 1;
		else
			Client.isWDSRequest = 0;

		if (Client.isWDSRequest == 1)
		{
			memcpy(&Client.hw_address, &Buffer[BOOTP_OFFSET_MACADDR], Buffer[BOOTP_OFFSET_MACLEN]);
			memcpy(&Client.ClientArch, &Buffer[(BOOTP_OFFSET_CARCH + 2)], Buffer[(BOOTP_OFFSET_CARCH + 1)]);

			if (Client.ActionDone == 1)
				retval = Handle_DHCP_Request(con, Buffer,
				GetClientinfo(Buffer[BOOTP_OFFSET_SYSARCH], Client.hw_address, Client.ActionDone), NULL, 0);
			else
				if (Config.AllowUnknownClients == 0 && GetClientRule(Client.hw_address) == 1)
					Client.ActionDone = 1;
				else
					Client.Action = WDSBP_OPTVAL_ACTION_ABORT;

			Client.ActionDone = 1;

		}
		else
		{
			Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;
			Client.ActionDone = 0;

			retval = Handle_DHCP_Request(con, Buffer, 0, NULL, mode);
		}
	}
}

int validateDHCPPacket(char* Data, size_t packetlen)
{
	/* ensure that the packet is larger than 240 bytes */
	if (packetlen <= DHCP_MINIMAL_PACKET_SIZE)
	{
		printf("[E] Packet too short!\n");
		return 1;
	}

	if (Data[BOOTP_OFFSET_COOKIE] == htonl(DHCP_MAGIC_COOKIE) != 0)
	{
		printf("[E] Cookie is not on the right place!\n");
		return 1;
	}

	/* Clients requests has always zero as next server set */
	if (Data[BOOTP_OFFSET_NEXTSERVER] != htonl(0))
	{
		printf("[E] Client packet has nextserver set!\n");
		return 1;
	}

	/* Transaction id should never be zero */
	if (Data[BOOTP_OFFSET_TRANSID] == htonl(0))
	{
		printf("[E] Transaction ID is invalid!\n");
		return 1;
	}

	/* ensure that we have got only client packets! */
	if (isValidDHCPType(Data[BOOTP_OFFSET_MSGTYPE]) == 1)
	{
		printf("invalid (Client) MessageType!\n");
		return 1;
	}

	return 0;
}

int WDS_Send(int con, char* data, size_t length, saddr* socket, int mode)
{
	socket = socket;

	if (mode == 0)
		return sendto(con, data, length, 0, (struct sockaddr*)&from, sizeof(from));
	else
	{
		bfrom.sin_addr.s_addr = inet_addr("255.255.255.255");
		return sendto(con, data, length, 0, (struct sockaddr*)&bfrom, sizeof(bfrom));

	}
}

int DHCP_Send(int con, char* data, size_t length, saddr* socket, int mode)
{
	socket = socket;
	mode = mode;

	bfrom.sin_addr.s_addr = inet_addr("255.255.255.255");
	return sendto(con, data, length, 0, (struct sockaddr*)&bfrom, sizeof(bfrom));
}

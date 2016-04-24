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

int CreateSocketandBind(int port, int SocketType, int AddressFamiliy, int Protocol)
{
	char enabled[1] = { 0x01 };
	int sockfd = socket(AddressFamiliy, SocketType, Protocol);
	struct sockaddr_in _lsock;

	if (sockfd != SOCKET_ERROR)
	{
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, enabled, sizeof(int)) == 0 &&
			setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, enabled, sizeof(int)) == 0)
		{
			memset(&_lsock, 0, sizeof(_lsock));
			
			_lsock.sin_family = AF_INET;
			_lsock.sin_addr.s_addr = INADDR_ANY;
			_lsock.sin_port = htons(port);

			if (bind(sockfd, (struct sockaddr*)&_lsock, sizeof(_lsock)) < 0)
			{
				sprintf(logbuffer, "[E] Bind(): Cant bind to Socket on port %d: (Error: %s)\n", port, strerror(errno));
				logger(logbuffer);

				return SOCKET_ERROR;
			}
		}
		else
		{
			sprintf(logbuffer, "[E] SetSockOpt(): Unable to Option for socket on port %d: (Error: %s)\n", port, strerror(errno));
			logger(logbuffer);

			return SOCKET_ERROR;
		}
	}
	else
	{
		sprintf(logbuffer, "[E] Socket(): Unable to create socket option for port %d: (Error: %s)\n", port, strerror(errno));
		logger(logbuffer);

		return SOCKET_ERROR;
	}

	return sockfd;
}

#ifdef _WIN32
	DWORD WINAPI DHCP_Thread()
#else
	void DHCP_Thread()
#endif
{
	memset(&bfrom, 0, sizeof(bfrom));
	
	int sockfd = CreateSocketandBind(67, SOCK_DGRAM, AF_INET, IPPROTO_IP);
	int Retval = 0;

	if (sockfd == SOCKET_ERROR)
	{
		sprintf(logbuffer, "[E] DHCP_Thread(): Unable to create Socket (Error: %s)\n", strerror(errno));
		logger(logbuffer);

		exit(errno);
	}
	else
		Retval = listening("DHCP", sockfd, 1);

#ifdef _WIN32
	return Retval;
#endif	
}

#ifdef _WIN32
	DWORD WINAPI BOOTP_Thread()
#else
	void BOOTP_Thread()
#endif
{
	memset(&from, 0, sizeof(from));

	int sockfd = CreateSocketandBind(4011, SOCK_DGRAM, AF_INET, IPPROTO_UDP);
	int Retval = 0;

	if (sockfd == SOCKET_ERROR)
	{
		Retval = sockfd;

		sprintf(logbuffer, "[E] BOOTP_Thread(): Unable to create Socket (Error: %s)\n", strerror(errno));
		logger(logbuffer);
	}
	else
		Retval = listening("BOOTP", sockfd, 0);

#ifdef _WIN32
	return Retval;
#endif
}

int bootp_start()
{
	int Retval = 0;

#ifdef _WIN32
	WSADATA wsa;
	DWORD myThreadID;
	HANDLE ThreadID;

	Retval = WSAStartup(MAKEWORD(2, 0), &wsa);
#else
	pthread_t myThreadID;
#endif

	Retval = gethostname(Server.nbname, sizeof(Server.nbname));

	Config.ServerIP = IP2Bytes(hostname_to_ip(Server.nbname));

	/* DHCP Thread (Handle this in Background) */

#ifdef _WIN32
	ThreadID = CreateThread(0, 0, &DHCP_Thread, 0, 0, &myThreadID);
#else
	Retval = pthread_create(&myThreadID, 0, &DHCP_Thread, NULL);
#endif
	BOOTP_Thread();

#ifdef _WIN32
	CloseHandle(ThreadID);
#else
	pthread_exit(&myThreadID);
#endif

	return Retval;
}

int listening(const char* Context, int con, int mode)
{
	int Retval = 1;
	char Buffer[DHCP_BUFFER_SIZE];
	uint32_t PacketSize = 0, MessageType = 0;

	while (Retval != SOCKET_ERROR)
	{
		ZeroOut(Buffer, sizeof(Buffer));

		if (mode == 0)
		{
			socketlen = sizeof(from);
			Retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&from, &socketlen);
		}
		else
		{
			socketlen = sizeof(bfrom);
			Retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&bfrom, &socketlen);
		}

		if (Retval < 1)
			continue;
		
		PacketSize = Retval;
		
		switch (Buffer[BOOTP_OFFSET_BOOTPTYPE])
		{
		case BOOTP_REQUEST: /* DHCP Request */
			if (PacketSize > DHCP_MINIMAL_PACKET_SIZE)
			{
				if (Buffer[(PacketSize - 14)] == 55 && Buffer[(PacketSize - 13)] == 11)
					Client.isWDSRequest = 1;
				else
					Client.isWDSRequest = 0;
				
				if (Client.isWDSRequest == 1 && mode == 0)
				{
					memcpy(&Client.hw_address, &Buffer[BOOTP_OFFSET_MACADDR], Buffer[BOOTP_OFFSET_MACLEN]);

					if (wdsnbp.ActionDone == 1)
						Retval = Handle_DHCP_Request(con, Buffer, GetClientinfo(Buffer[BOOTP_OFFSET_SYSARCH], Client.hw_address,
							GetClientRule(Client.hw_address)), mode);

					wdsnbp.ActionDone = 1;
				}
				else
				{
					Client.isWDSRequest = 0;
					wdsnbp.ActionDone = 0;
					wdsnbp.PXEPromptDone = 0;

					Retval = Handle_DHCP_Request(con, Buffer, 0, mode);
				}
			}
			break;
		default:
			memcpy(&MessageType, &Buffer[BOOTP_OFFSET_BOOTPTYPE], sizeof(MessageType));

			switch (SWAB32(MessageType))
			{
			case PKT_NCQ:
				Retval = Handle_NCQ_Request(con, Buffer, PacketSize);
				break;
			case PKT_RQU:
				break;
			case PKT_NEG:
				break;
			case PKT_AUT:
				break;
			case PKT_OFF:
				break;
			case PKT_REQ:
				break;
			default:
				break;
			}
			break;
		}
	}

	return Retval;
}

int Send(int con, char* data, size_t length, int mode)
{
	int Retval = 0;

	if (mode == 0)
		Retval = sendto(con, data, length, 0, (struct sockaddr*)&from, sizeof(from));
	else
	{
		bfrom.sin_addr.s_addr = inet_addr(BROADCAST_ADDR);
		Retval = sendto(con, data, length, 0, (struct sockaddr*)&bfrom, sizeof(bfrom));
	}

#if DEBUGMODE == 1
	if (Retval != SOCKET_ERROR && Retval > DHCP_MINIMAL_PACKET_SIZE)
		printf("[D] Sent %d bytes to Client!\n", Retval);
#endif
	return Retval;
}
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
		sockfd = SOCKET_ERROR;
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
				sprintf(logbuffer, "[E] Cant open BOOTP socket: (Error: %s)\n", strerror(errno));
                                logger(logbuffer);
			
                                sockfd = SOCKET_ERROR;
                        }
		}
		else
		{
			sprintf(logbuffer,"[E] Unable to set socket options: (Error: %s)\n", strerror(errno));
                        logger(logbuffer);
                        
                        sockfd = SOCKET_ERROR;
		}
	}

	return sockfd;
}

int CreateBroadCastSocketAndBind(int port, in_addr_t in_addr)
{
	char enabled[1] = { 0x01 };
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
				sprintf(logbuffer, "[E] Cant open DHCP Socket: (Error: %s)\n", strerror(errno));
                                logger(logbuffer);
                                
                                sockfd = SOCKET_ERROR;
                        }
		}
                else
		{
			sprintf(logbuffer,"[E] Unable to set socket options: (Error: %s)\n", strerror(errno));
                        logger(logbuffer);
                        
                        sockfd = SOCKET_ERROR;
		}
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
	int Retval = 0;
	int load = 0;
	char Buffer[DHCP_BUFFER_SIZE];
        uint32_t PacketSize = 0;
        
	if (socket != NULL)
	{
		while (load == 0)
		{
                        ZeroOut(Buffer, sizeof(Buffer));
                        
                        socketlen = sizeof(bfrom);
			Retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&bfrom, &socketlen);
                        
                        if (Retval > 0)
                        {
                            PacketSize = Retval;
			    
                            if (FindVendorOpt(Buffer, PacketSize) == 0)
                            {    
                                Retval = Handle_DHCP_Request(con, Buffer, 0, socket, mode);
				ZeroOut(&Client, sizeof(Client));
                            }
                        }
                }
	}

	return Retval;
}

int BOOTP_listening(int con, saddr* socket, int mode)
{
	int Retval = 1;
	int load = 0;
	char Buffer[DHCP_BUFFER_SIZE];

	if (socket != NULL)
	{
		while (load == 0)
		{
                        ZeroOut(Buffer, sizeof(Buffer));

                        socketlen = sizeof(from);
			Retval = recvfrom(con, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&from, &socketlen);

                        if (Buffer[(Retval - 14)] == 55 && Buffer[(Retval - 13)] == 11)
                            Client.isWDSRequest = 1;
                        else
                            Client.isWDSRequest = 0;
                        
			if (Client.isWDSRequest == 1)
			{
                                memcpy(&Client.hw_address, &Buffer[BOOTP_OFFSET_MACADDR], Buffer[BOOTP_OFFSET_MACLEN]);
				memcpy(&Client.ClientArch, &Buffer[(BOOTP_OFFSET_CARCH + 2)], Buffer[(BOOTP_OFFSET_CARCH + 1)]);

				if (wdsnbp.ActionDone == 1)
                                        Retval = Handle_DHCP_Request(con, Buffer,
					GetClientinfo(Buffer[BOOTP_OFFSET_SYSARCH], Client.hw_address, wdsnbp.ActionDone), socket, mode);
                                else
				{
                                        if (Config.AllowUnknownClients == 0 && GetClientRule(Client.hw_address) == 1)
						wdsnbp.ActionDone = 1;
					else
                                            if (Config.DropUnkownClients != 1 && Config.AllowUnknownClients != 1)
                                                wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_ABORT;
                                            else
                                                wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_DROP;
                                }       
				
                                wdsnbp.ActionDone = 1;
			}
			else
			{
                                wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_APPROVAL;
				wdsnbp.ActionDone = 0;
                                wdsnbp.PXEPromptDone = 0;
                                wdsnbp.Architecture = 0;

				Retval = Handle_DHCP_Request(con, Buffer, wdsnbp.ActionDone, socket, mode);
                                
                                if (Retval == SOCKET_ERROR)
                                    Retval = SOCKET_ERROR;
            		}
		}
	}

	return Retval;
}

int validateDHCPPacket(char* Data, size_t packetlen)
{
	/* ensure that the packet is larger than 240 bytes */
	if (packetlen < DHCP_MINIMAL_PACKET_SIZE)
	{
                sprintf(logbuffer, "[E] Packet too short!\n");
                logger(logbuffer);
		
                return 1;
	}

	if (Data[BOOTP_OFFSET_COOKIE] == htonl(DHCP_MAGIC_COOKIE) != 0)
	{
                sprintf(logbuffer, "[E] Cookie is not on the right place!\n");
                logger(logbuffer);
                
                return 1;
	}

	/* Clients requests has always zero as next server set */
	if (Data[BOOTP_OFFSET_NEXTSERVER] != htonl(0))
	{
		sprintf(logbuffer, "[E] Client packet has next server set!\n");
                logger(logbuffer);
                
                return 1;
	}

	/* Transaction id should never be zero */
	if (Data[BOOTP_OFFSET_TRANSID] == htonl(0))
	{
		
                sprintf(logbuffer, "[E] Transaction ID is invalid!\n");
		logger(logbuffer);
                
                return 1;
	}

	/* ensure that we have got only client packets! */
	if (isValidDHCPType(Data[BOOTP_OFFSET_MSGTYPE]) == 1)
	{
		sprintf(logbuffer, "[E] Invalid (Client) MessageType!\n");
		logger(logbuffer);
                
                return 1;
	}

	return 0;
}

int WDS_Send(int con, char* data, size_t length, saddr* socket, int mode)
{
	socket = socket; /* GCC unused warning */

        if (mode == 0)
            return sendto(con, data, length, 0, (struct sockaddr*)&from, sizeof(from));
        else
        {
            bfrom.sin_addr.s_addr = inet_addr(BROADCAST_ADDR);
            return sendto(con, data, length, 0, (struct sockaddr*)&bfrom, sizeof(bfrom));
        }
}

int DHCP_Send(int con, char* data, size_t length, saddr* socket, int mode)
{
	socket = socket; /* GCC unused warning */
	mode = mode;

	bfrom.sin_addr.s_addr = inet_addr(BROADCAST_ADDR);
	return sendto(con, data, length, 0, (struct sockaddr*)&bfrom, sizeof(bfrom));
}

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

int start(uint16_t port)
{

#ifdef _WIN32
	long rc;
	rc = startWinsock();

	if (rc != 0)
		return 1;
#endif

	m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (m_socket != -1)
	{
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = INADDR_ANY;
		local.sin_port = htons(port);

		getnameinfo((struct sockaddr *)&local, sizeof(local), Server.nbname, sizeof(Server.nbname), NULL, 0, 0);
		retval = bind(m_socket, (struct sockaddr *)&local, sizeof(local));

		if (retval != -1)
			WDS_Recv(m_socket);
		else
		{
			sprintf(logbuffer, "[E] bind(): Cant bind on Socket (UDP) %d!\n", port);
			logger(logbuffer);
		}
	}
	else
	{
		sprintf(logbuffer, "[E] socket(): Cant create Socket (UDP) %d!\n", port);
		logger(logbuffer);
	}

	return errno;
}

void WDS_Recv(int con)
{
	while (1)
	{
		fromlen = sizeof(from);
		retval = recvfrom(con, buff, sizeof(buff), 0, (struct sockaddr *) &from, &fromlen);

		if (retval > 0)
			GetPacketType(con, buff, retval);
		else
		{
			sprintf(logbuffer, "[E] socket(): Cant create Socket (UDP) %d!\n", config.port);
			logger(logbuffer);
			break;
		}
	}
}

int WDS_Send(int con, char* data, size_t length)
{
	retval = sendto(con, data, length, 0, (struct sockaddr *) &from, sizeof(from));
	return retval;
}

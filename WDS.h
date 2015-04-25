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
#ifdef _WIN32
#pragma once
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <inttypes.h>
#include <WinBase.h>

#ifndef DS
#define DS			"\\" 
#endif
#else

#define SOCKET_ERROR		-1
#define WSAGetLastError()	errno
#define WSACleanup()		cleanup
#define INVALID_SOCKET		-1
#define closesocket			close
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/wait.h>
#include <dirent.h>
#ifndef DS
#define DS			"/" 
#endif
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>

#ifndef WDS_H_
#define WDS_H_

struct sockaddr_in local, from;
int retval, m_socket;
socklen_t fromlen;
char ServerOSName[64];

#ifdef _WIN32
#define MSG_DONTWAIT		0
#endif

#include "WDS_Socket.h"
#include "WDS_Request.h"
#include "WDS_FileIO.h"
#include "WDS_RIS.h"

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN		1234
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN		4321
#endif

#ifndef __BYTE_ORDER
#if defined(_BIG_ENDIAN)
#define __BYTE_ORDER __BIG_ENDIAN
#elif defined(_LITTLE_ENDIAN)
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define SWAB32(x) x
#define SWAB16(x) x
#elif __BYTE_ORDER == __BIG_ENDIAN
#define SWAB32(x) (((uint32_t)(x) >> 24) | \
	(((uint32_t)(x) >> 8) & 0xff00) | \
	(((uint32_t)(x) << 8) & 0xff0000) | \
	((uint32_t)(x) << 24))
#define SWAB16(x) (((uint16_t)(x) >> 8) | (((uint16_t)(x) & 0xff) << 8))
#else
#define SWAB32(x) x
#define SWAB16(x) x
#endif

struct server_config
{
	uint16_t	port;
	char		server_root[256];
	int			NeedsApproval;
	int			PollIntervall;
	int			TFTPRetryCount;
	int			VersionQuery;
	int			AllowUnknownClients;
	int			DefaultAction;
} config;

struct Client_Info
{
	unsigned char hw_address[6];
	unsigned char ClientGuid[17];
	unsigned char IPAddress[4];
	int	ActionDone;
	int	Action;
	int Version;

} Client;

struct Server_Info
{
	char	dnsdomain[255];
	char	nbname[64];
	char	service[64];
	int		RequestID;
} Server;

uint32_t IP2Bytes(const char* IP_address);
uint32_t RESPtype;
size_t RESPsize;
char RESPData[4096], logbuffer[1024];
unsigned char eop;
void handle_args(int data_len, char* Data[]);

void logger(char* text);
void Set_Type(uint32_t NewType);
void Set_Size(size_t Newsize);
void Set_EoP(unsigned char neweop);
void Set_PKTLength();
void print_values(int data_len, char* Data[]);

#ifdef _WIN32
int startWinsock(void);
#endif

char* replace_str(const char* str, const char* old, const char* new);
size_t ascii_to_utf16le(const char* src, char* dest, size_t offset);

#ifdef _WIN32
static __inline void skipspaces(FILE *fd);
#else
static inline void skipspaces(FILE *fd);
#endif

#ifdef _WIN32
static __inline void eol(FILE *fd);
#else
static inline void eol(FILE *fd);
#endif

int Handle_VendorInfo(char* VenString, int VenStrLen);
const char* hostname_to_ip(const char* hostname);
unsigned char get_string(FILE *fd, char* dest, size_t size);
void print_wdsnbp_options(unsigned char* wds_options);
uint32_t IP2Bytes(const char* IP_address);


#define LOOKING_FOR_POLICY		"Server is looking for Policy..."
#define FILE_NOT_FOUND			"The required file for this client was not found on the server..."
#define CLIENT_IS_BANNED		"This Client is not allowed to connect"
#define CLIENT_ACCEPTED			"OK..."
#define REQUEST_ABORTED			"Request was aborted..."


#endif /* WDS_H_ */

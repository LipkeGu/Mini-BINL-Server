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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>

#ifdef _WIN32
#pragma once
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <inttypes.h>
#include <WinBase.h>
#include <process.h>

#define MSG_DONTWAIT		0
#ifndef DS
#define DS			"\\" 
#endif

int startWinsock(void);
static __inline void skipspaces(FILE *fd);
static __inline void eol(FILE *fd);

#else
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/wait.h>
#include <dirent.h>

#define SOCKET_ERROR		-1
#define WSAGetLastError()	errno
#define WSACleanup()		cleanup
#define INVALID_SOCKET		-1
#define closesocket			close

#ifndef DS
#define DS			"/" 
#endif

static inline void skipspaces(FILE *fd);
static inline void eol(FILE *fd);
#endif

#ifndef WDS_H_
#define WDS_H_

#include "WDS_Socket.h"
#include "WDS_Request.h"
#include "WDS_FileIO.h"
#include "WDS_RIS.h"

// #define	ALLOWALLARCHES		1

#ifndef WDS_DEFUALT_DOMAIN
#define WDS_DEFUALT_DOMAIN		"localdomain.local" 
#endif

#ifndef WDS_SETTINGS_FILE
#define WDS_SETTINGS_FILE		"Settings.txt" 
#endif

#ifndef WDS_CLIENTS_FILE
#define WDS_CLIENTS_FILE		"Clients.txt" 
#endif

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
	uint16_t	BOOTPPort;
	uint16_t	TFTPPort;

	uint32_t	ServerIP;
	uint32_t	SubnetMask;
	
	char		server_root[255];

	int			NeedsApproval;
	int			PollIntervall;
	int			TFTPRetryCount;
	int			VersionQuery;
	int			AllowUnknownClients;
	int			DefaultAction;
	int			ShowClientRequests;
	int			DefaultMode;
	int			PXEClientPrompt;
} config;

struct Client_Info
{
	unsigned char hw_address[6];
	unsigned char ClientGuid[17];
	unsigned char IPAddress[4];

	char Bootfile[128];
	char BCDPath[64];

	int ClientArch;
	int	ActionDone;
	int	Action;
	int Version;
	int WDSMode;
	int Handled;

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
uint32_t IP2Bytes(const char* IP_address);

size_t RESPsize;
size_t ascii_to_utf16le(const char* src, char* dest, size_t offset);

char RESPData[4096], logbuffer[1024];
char* replace_str(const char* str, const char* old, const char* new);
const char* hostname_to_ip(const char* hostname);

unsigned char eop;
unsigned char get_string(FILE *fd, char* dest, size_t size);

int Handle_VendorInfo(char* VenString, int VenStrLen);
int isValidDHCPType(int type);
int setDHCPRespType(int found);
struct sockaddr_in from;
socklen_t fromlen;

void handle_args(int data_len, char* Data[]);
void logger(char* text);
void Set_Type(uint32_t NewType);
void Set_Size(size_t Newsize);
void Set_EoP(unsigned char neweop);
void Set_PKTLength();
void print_values(int data_len, char* Data[]);
void print_wdsnbp_options(unsigned char* wds_options);
void ZeroOut(void* Buffer, size_t length);

#define WDS_MSG_LOOKING_FOR_POLICY		"Server is looking for client policy..."
#define WDS_MSG_FILE_NOT_FOUND			"A requested file for this client was not found on the server..."
#define WDS_MSG_CLIENT_IS_BANNED		"This Client is not allowed to connect"
#define WDS_MSG_CLIENT_ACCEPTED			"Client accepted..."
#define WDS_MSG_REQUEST_ABORTED			"Request aborted..."
#define WDS_MSG_REFERRAL				"An more suitable Server will handle this request."

#define WDS_MODE_RIS			0
#define WDS_MODE_WDS			1
#define WDS_MODE_UNK			2

#endif /* WDS_H_ */



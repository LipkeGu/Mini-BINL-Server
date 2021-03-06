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

#ifndef _WIN32 
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/wait.h>
#include <dirent.h>

static inline void skipspaces(FILE *fd);
static inline void eol(FILE *fd);

#define SOCKET_ERROR		-1
#define WSAGetLastError() 	errno()
#define WSACleanup	 		cleanup()
#define INVALID_SOCKET		-1
#define closesocket()		close()
#else
#include <inttypes.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

static __inline void skipspaces(FILE *fd);
static __inline void eol(FILE *fd);
#define in_addr_t unsigned long
#endif

#ifndef WDS_H_
#define WDS_H_

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)  
#define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)

#define HAVEFORKSUPPORT
#define WDS_MSG_LOOKING_FOR_POLICY				"Server is looking for Policies..."

#define WDS_MODE_RIS							0
#define WDS_MODE_WDS							1
#define WDS_MODE_UNK							2

#ifndef DS
#define DS									"/"
#endif

#include "WDS_Socket.h"
#include "WDS_Request.h"
#include "WDS_FileIO.h"
#include "WDS_NTLM.h"
#include "WDS_RIS.h"

// #define	ALLOWALLARCHES					1

#ifndef SETTINGS_DEFAULT_WDSCONFIG
#define SETTINGS_DEFAULT_ALLOWUNKCLIENTS		0
#define SETTINGS_DEFAULT_POLLINTERVALL			4		
#define SETTINGS_DEFAULT_RETRYCOUNT			65535
#define SETTINGS_DEFAULT_SHOWREQS				1
#define SETTINGS_DEFAULT_DHCPMODE				1
#define SETTINGS_DEFAULT_VERSIONQUERY			0
#define SETTINGS_DEFAULT_CLIENTPROMPT			WDSBP_OPTVAL_PXE_PROMPT_OPTOUT
#define SETTINGS_DEFAULT_WDSMODE				WDS_MODE_WDS

#define SETTINGS_DEFAULT_WDSCONFIG				1
#endif

#ifndef WDS_SERVER_ROOT
#define WDS_SERVER_ROOT						"#mnt#reminst"
#endif

#ifndef WDS_DEFUALT_DOMAIN
#define WDS_DEFUALT_DOMAIN						"localdomain.local"
#endif

#ifndef BROADCAST_ADDR
#define BROADCAST_ADDR						"255.255.255.255"
#endif

#ifndef VENDORIDENT
#define VENDORIDENT							"PXEClient"
#endif

#ifndef WDS_SETTINGS_FILE
#define WDS_SETTINGS_FILE						"Settings.txt"
#endif

#ifndef WDS_CLIENTS_FILE
#define WDS_CLIENTS_FILE						"Clients.txt"
#endif

#define DHCP_BUFFER_SIZE						1460

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN						1234
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN							4321
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
	uint32_t ServerIP;
	uint32_t ReferalIP;
	uint32_t RouterIP;

	char server_root[255];
	char OSCBasePath[128];
	char Password[32];
	int NeedsApproval;
	uint16_t PollIntervall;
	uint16_t TFTPRetryCount;
	
	uint8_t NTLMV2Enabled;
	uint8_t VersionQuery;
	uint8_t AllowServerSelection;
	int DropUnkownClients;
	int AllowUnknownClients;
	uint8_t DefaultAction;
	int ShowClientRequests;
	int DefaultMode;
	uint8_t PXEClientPrompt;
	int DHCPReqDetection;

} Config;

struct wdsparams
{
	uint8_t VersionQuery;
	uint8_t ActionDone;
	uint8_t NextAction;
	uint8_t PXEPromptDone;
	uint8_t PXEClientPrompt;
	uint8_t AllowServerSelection;

	uint16_t Architecture;
	uint16_t RetryCount;
	uint16_t PollIntervall;
	uint16_t nbpversion;

	uint32_t ServerVersion;
	uint32_t RequestID;
	uint32_t ReferalIP;


} wdsnbp;

struct Client_Info
{
	char Bootfile[128];
	char BCDPath[64];
	char HostName[64];

	uint8_t hw_address[6];
	uint8_t IPAddress[4];
	
	uint16_t ClientArch;
	
	int Version;
	int WDSMode;
	int Handled;
	int lastDHCPType;
	int isWDSRequest;
	int PXEPrompt;
} Client;

struct Server_Info
{
	char dnsdomain[255];
	char nbname[64];
	char service[64];
	char UserName[64];
	char nbdomain[64];
	char dnshostname[320];

	uint32_t RequestID;
} Server;


char RESPData[4096], logbuffer[1024];
char* replace_str(const char* str, const char* old, const char* newchar);

const char* hostname_to_ip(const char* hostname);

uint8_t eop;
uint8_t get_string(FILE *fd, char* dest, size_t size);
uint8_t setDHCPRespType();

int isValidDHCPType(int type);
int isZeroIP(const char* IP);
int FindVendorOpt(const char* Buffer, size_t buflen, size_t offset);

uint32_t IP2Bytes(const char* IP_address);
uint32_t RESPtype;

size_t RESPsize;
size_t ascii_to_utf16le(const char* src, char* dest, size_t offset);

void handle_args(int data_len, char* Data[]);
void logger(char* text);
void Set_Type(uint32_t NewType);
void Set_Size(size_t Newsize);
void Set_EoP(uint8_t neweop);
void Set_PKTLength();

#endif /* WDS_H_ */

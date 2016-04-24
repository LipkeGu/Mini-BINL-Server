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

#include "WDS.h"

#ifndef WDS_SOCKET_H_
#define WDS_SOCKET_H_
#define WDS_LISTEN_PORT         4011

#define SYSARCH_INTEL_X86		0
#define SYSARCH_NEC_PC98		1
#define SYSARCH_INTEL_IA64		2
#define SYSARCH_DEC_ALPHA		3
#define SYSARCH_ARC_x86         4
#define SYSARCH_INTEL_LEAN		5
#define SYSARCH_INTEL_X64		6
#define SYSARCH_INTEL_EFI		7


#define WDS_MIN_PACKETSIZE     240
#define PXE_MIN_PACKETSIZE     304

int socketlen;

struct sockaddr_in from;
struct sockaddr_in bfrom;

int listening(const char* Context, int con, int mode);
#ifndef _WIN32
void DHCP_Thread();
void BOOTP_Thread();
#else
DWORD WINAPI DHCP_Thread();
DWORD WINAPI BOOTP_Thread();
#endif

int CreateSocketandBind(int port, int SocketType, int AddressFamiliy, int Protocol);

int bootp_start();
int Send(int con, char* buf, size_t len, int mode);

#endif /* WDS_SOCKET_H_ */

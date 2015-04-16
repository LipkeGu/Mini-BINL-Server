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

#ifndef WDS_PACKET_H_
#define WDS_PACKET_H_
#define DHCP_MINIMAL_PACKET_SIZE	290

#define BOOTP_REPLY					2
#define BOOTP_REQUEST				1
#define DHCP_RESP_ACK				5
#define	DHCP_RESP_OFF				2

#define WDSNBP_RPCPORT				5040
#define WDSNBP_UNDIVER				2010

#define BOOTP_OFFSET_HWTYPE			1
#define BOOTP_OFFSET_MACLEN			2
#define BOOTP_OFFSET_HOPS			3
#define	BOOTP_OFFSET_TRANSID		4
#define BOOTP_OFFSET_SECONDS		8
#define	BOOTP_OFFSET_ADDRPADD		10	
#define BOOTP_OFFSET_YOURIP			12
#define BOOTP_OFFSET_CLIENTIP		16
#define	BOOTP_OFFSET_RELAYIP		24
#define BOOTP_OFFSET_MACADDR		28
#define BOOTP_OFFSET_MACPADDING		34

#define BOOTP_OFFSET_COOKIE			236
#define BOOTP_OFFSET_VENOPTION		243
#define BOOTP_OFFSET_GUID			257
#define BOOTP_OFFSET_WDSNBP			277
#define BOOTP_OFFSET_OPTIONS		279		/* WDSNBP */
#define BOOTP_OFFSET_SYSARCH		289		/* WDSNBP */

char Bootfile[128];
char BootStore[64];

int GetPacketType(int con, char* Data, size_t Datalen);
int Handle_NBP_Request(int con, char* Data, size_t Packetlen, int arch, int found);
int GetClientinfo(int Device, int arch, unsigned char* hwadr, unsigned char* guid, unsigned char* wds_options);

#endif

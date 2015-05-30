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

#define DHCP_MAGIC_COOKIE                   (0x63825363)
#define DHCP_MINIMAL_PACKET_SIZE			240

#define BOOTP_REQUEST						1
#define BOOTP_REPLY							2

#define DHCPDISCOVER						1
#define DHCPOFFER							2
#define DHCPREQUEST							3
#define DHCPDECLINE							4
#define DHCPACK								5
#define DHCPNAK								6
#define DHCPRELEASE							7
#define DHCPINFORM							8

#define WDSNBP_OPTION						250
#define IPV4_ADDR_LENGTH                    4

#define WDSBP_OPT_ARCHITECTURE              1
#define WDSBP_OPT_NEXT_ACTION               2
#define WDSBP_OPT_POLL_INTERVAL             3
#define WDSBP_OPT_POLL_RETRY_COUNT          4
#define WDSBP_OPT_REQUEST_ID                5
#define WDSBP_OPT_MESSAGE                   6
#define WDSBP_OPT_VERSION_QUERY             7
#define WDSBP_OPT_SERVER_VERSION            8
#define WDSBP_OPT_REFERRAL_SERVER           9
#define WDSBP_OPT_PXE_CLIENT_PROMPT         11
#define WDSBP_OPT_PXE_PROMPT_DONE           12
#define WDSBP_OPT_NBP_VER                   13
#define WDSBP_OPT_ACTION_DONE               14
#define WDSBP_OPT_ALLOW_SERVER_SELECTION    15
#define WDSBP_OPT_SERVER_FEATURES           16
#define WDSBP_OPT_END						255

//
// Bootfiles
//

#define DHCP_BOOTFILE			"wdsnbp.0"
#define WDS_BOOTFILE_X86		"\\Boot\\x86\\pxeboot.n12"
#define WDS_BOOTFILE_X64		"\\Boot\\x64\\pxeboot.n12"
#define WDS_BOOTFILE_EFI		"\\Boot\\EFI\\bootmgfw.efi"
#define RIS_BOOTFILE_DEFAULT	"\\Boot\\winxp\\startrom.n12"
#define WDS_BOOTFILE_UNKNOWN	"\\pxelinux.0"

#define WDS_BOOTSTORE_X86		"\\Boot\\x86\\default.bcd"
#define WDS_BOOTSTORE_X64		"\\Boot\\x64\\default.bcd"
#define WDS_BOOTSTORE_EFI		"\\Boot\\EFI\\default.bcd"
#define WDS_BOOTSTORE_DEFAULT	"\\Boot\\BCD"

#define WDS_ABORT_BOOTFILE_X86	"\\Boot\\x86\\abortpxe.com"
#define WDS_ABORT_BOOTFILE_X64	"\\Boot\\x64\\abortpxe.com"
#define WDS_ABORT_BOOTFILE_EFI	"\\Boot\\EFI\\abortpxe.efi"

//
// Values for WDSBP_OPT_NEXT_ACTION Option.
//

#define WDSBP_OPTVAL_ACTION_APPROVAL		1
#define WDSBP_OPTVAL_ACTION_REFERRAL		3
#define WDSBP_OPTVAL_ACTION_ABORT			5

//
// Values for WDSBP_OPT_PXE_CLIENT_PROMPT and WDSBP_OPT_PXE_PROMPT_DONE.
//

#define WDSBP_OPTVAL_PXE_PROMPT_OPTIN		1
#define WDSBP_OPTVAL_PXE_PROMPT_NOPROMPT	2
#define WDSBP_OPTVAL_PXE_PROMPT_OPTOUT		3

//
// Values for WDSBP_OPT_NBP_VER.
//

#define WDSBP_OPTVAL_NBP_VER_7			0x0700
#define WDSBP_OPTVAL_NBP_VER_8			0x0800

#define BOOTP_OFFSET_BOOTPTYPE			0
#define BOOTP_OFFSET_HWTYPE             1
#define BOOTP_OFFSET_MACLEN             2
#define BOOTP_OFFSET_HOPS               3
#define BOOTP_OFFSET_TRANSID			4
#define BOOTP_OFFSET_SECONDS			8
#define BOOTP_OFFSET_BOOTPFLAGS			10
#define BOOTP_OFFSET_YOURIP             12
#define BOOTP_OFFSET_CLIENTIP			16
#define BOOTP_OFFSET_NEXTSERVER			20
#define BOOTP_OFFSET_RELAYIP			24
#define BOOTP_OFFSET_MACADDR			28
#define BOOTP_OFFSET_MACPADDING			34

#define BOOTP_OFFSET_COOKIE             236
#define BOOTP_OFFSET_MSGTYPE            242
#define BOOTP_OFFSET_VENOPTION			245
#define BOOTP_OFFSET_GUID               254
#define BOOTP_OFFSET_CARCH              273
#define BOOTP_OFFSET_WDSNBP             277
#define BOOTP_OFFSET_OPTIONS			279		/* WDSNBP */
#define BOOTP_OFFSET_SYSARCH			289		/* WDSNBP */

#define BOOTP_FLAG_BROADCAST            128
#define BOOTP_FLAG_UNICAST              0

//
// Values for NCQ (Driver Query).
//

int GetPacketType(int con, char* Data, size_t Datalen);
int Handle_DHCP_Request(int con, char* Data, int found, saddr* socket, int mode);
int GetClientinfo(int arch, unsigned char* hwadr, int found);
#endif

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
#ifndef RIS
#define RIS                             1
#define NIC_DRIVER_LIST_FILE			"Nics.txt"

#define RIS_DRIVER_BUSTYPE_PCI			"5"
#define RIS_DRIVER_CHARACTERISTICS		"132"
#define RIS_DRIVER_OFFSET_VENID			24
#define RIS_DRIVER_OFFSET_DEVID			26

#define NCR_OK                          0x00000000	/* OK */
#define NCR_KO                          0xc000000d	/* NOT FOUND! */

#define PKT_NCR							0x52434e82	/* Network Card Reply */

#define PKT_NCQ							0x51434e81	/* Network Card Query */
#define PKT_RQU							0x55515281	/* OSChooser File Request */
#define PKT_NEG							0x47454e81	/* NTLM Negotiate */
#define PKT_AUT							0x54554181	/* NTLM Authenticate */
#define PKT_OFF							0x46464f81	/* NTLM Reboot to new PXE ROM */
#define PKT_REQ							0x51455281	/* Unknown */

#define OSCHOOSER_TITLE				"Client Installation Wizard"
#define OSCHOOSER_WELCOME			"Welcome to the Client Installation Wizard,<BR>To Install a Operating System Press [Enter]<BR><BR>To abort and restart the Computer press [F3]"
#define OSCHOOSER_NOTFOUND			"The requested file \"%s\" worse not found on the Server."


#define NTLMSSP_VER				0x0f
#define NTVER_MAJOR				0x05
#define NTVER_MINOR				0x02

typedef struct _DRIVER
{
	uint16_t vid, pid;
	char driver[256];
	char service[256];
} DRIVER;

int Handle_NCQ_Request(int con, char* Data, uint8_t mode, size_t Packetlen);
int Handle_OSC_Request(int con, char* Data, uint8_t mode, size_t Packetlen);
int Handle_OFF_Request(int con, char* Data, uint8_t mode, size_t Packetlen);
int Handle_REQ_Request(int con, char* Data, uint8_t mode, size_t Packetlen);

int Handle_NTLMSSP_Request(int con, char* Data, uint8_t mode, size_t Packetlen);
int find_drv(uint16_t cvid, uint16_t cpid, DRIVER *drv);

#ifndef _WIN32
static inline void eol(FILE *fd);
#else
static __inline void eol(FILE *fd);
#endif
#endif

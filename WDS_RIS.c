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

#ifndef _WIN32
static inline void skipspaces(FILE *fd)
#else
static __inline void skipspaces(FILE *fd)
#endif
{
	unsigned char c = 0;

	while (!feof(fd) && !isspace(c))
		if (fread(&c, 1, sizeof(c), fd) != sizeof(c))
			break;
}

#ifndef _WIN32
static inline void eol(FILE *fd)
#else
static __inline void eol(FILE *fd)
#endif
{
	unsigned char c = 0;

	while (!feof(fd) && (c != '\n') && (c != '\r'))
		if (fread(&c, 1, sizeof(c), fd) != sizeof(c))
			break;
}

int Handle_OSC_Request(int con, char* Data, uint8_t mode, size_t Packetlen)
{
#define PKT_RSU			0x55535282
#define OSCFileOffset	36
	sprintf(logbuffer, "======= RIS (OSChooser) =======\n");
	logger(logbuffer);

	size_t NameLength = (Packetlen - OSCFileOffset) - 1;
	char OSCFile[256] = "";
	char OSCName[10] = "";
	char OSCContent[2048] = "";
	time_t t;

	Set_Type(PKT_RSU);
	Set_Size(4);

	memcpy(&RESPData[RESPsize], &Data[0x8], 28);
	Set_Size(28);

	if (NameLength == 0) /*  welcome.osc is requested! */
	{
		sprintf(OSCContent, "<OSCML> \
		<META KEY=\"F3\" ACTION=\"REBOOT\"><META KEY=\"ENTER\" HREF=\"LOGIN\"><TITLE>%s</TITLE><FOOTER>[F3] restart computer [ENTER] Continue</FOOTER> \
		<BODY left=5 right=75><BR>%s</BODY></OSCML>", OSCHOOSER_TITLE, OSCHOOSER_WELCOME);

		printf("[D]FILE: WELCOME.osc\n");
	}
	else
	{
		memcpy(OSCName, &Data[36], NameLength);
		sprintf(OSCFile, "%s%s%s.osc", Config.server_root, Config.OSCBasePath, OSCName);

		printf("FILE: %s.osc\n", OSCName);

		if (Exist(OSCFile) != 0)
		{
			sprintf(OSCContent, "<OSCML> \
			<META KEY=\"F3\" ACTION=\"REBOOT\"><META KEY=\"ENTER\" HREF=\"LOGIN\"><TITLE>%s</TITLE><FOOTER>[F3] restart computer [ENTER] Continue</FOOTER> \
			<BODY left=5 right=75><BR>%s</BODY></OSCML>", OSCHOOSER_TITLE, OSCHOOSER_NOTFOUND);

			sprintf(logbuffer, "ERROR: File not found: %s\n", OSCFile);
			logger(logbuffer);
		}
		else
			Read(OSCFile, OSCContent, sizeof OSCContent);
	}

	t = time(NULL);

	if (strlen(OSCContent) >= 21)
	{
		sprintf(OSCContent, "%s", replace_str(OSCContent, "%ServerUTCFileTime%", (char *)(int)&t));
		sprintf(OSCContent, "%s", replace_str(OSCContent, "%SERVERNAME%", Server.nbname));
		sprintf(OSCContent, "%s", replace_str(OSCContent, "%SERVERDOMAIN%", Server.nbdomain));
		sprintf(OSCContent, "%s%d", replace_str(OSCContent, "%MACHINENAME%", Client.HostName), Server.RequestID);
	}

	memcpy(&RESPData[RESPsize], OSCContent, strlen(OSCContent));
	Set_Size(strlen(OSCContent));

	Set_EoP(0x00);
	Set_PKTLength();

	Send(con, RESPData, RESPsize, mode);

	sprintf(logbuffer, "===============================\n");
	logger(logbuffer);

	return 0;
}

int Handle_NTLMSSP_Request(int con, char* Data, uint8_t mode, size_t Packetlen)
{
#define PKT_CHA		0x4c484382
#define PKT_RES		0x53455282


	char Response[1024] = "";
	char Signature[8] = NTLMSSP_MESSAGE_HEADER;

	uint32_t Offset = 0;
	uint32_t Header = 0;
	uint32_t result = 0;
	uint32_t Indicator = 0;
	uint32_t ServerFlags = 0x00018206; /* ntlm v1 */
	uint32_t TargetNameBuffer = 0x00000030;
	uint32_t TargetInfoBuffer = 0x00000030;

	/* TODO: REWRITE algoritm for this crap */
	uint8_t challenge[8];
	size_t length = 0;

	generate_challenge(challenge, inet_ntoa(from.sin_addr));

	char Reserved[8];
	memset(Reserved, 0, sizeof(Reserved));

	char auth_u1[8] = { NTVER_MAJOR, NTVER_MINOR, 0xCE, 0x0E, 0x00, 0x00, 0x00, NTLMSSP_VER };

	unsigned char output[24] = "";

	nt_response(output, Config.Password, challenge);

	int MessageType = 0, retval = 0, auth_result = 1;
	memcpy(&MessageType, &Data[16], 1);

	sprintf(logbuffer, "======= RIS (NTLMSSP) =======\n");
	logger(logbuffer);

	switch (MessageType)
	{
	case NTLMSSP_NEGOTIATE:
		sprintf(logbuffer, "TYPE: NEG (%d)\n", MessageType);
		logger(logbuffer);

		Header = SWAB32(PKT_CHA);
		Indicator = 2;

		char Payload[256] = "";
		size_t payloadoffset = 0;

		/* Netbios DomainName */
		uint16_t TypeDomainName = 0x0200;
		length = ascii_to_utf16le(Server.nbdomain, Payload, (payloadoffset + 8));

		memcpy(&Payload[payloadoffset], &TypeDomainName, sizeof(TypeDomainName));
		payloadoffset += 2;

		memcpy(&Payload[payloadoffset], &length, sizeof(length));
		payloadoffset += 3;

		/* Server Name */
		uint16_t TypeServerName = 0x0100;
		length = ascii_to_utf16le(Server.nbname, Payload, (payloadoffset + 4));

		memcpy(&Payload[payloadoffset], &TypeServerName, sizeof(TypeServerName));
		payloadoffset += 2;

		memcpy(&Payload[payloadoffset], &length, sizeof(length));
		payloadoffset += 3;

		/* DNS Domain Name */
		uint16_t TypeDNSDomain = 0x0300;
		length = ascii_to_utf16le(Server.dnsdomain, Payload, (payloadoffset + 4));

		memcpy(&Payload[payloadoffset], &TypeDNSDomain, sizeof(TypeDNSDomain));
		payloadoffset += 2;

		memcpy(&Payload[payloadoffset], &length, sizeof(length));
		payloadoffset += 3;

		/* DNS Host Name */
		uint16_t TypeDNSHostName = 0x0400;
		length = ascii_to_utf16le(Server.dnshostname, Payload, (payloadoffset + 4));

		memcpy(&Payload[payloadoffset], &TypeDNSHostName, sizeof(TypeDNSHostName));
		payloadoffset += 2;

		memcpy(&Payload[payloadoffset], &length, sizeof(length));
		payloadoffset += 3;

		uint32_t Terminator = 0;
		memcpy(&Payload[payloadoffset], &Terminator, sizeof(Terminator));
		payloadoffset += 2;

		memcpy(&Response[Offset], &Header, sizeof(Header));
		Offset += (sizeof(Header) + 4);

		memcpy(&Response[Offset], Signature, sizeof(Signature));
		Offset += sizeof(Signature);

		memcpy(&Response[Offset], &Indicator, sizeof(Indicator));
		Offset += sizeof(Indicator) + 2;

		uint16_t len = ((uint16_t)strlen(Server.nbdomain) * 2);
		memcpy(&Response[Offset], &len, sizeof(len));
		Offset += sizeof(len);

		memcpy(&Response[Offset], &len, sizeof(len));
		Offset += sizeof(len);

		memcpy(&Response[Offset], &TargetNameBuffer, sizeof(TargetNameBuffer));
		Offset += sizeof(TargetNameBuffer);

		memcpy(&Response[Offset], &ServerFlags, sizeof(ServerFlags));
		Offset += sizeof(ServerFlags);

		// Challenge
		memcpy(&Response[Offset], challenge, sizeof(challenge));
		Offset += sizeof(challenge);

		// Reserved
		memcpy(&Response[Offset], Reserved, sizeof(Reserved));
		Offset += sizeof(Reserved);

		// Targetinfo Buffer
		memcpy(&Response[Offset], &TargetInfoBuffer, sizeof(TargetInfoBuffer));
		Offset += sizeof(TargetInfoBuffer);

		ascii_to_utf16le(Server.nbdomain, Response, Offset);
		Offset += (strlen(Server.nbdomain) * 2);

		memcpy(&Response[Offset], Payload, payloadoffset);
		Offset += payloadoffset;

		memcpy(&Response[4], &Offset, sizeof(Offset));

		break;
	case NTLMSSP_AUTH:
		sprintf(logbuffer, "TYPE: Authenticate (%d)\n", MessageType);
		logger(logbuffer);

		if (Data[36] != 0)
		{
			printf("[D]: Client provides Domain info.\n");

			if (Data[52] <= Data[54])
				auth_result = memcmp(&Data[Data[9]], Server.nbdomain, Data[36]);
			else
				auth_result = 1;
		}

		if (Data[52] != 0)
		{
			printf("[D]: Client provides User info.\n");

			if (Data[36] <= Data[38])
				auth_result = memcmp(&Data[Data[4]], Server.UserName, Data[Data[24]]);
			else
				auth_result = 1;
		}
		
		if (auth_result == 0)
			result = STATUS_SUCCESS;
		else
			result = STATUS_LOGON_FAILURE;

		Header = SWAB32(PKT_RES);
		Offset = 0;

		memcpy(&Response[Offset], &Header, sizeof(Header));
		Offset += sizeof(Header) + 1;

		memcpy(&Response[Offset], &result, sizeof(result));
		Offset += sizeof(result);

		break;
	default:
		return 0;
		break;
	}

	retval = Send(con, Response, Offset, mode);

	sprintf(logbuffer, "===============================\n");
	logger(logbuffer);

	return retval;
}

int Handle_OFF_Request(int con, char* Data, uint8_t mode, size_t Packetlen)
{
	return 1;
}

int Handle_REQ_Request(int con, char* Data, uint8_t mode, size_t Packetlen)
{
	return 1;
}

int Handle_UNR_Request(int con, char* Data, uint8_t mode, size_t Packetlen)
{
	return 1;
}

int Handle_NCQ_Request(int con, char* Data, uint8_t mode, size_t Packetlen)
{
	int Retval = 1;

	if (Packetlen > 0)
	{
		DRIVER drv;
		uint16_t vid = 0, pid = 0;
		size_t offset = 0;

		char packet[500] = "";
		const char ris_params[] =
			"Description"		"2" "RIS NIC Card"
			"Characteristics"	"1" RIS_DRIVER_CHARACTERISTICS
			"BusType"			"1" RIS_DRIVER_BUSTYPE_PCI;

		uint32_t type = SWAB32(PKT_NCR), value = 0, res = 0;
		size_t ulen = 0;

		memcpy(&vid, &Data[RIS_DRIVER_OFFSET_VENID], sizeof(vid));
		memcpy(&pid, &Data[RIS_DRIVER_OFFSET_DEVID], sizeof(pid));

		sprintf(logbuffer, "%s", "============= Driver Query =============\n");
		logger(logbuffer);

		if (find_drv(SWAB16(vid), SWAB16(pid), &drv) == 1)
		{
			memcpy(packet, &type, sizeof(type));
			offset += sizeof(type);

			res = SWAB32(NCR_OK);
			offset += 0x4; /* Packet len will be filled later */

			memcpy(&packet[offset], &res, sizeof(res));
			offset += sizeof(res);

			value = SWAB32(0x2); /* Type */
			memcpy(&packet[offset], &value, sizeof(value));
			offset += sizeof(value);

			value = SWAB32(0x24); /* Base offset */
			memcpy(&packet[offset], &value, sizeof(value));
			offset += sizeof(value);

			offset += 0x8; /* Driver / Service name offset */

			value = SWAB32(sizeof(ris_params)); /* Parameters */
			memcpy(&packet[offset], &value, sizeof(value));
			offset += sizeof(value);

			offset += 0x4; /* Parameters list offset */
			sprintf(logbuffer, "Driver: %s\n", drv.driver);
			logger(logbuffer);

			sprintf(logbuffer, "Service: %s\n", drv.service);
			logger(logbuffer);

			sprintf(Data, "PCI\\VEN_%04X&DEV_%04X", drv.vid, drv.pid);

			sprintf(logbuffer, "PCI-ID: PCI\\VEN_%X&DEV_%X\n", drv.vid, drv.pid);
			logger(logbuffer);

			ulen = ascii_to_utf16le(Data, packet, offset);
			offset += ulen + 2; /* PCI\VEN_XXXX&DEV_YYYY */

			/* We can fill Driver name offset */
			value = SWAB32(offset);
			memcpy(&packet[0x14], &value, sizeof(value));

			ulen = ascii_to_utf16le(drv.driver, packet, offset);
			offset += ulen + 2; /* Driver name */

			/* We can fill Service name offset */
			value = SWAB32(offset);
			memcpy(&packet[0x18], &value, sizeof(value));

			ulen = ascii_to_utf16le(drv.service, packet, offset);
			offset += ulen + 2; /* Service name */

			/* We can fill Parameters list offset */
			value = SWAB32(offset);
			memcpy(&packet[0x20], &value, sizeof(value));

			/* And now params */
			memcpy(&packet[offset], ris_params, sizeof(ris_params));
			offset += sizeof(ris_params) + 2;

			/* Packet Length */
			value = SWAB32(offset);
			memcpy(&packet[0x4], &value, sizeof(value));
		}
		else /* Send NCR_KO packet when driver was not found... */
		{
			res = SWAB32(NCR_KO);
			value = SWAB32(offset);

			memcpy(&packet[offset], &value, sizeof(value));
			offset += sizeof(offset);

			memcpy(&packet[offset], &res, sizeof(res));
			offset += sizeof(res);

			sprintf(logbuffer, "[E]: Driver not found (PCI\\VEN_%X&DEV_%X)\n",
				SWAB16(vid), SWAB16(pid));
			logger(logbuffer);
		}

		sprintf(logbuffer, "%s", "========================================\n");
		logger(logbuffer);

		Retval = Send(con, packet, offset, 0);
	}

	if (Retval > 1)
		Retval = 0;

	return Retval;
}

int find_drv(uint16_t cvid, uint16_t cpid, DRIVER *drv)
{
	int found = 0;

	if (Exist(NIC_DRIVER_LIST_FILE) == 0)
	{
		uint16_t vid = 0, pid = 0;
		char buffer[1024];

		FILE *fd = fopen(NIC_DRIVER_LIST_FILE, "r");

		if (fd == NULL)
			return found;
		else
			while (found == 0)
			{
				if (fread(buffer, 1, sizeof(uint32_t), fd) != sizeof(uint32_t))
					break;

				buffer[sizeof(uint32_t)] = 0;

				sscanf(buffer, "%hu2", &vid);
				skipspaces(fd);

				if (cvid == vid)
				{
					if (fread(buffer, 1, sizeof(uint32_t), fd) != sizeof(uint32_t))
						break;

					buffer[sizeof(uint32_t)] = 0;
					sscanf(buffer, "%hu2", &pid);

					skipspaces(fd);

					if (cpid == pid)
					{
						if (!isspace(get_string(fd, drv->driver, sizeof(drv->driver))))
							skipspaces(fd);

						if (!isspace(get_string(fd, drv->service, sizeof(drv->service))))
							eol(fd);

						if ((cvid == vid) && (cpid == pid))
						{
							drv->vid = vid;
							drv->pid = pid;

							found = 1;
							break;
						}
						else
							continue;
					}
					else
						continue;
				}
				else
					continue;
			}

		fclose(fd);
	}
	else
	{
		sprintf(logbuffer, "[E] File not Found: %s\n", NIC_DRIVER_LIST_FILE);
		logger(logbuffer);
	}

	return found;
}
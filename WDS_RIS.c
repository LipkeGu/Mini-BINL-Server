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

int Handle_NCQ_Request(int con, char* Data, size_t Packetlen)
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
		uint32_t vid, pid;
		char buffer[1024];

		FILE *fd = fopen(NIC_DRIVER_LIST_FILE, "r");

		if (fd == NULL)
			return found;
		else
			while (found == 0)
			{
				if (fread(buffer, 1, 4, fd) != 4)
					break;

				buffer[4] = 0;
				sscanf(buffer, "%x2", &vid);
				skipspaces(fd);

				if (cvid == vid)
				{
					if (fread(buffer, 1, 4, fd) != 4)
						break;

					buffer[4] = 0;
					sscanf(buffer, "%x2", &pid);

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
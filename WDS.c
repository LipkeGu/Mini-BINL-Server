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

void Set_Type(uint32_t NewType)
{
	RESPsize = 0;
	RESPtype = NewType;

	memcpy(&RESPData[0], &RESPtype, sizeof(NewType));
	Set_Size(sizeof(NewType));
}

void Set_Size(size_t Newsize)
{
	RESPsize += Newsize;
}

void Set_EoP(uint8_t neweop)
{
	eop = neweop;
}

void Set_PKTLength()
{
	uint32_t _tmp = SWAB32(RESPsize);
	memcpy(&RESPData[4], &_tmp, sizeof(uint32_t));
}

void logger(char* text)
{
#ifndef _WIN32
#if DEBUGMODE == 0
	openlog("WDSServer", LOG_CONS | LOG_PID, LOG_USER);
	syslog(LOG_INFO, "%s", text);

	closelog();
#else
	printf("%s", text);
#endif
#else
	printf("%s", text);
#endif
}

void handle_args(int data_len, char* Data[])
{
	if (data_len > 1)
		for (int i = 0; i < data_len; i++)
		{
			if (memcmp(Data[i], "-rootdir", 8) == 0) /* root Directory */
				sprintf(Config.server_root, "%s", replace_str(Data[(i + 1)], "#", DS));

			if (memcmp(Data[i], "-bserv", 6) == 0) /* Referal Server */
				Config.ReferalIP = IP2Bytes(Data[(i + 1)]);

			if (memcmp(Data[i], "-router", 7) == 0) /* Gateway */
				Config.RouterIP = IP2Bytes(Data[(i + 1)]);

			if (memcmp(Data[i], "-srvip", 6) == 0) /* THIS Server IP */
				Config.ServerIP = IP2Bytes(Data[(i + 1)]);

			if (memcmp(Data[i], "-nbname", 7) == 0) /* Server Hostname */
				sprintf(Server.nbname, "%s", Data[(i + 1)]);

			if (memcmp(Data[i], "-dnsdom", 7) == 0) /* FQDN Domainname */
				sprintf(Server.dnsdomain, "%s", Data[(i + 1)]);
		}
}

char* replace_str(const char* str, const char* old, const char* newchar)
{
	char* ret, *r;
	const char* p, *q;

	if (newchar == NULL || str == NULL || old == NULL)
		return "\0";

	if (strlen(str) >= 1 && strlen(newchar) >= 1 && strlen(old) >= 1)
	{
		size_t oldlen = strlen(old);
		size_t count = 0, retlen = 0, newlen = strlen(newchar);

		if (oldlen != newlen)
		{
			for (count = 0, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
				count++;

			retlen = p - str + strlen(p) + count * (newlen - oldlen);
		}
		else
			retlen = strlen(str);

		if ((ret = malloc(retlen + 1)) == NULL)
			return NULL;

		for (r = ret, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
		{
			ptrdiff_t l = q - p;

			memcpy(r, p, l);
			r += l;

			memcpy(r, newchar, newlen);
			r += newlen;
		}

		strcpy(r, p);

		return ret;
	}
	else
		return "";
}

size_t ascii_to_utf16le(const char* src, char* dest, size_t offset)
{
	size_t ulen = 0;

	for (size_t i = 0; i < strlen(src); i++)
	{
		dest[offset + ulen] = src[i];
		ulen += 2;
	}

	return ulen;
}

const char* hostname_to_ip(const char* hostname)
{
	return inet_ntoa(**(struct in_addr**)gethostbyname(hostname)->h_addr_list);
}

uint8_t get_string(FILE *fd, char* dest, size_t size)
{
	uint32_t i = 0;
	uint8_t c = 0;

	while (i < size)
	{
		if (fread(&c, 1, sizeof(c), fd) != sizeof(c))
			break;

		if (isspace(c))
			break;

		dest[i++] = c;
	}

	dest[i] = 0;

	return c;
}

uint32_t IP2Bytes(const char* IP_address)
{
	struct in_addr ipvalue;
	inet_pton(AF_INET, IP_address, &ipvalue);

	return ipvalue.s_addr;
}

uint8_t setDHCPRespType()
{
	uint8_t Retval = DHCPOFFER;
		
	if (Client.lastDHCPType == DHCPDISCOVER)
		Retval = DHCPOFFER;
	else
		if (Client.lastDHCPType == DHCPREQUEST)
			Retval = DHCPACK;
		else
			Retval = DHCPOFFER;

	return Retval;
}

int isZeroIP(const char* IP)
{
	uint32_t ZeroIP = 0;
	
	return memcmp(IP, &ZeroIP, sizeof(uint32_t));
}

int FindVendorOpt(const char* Buffer, size_t buflen, size_t offset)
{
	for (size_t i = offset; i < buflen; i = i + strlen(VENDORIDENT))
		if (i < buflen && offset < buflen)
			if (memcmp(VENDORIDENT, &Buffer[i], strlen(VENDORIDENT)) == 0)
				return 0;

	return 1;
}

int isValidDHCPType(int type)
{
	int result = 1;

	switch (type)
	{
	case DHCPDISCOVER:
		result = 0;
		Client.lastDHCPType = DHCPDISCOVER;
		break;
	case DHCPOFFER:
		result = 1;
		Client.lastDHCPType = DHCPOFFER;
		break;
	case DHCPREQUEST:
		result = 0;
		Client.lastDHCPType = DHCPREQUEST;
		break;
	case DHCPDECLINE:
		result = 1;
		Client.lastDHCPType = DHCPDECLINE;
		break;
	case DHCPACK:
		result = 1;
		Client.lastDHCPType = DHCPACK;
		break;
	case DHCPNAK:
		result = 1;
		Client.lastDHCPType = DHCPNAK;
		break;
	case DHCPRELEASE:
		result = 1;
		Client.lastDHCPType = DHCPRELEASE;
		break;
	case DHCPINFORM:
		result = 1;
		Client.lastDHCPType = DHCPINFORM;
		break;
	default:
		result = 1;
		Client.lastDHCPType = DHCPDISCOVER;
		break;
	}

	return result;
}


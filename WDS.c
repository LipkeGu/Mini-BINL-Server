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

void ZeroOut(void* Buffer, size_t length)
{
	bzero(Buffer, length);
}

void Set_Size(size_t Newsize)
{
	RESPsize += Newsize;
}

void Set_EoP(unsigned char neweop)
{
	eop = neweop;
}

void Set_PKTLength()
{
	uint32_t _tmp = SWAB32(RESPsize);
	memcpy(&RESPData[4], &_tmp, 4);
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

void print_values(int data_len, char* Data[])
{
	int i = 0;

	if (data_len > 1)
		for (i = 0; i < data_len; i++)
			printf("[D] Value %d: %s\n", i, Data[i]);
}

void handle_args(int data_len, char* Data[])
{
	int i = 0;

	if (data_len > 1)
		for (i = 0; i < data_len; i++)
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
	size_t ulen = 0, i = 0, len = strlen(src);

	for (i = 0; i < len; i++)
	{
		dest[offset + ulen] = src[i];
		ulen += 2;
	}

	return ulen;
}

const char* hostname_to_ip(const char* hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;

	int i = 0;

	he = gethostbyname(hostname);
	addr_list = (struct in_addr **) he->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++)
		return inet_ntoa(*addr_list[i]);

	return NULL;
}

unsigned char get_string(FILE *fd, char* dest, size_t size)
{
	unsigned int i = 0;
	unsigned char c = 0;

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

int setDHCPRespType(int found, int mode)
{
#ifndef _WIN32	/* avoid the GCC Unused Warning */
	mode = mode;
	found = found;
#endif

	int Retval = DHCPOFFER;
		
	if (Client.lastDHCPType == DHCPDISCOVER)
		Retval = DHCPOFFER;
	else
		if (Client.lastDHCPType == DHCPREQUEST)
			Retval = DHCPACK;
		else
			Retval = DHCPOFFER;

	return Retval;
}

int isZeroIP(char* IP)
{
	char ZeroIP[IPV4_ADDR_LENGTH] = { 0x00, 0x00, 0x00, 0x00 };
	
	if (memcmp(IP, ZeroIP , IPV4_ADDR_LENGTH) == 0)
		return 0;
	else
		return 1;
}

int FindVendorOpt(const char* Buffer, size_t buflen, size_t offset)
{
	size_t i = offset;

	for (i; i < buflen; i = i + strlen(VENDORIDENT))
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


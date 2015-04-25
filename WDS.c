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
	time_t now = time(0);
	char* fn_log = NULL;

#ifdef _WIN32
	printf(text);
#else
	openlog("WDSServer", LOG_CONS | LOG_PID, LOG_USER);
	syslog(LOG_INFO, "%s", text);

	closelog();
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
			if (memcmp(Data[i], "-datadir", 9) == 0) /* root Directory */
				sprintf(config.server_root, "%s", Data[(i + 1)]);

			if (memcmp(Data[i], "-AUC", 4) == 0) /* Allow Unknown Clients */
				sprintf(config.AllowUnknownClients, "%d", atoi(Data[(i + 1)]));
		}
}

char* replace_str(const char* str, const char* old, const char* new)
{
	char* ret, *r;
	const char* p, *q;

	if (new == NULL || str == NULL || old == NULL)
		return "\0";

	if (strlen(str) >= 1 && strlen(new) >= 1 && strlen(old) >= 1)
	{
		size_t oldlen = strlen(old);
		size_t count = 0, retlen = 0, newlen = strlen(new);

		if (oldlen != newlen)
		{
			for (count = 0, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
				count++;

			/* this is undefined if p - str > PTRDIFF_MAX */
			retlen = p - str + strlen(p) + count * (newlen - oldlen);
		}
		else
			retlen = strlen(str);

		if ((ret = malloc(retlen + 1)) == NULL)
			return NULL;

		for (r = ret, p = str; (q = strstr(p, old)) != NULL; p = q + oldlen)
		{
			/* this is undefined if q - p > PTRDIFF_MAX */
			ptrdiff_t l = q - p;
			memcpy(r, p, l);
			r += l;
			memcpy(r, new, newlen);
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
	char* dump = NULL;

	he = gethostbyname(hostname);
	addr_list = (struct in_addr **) he->h_addr_list;

	for (i = 0; addr_list[i] != NULL; i++)
		return inet_ntoa(*addr_list[i]);

	return dump;	// silence the OSX Compiler.... ;(
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

size_t CopyBootPOption(char* dest, char* src, size_t offset)
{
	if (offset != NULL)
	{
		memcpy(dest, &src[offset], 1);
		memcpy(dest, &src[(offset + 1)], src[(offset + 1)]);
		memcpy(dest, &src[offset + 2], src[(offset + 2)]);

		printf("%d copied to destination...\n", src[(offset + 1)]);
		return src[(offset + 1)];
	}
	else
		return 0;
}

int IsApprovalDone()
{
	int Done = 0;
	
	if (config.AllowUnknownClients == 0)
	{
		Done = GetClientRule(Client.hw_address, Client.ClientGuid);
		Client.ActionDone = Done;
		
		if (Done == 1)
			Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;
		else
			Client.Action = WDSBP_OPTVAL_ACTION_ABORT;
		
		return Done;
	}
	else
	{
		Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;
		Client.ActionDone = 1;

		return 1;
	}
		
}


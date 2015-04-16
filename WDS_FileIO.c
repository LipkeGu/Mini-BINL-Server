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

int Exist(const char* Filename)
{
	FILE *fil = fopen(Filename, "r");

	if (fil != NULL)
	{
		fclose(fil);
		return 0;
	}
	else
		return -1;
}

int Write(const char* Filename, const char* Data, size_t Length)
{
	int res = 1;

	if (Length > 0)
	{
		FILE *fil = fopen(Filename, "w");

		if (fil != NULL)
		if (fwrite(Data, sizeof(char), Length, fil) == 0)
			res = errno;
		else
		{
			sprintf(logbuffer, "[S] Error while writing the File: %s (%d) ", Filename, errno);
			logger(logbuffer);
		}

		if (fil != NULL)
			fclose(fil);
	}

	return errno;
}

int Read(const char* Filename, char* content, size_t Length)
{
	int res = 1;
	FILE *fil = fopen(Filename, "r");

	if ((fil != NULL) && (fread(content, 1, Length, fil) == 0))
	{
		fclose(fil);
		res = 0;
	}

	return res;
}

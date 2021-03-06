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

#ifndef WDS_FILESYSTEM_H_
#define WDS_FILESYSTEM_H_

int Exist(const char* Filename);
int Write(const char* Filename, const char* Data, size_t Length);
int Read(const char* Filename, char* dest, size_t Length);

uint8_t GetClientRule(const uint8_t* hwadr);

#endif /* WDS_FILESYSTEM_H_ */

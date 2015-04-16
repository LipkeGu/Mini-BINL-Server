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

#define WDS_LISTEN_PORT		4011

#ifndef WDS_SOCKET_H_
#define WDS_SOCKET_H_

char buff[1024];
void WDS_Recv(int con);
int start(uint16_t port);
int WDS_Send(int con, char* buf, size_t len);
int startWinsock(void);

#endif /* WDS_SOCKET_H_ */

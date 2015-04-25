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

int main(int argc, char* argv[])
{
	Server.RequestID = 7;
	config.AllowUnknownClients = 0;
	config.VersionQuery = 0;
	config.PollIntervall = 6;
	config.TFTPRetryCount = 3;
	config.port = WDS_LISTEN_PORT;
	sprintf(Server.dnsdomain, "%s", "localdomain.local");
	GetServerSettings();
	
	
	Client.ActionDone = 0;
	Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;

	if (config.AllowUnknownClients == 1)
		config.NeedsApproval = 0;
	else
		config.NeedsApproval = 1;

#ifdef _WIN32
	sprintf(config.server_root, "%s", replace_str("D:#reminst", "#", DS));
#else
	sprintf(config.server_root, "%s", replace_str("#mnt#reminst", "#", DS));
#endif
	handle_args(argc, argv);
	start(config.port);

	return 0;
}

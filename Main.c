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
	Config.ReferalIP = 0;
	Config.RouterIP = 0;
	Config.NTLMV2Enabled = 0;
	Config.DHCPReqDetection = SETTINGS_DEFAULT_DHCPMODE;
	Config.ShowClientRequests = 1;

	Client.WDSMode = 1;
	sprintf(Client.HostName, "%s", "Client");

	sprintf(Server.UserName, "%s", "root");
	sprintf(Server.nbdomain, "%s", "LOCALDOMAIN");
	sprintf(Server.dnsdomain, "%s", WDS_DEFUALT_DOMAIN);

	wdsnbp.ActionDone = 0;
	wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_APPROVAL;
	wdsnbp.PollIntervall = htons(5);
	wdsnbp.RetryCount = htons(65535);
	wdsnbp.RequestID = htonl(1);
	wdsnbp.PXEClientPrompt = SETTINGS_DEFAULT_CLIENTPROMPT;
	wdsnbp.PXEPromptDone = 0;

	sprintf(Config.Password, "%s", "secret");
	sprintf(Config.server_root, "%s", replace_str(WDS_SERVER_ROOT, "#", DS));
	sprintf(Config.OSCBasePath, "%s", replace_str("#OSChooser#english#", "#", DS));

	handle_args(argc, argv);
#ifndef _WIN32
	pid_t mainpid = fork();

	if (mainpid == 0)
	{
		setsid();
		bootp_start();
	}
	else
		exit(0);
#else
	bootp_start();
#endif

	return 0;
}

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
	Config.BOOTPPort = 4011;
	Config.DHCPPort = 67;
	
	Config.ReferalIP = (unsigned long)0;
	Config.RouterIP = (unsigned long)0;

	sprintf(Server.dnsdomain, "%s", WDS_DEFUALT_DOMAIN);

	wdsnbp.ActionDone = 0;
	wdsnbp.NextAction = WDSBP_OPTVAL_ACTION_APPROVAL;

	if (GetServerSettings() == 1)
	{
		
	}

	wdsnbp.PollIntervall = Config.PollIntervall;
	wdsnbp.RetryCount = Config.TFTPRetryCount;
	wdsnbp.RequestID = Server.RequestID;
	wdsnbp.PXEClientPrompt = Config.PXEClientPrompt;
	wdsnbp.PXEPromptDone = Config.PXEClientPrompt;
	wdsnbp.VersionQuery = Config.VersionQuery;

	Config.DHCPReqDetection = SETTINGS_DEFAULT_DHCPMODE;
	
	if (Config.AllowUnknownClients == 1)
		Config.NeedsApproval = 0;
	else
		Config.NeedsApproval = 1;

	sprintf(Config.server_root, "%s", replace_str(WDS_SERVER_ROOT, "#", DS));

	handle_args(argc, argv);

#ifndef _WIN32
	pid_t mainpid = fork();
#if DEBUGMODE == 1
	bootp_start();
#else

	if (mainpid == 0)
	{
		setsid();
		bootp_start();
	}
	else
		exit(0);
#endif
#else
	bootp_start();
#endif
	return 0;
}

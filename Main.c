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

int main(int argc, char* argv[])
{
    Config.BOOTPPort = 4011;
    Config.DHCPPort = 67;

    Config.DefaultAction = WDSBP_OPTVAL_ACTION_ABORT;
    sprintf(Server.dnsdomain, "%s", WDS_DEFUALT_DOMAIN);
    Config.PXEClientPrompt = WDSBP_OPTVAL_PXE_PROMPT_OPTOUT;

    if (GetServerSettings() == 1)
    {
        Server.RequestID = 7;
        
        Config.AllowUnknownClients = 0;
        Config.DefaultMode = WDS_MODE_WDS;
        Config.VersionQuery = 0;
        Config.PollIntervall = 2;
        Config.TFTPRetryCount = 5;
        Config.ShowClientRequests = 1;
        Config.DHCPReqDetection = 1;
        Config.ShowClientRequests = 1;
    }
    
    Client.ActionDone = 0;
    Client.Action = WDSBP_OPTVAL_ACTION_APPROVAL;
    Client.inDHCPMode = 1;

    if (Config.AllowUnknownClients == 1)
	Config.NeedsApproval = 0;
    else
	Config.NeedsApproval = 1;

    sprintf(Config.server_root, "%s", replace_str("#mnt#reminst", "#", DS));

    handle_args(argc, argv);

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

return 0;
}

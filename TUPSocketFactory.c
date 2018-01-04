/* TUPm Uptime Client	   : Update uptime into TUP database (http://www.uptimeprj.com)
 * TUPm(Monitoring) Client : Monitor services thru TUP (http://www.uptimeprj.com)
 * GPL/Free4Use 2007-21/12/2012 Sebastien TUGS (uptimeprj@nextworlds.com)
 *
 * TUP Linux Monitoring Engine : This Client includes a Monitoring Engine
 *
 * TUP Linux Client & TUPm Client are released on GPL licence :
 * --------------------------------------------
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * TUP Linux Client use a version of minIni :
 * --------------------------------------------
 * Under Apache Licence. See minIni.c to read licence informations
 * minIni.h is compiled with INI_READONLY option (no write to conf file)
 *
 * $Author: lecariboumasque@gmail.com $ . $LastChangedDate: 2011-04-25 12:45:39 +0200 (Mon, 25 Apr 2011) $
 * $Revision: 7 $ .
 * $Id: TUPSocketFactory.c 7 2011-04-25 10:45:39Z lecariboumasque@gmail.com $
 *
 */

/*! \file */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>


int initSocket (int *sock, struct sockaddr_in *sockname, struct hostent *host_address, int iServerPort, char *srv_hostname)
{

	int iSyncnt = 1;
	int iSyncnt_sz = sizeof(iSyncnt);

	if ((host_address = gethostbyname (srv_hostname)) == NULL)
	{
		printf("[Socket Error] FATAL : Unable to resolve hostname . Check your DNS/Host file or edit TUP.conf \n");
		return 0;
	}


	if ((*sock = socket (PF_INET, SOCK_STREAM, 0)) == -1)
	{
		printf("[Socket Error] FATAL : Unable to create client socket. Network problem... \n");
		return 0;
	}


	sockname->sin_family = host_address ->h_addrtype;
	sockname->sin_port = htons (iServerPort);
	memcpy ((char *) &(sockname->sin_addr.s_addr), host_address->h_addr, host_address->h_length);

	// reduce tcp timeout by reducing syn retries
	setsockopt(*sock,IPPROTO_TCP,7,&iSyncnt,iSyncnt_sz);

	if ((connect (*sock, (struct sockaddr *) sockname, sizeof (struct sockaddr_in))) == -1)
	{
		printf("[Socket Error] Connection problem . Perhaps Network down or bad proxy. \n\n");
		return 0;
	}

	return 1;
}

int closeSocket(int sock) {
	shutdown(sock,2);
	close(sock);
	return 1;
}



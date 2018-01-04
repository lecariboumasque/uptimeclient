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
 * $Author: lecariboumasque@gmail.com $ . $LastChangedDate: 2012-09-26 17:47:01 +0200 (Wed, 26 Sep 2012) $
 * $Revision: 23 $ .
 * $Id: TUPMonitor.h 23 2012-09-26 15:47:01Z lecariboumasque@gmail.com $
 *
 */

/*! \file */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "minIni.h"

#define BUF_PATH_2 512				

struct tupmon {
	char tupmon_name[100];
	char tupmon_type[10];
	char tupmon_filename[512];
	char tupmon_parameters[512];
	char tupmon_service_desc[512];
	char tupmon_group[100];
	int tupmon_order;
	int tupmon_isactive;
	int tupmon_stoponerror;
};

int tupmon_cmp (const void *t1, const void *t2);

const char *TUPgetExt (const char *fspec);

struct tupmon *TUPLoadMonitor(char sExecPath[PATH_SIZE_IF],int *iMonCount,int iSetDebug, int iSetNoLog, int iSetNoDaemon, char sGlobalLogPath[PATH_SIZE_IF]);



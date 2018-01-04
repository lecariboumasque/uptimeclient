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
 * $Author: lecariboumasque@gmail.com $ . $LastChangedDate: 2011-12-28 19:47:50 +0100 (Wed, 28 Dec 2011) $
 * $Revision: 15 $ .
 * $Id: TUPConvergence.h 15 2011-12-28 18:47:50Z lecariboumasque@gmail.com $
 *
 */

/*! \file */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define PATH_SIZE_IF 256				// Path string size including filename

struct tuptimer {
	char tuptimer_name[64];
	int tuptimer_origvalue;
	int tuptimer_value;
};

char *TUPcGetDateTime();

char *TUPBuildToken();

int TUPcWritePid(char *sFFilename, int iPid);

int TUPcWriteALineOfLog(char sLogPath[150], char *sLine);

int TUPcWriteToFile(char *sFFilename, char *sLineWrite);

int tuptimer_cmp (const void *t1, const void *t2);

char **TUPcReadFile(char *sFFilename, int *iArrSize, int iSetDebug);

char *str_replace (const char *txt, const char *Avant, const char *Apres);

int TUPPathParseAndFind(char *pth, const char *exe);

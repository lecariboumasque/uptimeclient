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
 * $Id: TUPMonitor.c 23 2012-09-26 15:47:01Z lecariboumasque@gmail.com $
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

#include "TUPConvergence.h"
#include "TUPMonitor.h"
#include "minIni.h"



const char *TUPgetExt (const char *fspec) {
    char *e = strrchr (fspec, '.');
    if (e == NULL)
        e = "";
    return e;
}

int tupmon_cmp (const void *t1, const void *t2) {

	const struct tupmon *z1 = t1;
	const struct tupmon *z2 = t2;

	if(strcmp( z1->tupmon_group, z2->tupmon_group) == 0) {
		
		if( z1->tupmon_order > z2->tupmon_order ) {

			return 1;
		
		} else {

			return -1;
		} // end order
	} else {
		if(strcmp( z1->tupmon_group, z2->tupmon_group) > 0) {

			return 1;			
			
		} else {

			return -1;

		} // end group > 0
	} // end tupmon = 0
} 

struct tupmon *TUPLoadMonitor(char sExecPath[BUF_PATH_2],int *iMonCount,int iSetDebug, int iSetNoLog, int iSetNoDaemon, char sGlobalLogPath[BUF_PATH_2])
{

	struct tupmon *tupmoncollection;
	DIR *dirp;
	struct dirent *dp;
	int iTermon = 0;
	char sMonConfFileFullPath[1024];
	char sMonDirFullPath[1024];
	char arrBufSection[32];
	char arrTemporaryBuffer[512];
	char sTempLogLine[100];				// A log line buffer

	int iValidMandatory = 0;
	int iIsMonFilenameR;

	sprintf(sMonDirFullPath,"%s/mon",sExecPath);
	tupmoncollection = malloc((128+1)*sizeof(struct tupmon));

	if ((dirp = opendir(sMonDirFullPath)) == NULL) {
		printf("couldn't open '%s'",sMonDirFullPath);
		return NULL;
	}



  do {
	errno = 0;
	iValidMandatory = 0;
	if ((dp = readdir(dirp)) != NULL) {

		if (strcmp(TUPgetExt(dp->d_name),".conf") == 0) {

			// ----------------- Parsing conf file
			sprintf(sMonConfFileFullPath,"%s/%s",sMonDirFullPath,dp->d_name);
			
			if ( ini_getsection(0, arrBufSection, sizeof arrBufSection, sMonConfFileFullPath) == 0)  {

				printf("[Monitor Error] %s . Not able to read monitor configuration or error in conf file\n",dp->d_name);

			} else {


				if( ini_getl("TMON_DEF", "tmon_isactive" , 0 , sMonConfFileFullPath) ) {

					if( ini_gets("TMON_DEF", "tmon_name", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sMonConfFileFullPath) > 0 ) {
						sprintf(tupmoncollection[iTermon].tupmon_name,"%s",arrTemporaryBuffer);

					} else {
						if( iSetDebug) printf("[Monitor Error] %s - Name error.\n",dp->d_name);
						iValidMandatory++;
					}

					if( ini_gets("TMON_DEF", "tmon_type", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sMonConfFileFullPath) > 0 ) {
						sprintf(tupmoncollection[iTermon].tupmon_type,"%s",arrTemporaryBuffer);

					} else {
						if( iSetDebug) printf("[Monitor Error] %s - Type error.\n",dp->d_name);
						iValidMandatory++;
					}

					if( ini_gets("TMON_DEF", "tmon_filename", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sMonConfFileFullPath) > 0 ) {
						sprintf(tupmoncollection[iTermon].tupmon_filename,"%s",arrTemporaryBuffer);

					} else {
						if( iSetDebug) printf("[Monitor Error] %s - Command (tmon_filename) error.\n",dp->d_name);
						iValidMandatory++;
					} 

					iIsMonFilenameR = access( tupmoncollection[iTermon].tupmon_filename , R_OK );
					
					if( iIsMonFilenameR ) {
						if( !iSetNoLog ) { 
							sprintf(sTempLogLine,"(monitor) Error in %s - No able to access filename (%s)",tupmoncollection[iTermon].tupmon_name,tupmoncollection[iTermon].tupmon_filename); 
							TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); 
						}
						
						if( iSetNoDaemon ) {
							printf("\n[Monitor Error] Error in %s - Not able to access filename (%s)",tupmoncollection[iTermon].tupmon_name,tupmoncollection[iTermon].tupmon_filename);
						}

						if( iSetDebug) printf("\n[Monitor Error] Skeleton %s read access error.\n",tupmoncollection[iTermon].tupmon_filename);
						iValidMandatory++;
					}


					if( ini_gets("TMON_DEF", "tmon_parameters", "dummy" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sMonConfFileFullPath) > 0 ) {
						sprintf(tupmoncollection[iTermon].tupmon_parameters,"%s",arrTemporaryBuffer);
						
					} else {
						if( iSetDebug) printf("[Monitor Error] %s - Parameters error.\n",dp->d_name);
						iValidMandatory++;
					}


					if( ini_gets("TMON_DEF", "tmon_service_desc", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sMonConfFileFullPath) > 0 ) {
						sprintf(tupmoncollection[iTermon].tupmon_service_desc,"%s",arrTemporaryBuffer);

					} else {
						if( iSetDebug) printf("[Monitor Error] %s - Service description error.\n",dp->d_name);
						iValidMandatory++;
					} 


					if( ini_gets("TMON_DEF", "tmon_group", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sMonConfFileFullPath) > 0 ) {
						sprintf(tupmoncollection[iTermon].tupmon_group,"%s",arrTemporaryBuffer);

					} else {
						if( iSetDebug) printf("[Monitor Error] %s - Group error.\n",dp->d_name);
						iValidMandatory++;
					} 

					tupmoncollection[iTermon].tupmon_isactive = ini_getl("TMON_DEF", "tmon_isactive" , 1 , sMonConfFileFullPath);
					tupmoncollection[iTermon].tupmon_order = ini_getl("TMON_DEF", "tmon_order" , 1 , sMonConfFileFullPath);
					tupmoncollection[iTermon].tupmon_stoponerror = ini_getl("TMON_DEF", "tmon_stoponerror" , 0 , sMonConfFileFullPath);

					if( iValidMandatory > 0) {

						if( iSetDebug) printf("[Monitor Error] Bad format for %s configuration file : %i error(s) detected.\n",dp->d_name,iValidMandatory);

					} else {	

						iTermon++;

					}
				}
			
				
			} // end get section


		} // end strcmp


      } // end readdir

   } while (dp != NULL); // end do

   free(dp);
  (void) closedir(dirp);

   *iMonCount = iTermon;
  return tupmoncollection;
}



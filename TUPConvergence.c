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
 * $Id: TUPConvergence.c 15 2011-12-28 18:47:50Z lecariboumasque@gmail.com $
 *
 */

/*! \file */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "TUPConvergence.h"
#include "sha2_4_tup.h"		// sha functions (256/384/512)

char *TUPBuildToken()
{
    SHA256_CTX ctx256;				       // Context for SHA-256 encoding (used for password)
    static char cTempToken[68];

    char sTempGetTime[20];
    sprintf(sTempGetTime,"%s",TUPcGetDateTime());
   
    SHA256_Init(&ctx256);
    SHA256_Update(&ctx256, (unsigned char*)sTempGetTime, strlen(sTempGetTime));
    SHA256_End(&ctx256, cTempToken);

    return cTempToken;
}

char *TUPcGetDateTime()
{
    static char outstr[20];
    time_t t;
    struct tm *tmp;
    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
   	return "Z";
    } else {
	    if (strftime(outstr, sizeof(outstr), "%F %T", tmp) == 0) {
		return "Z";
	    } else {
		return outstr;
	    }
     }
} 

int TUPcWritePid(char *sFFilename, int iPid)
{
	FILE *file;
	
	if ( (file = fopen (sFFilename, "w+")) == NULL) {/* a+ create or write to an existing file */
		return 0;
	} else {
		fprintf(file,"%i\n",iPid ); /* wr */
		fclose(file); 
		return 1;
	}
	
}

int TUPcWriteALineOfLog(char sLogPath[150], char *sLine) 
{

	FILE *fileLog;

	if ( (fileLog = fopen (sLogPath, "a+")) == NULL) {/* a+ create or write to an existing file */
		printf("[Error] No able to write log file to ...%s\n",sLogPath);
		return 0;
	} else {


		char sDateTime[30];
		size_t iSz;
		time_t now = time(NULL);
		struct tm tim = (*localtime(&now));
		iSz = strftime(sDateTime,30,"%b %d, %Y; %H:%M:%S",&tim);


		fprintf(fileLog,"[%s] - %s\n",sDateTime,sLine);
		fclose(fileLog);
	return 1; 
	}

}

int TUPcWriteToFile(char *sFFilename, char *sLineWrite)
{
	FILE *file;
	
	if ( (file = fopen (sFFilename, "a+")) == NULL) {/* a+ create or write to an existing file */
		return 0;
	} else {
		fprintf(file,"%s\n",sLineWrite ); /* wr */
		fclose(file); 
		return 1;
	}
	
}

int tuptimer_cmp (const void *t1, const void *t2) {

	const struct tuptimer *z1 = t1;
	const struct tuptimer *z2 = t2;

	if(z1->tuptimer_value > z2->tuptimer_value) {

		return 1;			
			
	} else {

		return -1;

	} 

} 


char **TUPcReadFile(char *sFFilename, int *iArrSize, int iSetDebug) {

	FILE *file;
	static char buf[512];
	static char **cStrRet;

	int iTerReq = 0;

	cStrRet = (char**)malloc(128*sizeof(char*));

	if ( (file = fopen (sFFilename, "r")) != NULL)
    	{
		while ( fgets (buf, sizeof (buf), file) ) {
			
			cStrRet[iTerReq] = malloc((512+1)*sizeof(char));
			strcpy(cStrRet[iTerReq],buf);
			iTerReq++;
			
		}
		*iArrSize = iTerReq++;
		fclose(file);
		return cStrRet;
    	} else {
		if( iSetDebug ) {
			printf ("\n-----> Error opening file: %s (%s)\n", strerror (errno),sFFilename);
	}
		*iArrSize = 0;
		return cStrRet;
    	}
	


}



char *str_replace (const char *txt, const char *Avant, const char *Apres)
{
	const char *pos;      /* Position d'une occurance de Avant dans txt */
	char *TxtRetour;      /* La chaine retournée */
	size_t PosTxtRetour;  /* Position du prochain caractère à écrire */
	/* dans TxtRetour */
	size_t Long;          /* Long d'une chaine à écrire dans TxtRetour */
	size_t TailleAllouee; /* Taille allouée à TxtRetour */
	
	/* Cherche la première occurence */
	pos = strstr (txt, Avant);
	
	/* Aucune occurrences : renvoie simplement une copie de la chaine */
	if (pos == NULL)
	{
		return NULL;
	}
	
	/* Alloue une nouvelle chaine */
	Long = (size_t)pos - (size_t)txt;
	TailleAllouee = Long + strlen (Apres) + 1;
	TxtRetour = malloc (TailleAllouee);
	PosTxtRetour = 0;
	
	/* Copie la première partie de la chaîne sans occurrence */
	strncpy (TxtRetour + PosTxtRetour, txt, Long);
	PosTxtRetour += Long;
	txt = pos + strlen (Avant);
	
	/* Ajoute la chaîne de remplacement Apres */
	Long = strlen (Apres);
	strncpy (TxtRetour + PosTxtRetour, Apres, Long);
	PosTxtRetour += Long;
	
	/* Cherche la prochaine occurrence */
	pos = strstr (txt, Avant);
	while (pos != NULL)
	{
		/* Agrandit la chaine */
		Long = (size_t)pos - (size_t)txt;
		TailleAllouee += Long + strlen (Apres);
		TxtRetour = (char *)realloc (TxtRetour, TailleAllouee);
		
		/* Copie ce qu'il y a entre la dernier occurrence et la nouvelle */
		strncpy (TxtRetour + PosTxtRetour, txt, Long);
		PosTxtRetour += Long;
		
		/* Passe l'occurrence */
		txt = pos + strlen (Avant);
		
		/* Ajoute la chaîne de remplacement */
		Long = strlen (Apres);
		strncpy (TxtRetour + PosTxtRetour, Apres, Long);
		PosTxtRetour += Long;
		
		/* Cherche la prochaine occurrence */
		pos = strstr (txt, Avant);
	}
	
	/* Ajoute le reste de la chaîne (il reste au moins '\0') */
	Long = strlen (txt) + 1;
	TailleAllouee += Long;
	TxtRetour = realloc (TxtRetour, TailleAllouee);
	strncpy (TxtRetour + PosTxtRetour, txt, Long);
	return TxtRetour;
}

int TUPPathParseAndFind(char *pth, const char *exe)
{
     char *searchpath;
     char *beg, *end;
     int stop, found;
     int len;

     if (strchr(exe, '/') != NULL) {
	  if (realpath(exe, pth) == NULL) return 0;
	  if( access( pth, X_OK ) ) {
		return 0;
	  } else {
		return 1;
          }
     }

     searchpath = getenv("PATH");
     if (searchpath == NULL) return 0;
     if (strlen(searchpath) <= 0) return 0;

     beg = searchpath;
     stop = 0; found = 0;
     do {
	  end = strchr(beg, ':');
	  if (end == NULL) {
	       stop = 1;
	       strncpy(pth, beg, PATH_MAX);
	       len = strlen(pth);
	  } else {
	       strncpy(pth, beg, end - beg);
	       pth[end - beg] = '\0';
	       len = end - beg;
	  }
	  if (pth[len - 1] != '/') strncat(pth, "/", 1);
	  strncat(pth, exe, PATH_MAX - len);

	  if( access( pth, X_OK )) {
		found = 0;
	  } else {
		found = 1;
          }
	  
	  if (!stop) beg = end + 1;
     } while (!stop && !found);
	  
     return found;
}



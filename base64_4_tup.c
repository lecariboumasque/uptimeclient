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
 *
 * $Author: lecariboumasque@gmail.com $ . $LastChangedDate: 2011-04-25 12:45:39 +0200 (Mon, 25 Apr 2011) $
 * $Revision: 7 $ .
 * $Id: base64_4_tup.c 7 2011-04-25 10:45:39Z lecariboumasque@gmail.com $
 *
 */
/*
 Fichier base64.c
 Auteur Bernard Chardonneau
 
 Logiciel libre, droits d'utilisation précisés en français
 dans le fichier : licence.fr
 
 Traductions des droits d'utilisation dans les fichiers :
 licence.de , licence.en , licence.es , licence.it
 licence.nl , licence.pt , licence.eo , licence.eo-utf
 
 
 Bibliothèque de fonctions permettant d'encoder et de
 décoder le contenu d'un tableau en base64.
 */


#include "base64_4_tup.h"

/* encode base64 nbcar caractères mémorisés
 dans orig et met le résultat dans dest */

void encode64 (char *orig, char *dest, int nbcar)
{
    octet triplet [3]; // groupe de 3 caractères à convertir en base 64
    int   cartriplet;  // nombre de caractères du triplet récupérés
    octet valcode [4]; // valeur des 4 caractères en base 64
    int   posorig;     // position dans la ligne passée en paramètre
    int   posdest;     // position dans la ligne contenant le résultat
    char  valcar [] =  // tableau d'encodage
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	
	
    // initialisations
    posorig = 0;
    posdest = 0;
	
    // tant que non fin de ligne
    while (posorig < nbcar)
    {
        // initialisation
        cartriplet = 0;
		
        // récupérer un groupe de 3 caractères
        do
        {
            triplet [cartriplet++] = orig [posorig++];
        }
        while (cartriplet < 3 && posorig < nbcar);
		
        // encodage des 4 caractères du résultat
		
        // prise en compte du premier caractère du triplet
        valcode [0] = triplet [0] >> 2;
        valcode [1] = (triplet [0] & 3) << 4;
		
        // si 2ème caractère du triplet présent
        if (cartriplet > 1)
        {
            // le prendre en compte
            valcode [1] = valcode [1] | (triplet [1] >> 4);
            valcode [2] = (triplet [1] & 0x0F) << 2;
        }
        else
            // sinon, on mettra un caractère de padding à la place
            valcode [2] = 64;
		
        // traitement similaire pour le 3ème caractère du triplet
        if (cartriplet == 3)
        {
            valcode [2] = valcode [2] | (triplet [2] >> 6);
            valcode [3] = triplet [2] & 0x3F;
        }
        else
            valcode [3] = 64;
		
        // affichage des données encodées
        dest [posdest++] = valcar [valcode [0]];
        dest [posdest++] = valcar [valcode [1]];
        dest [posdest++] = valcar [valcode [2]];
        dest [posdest++] = valcar [valcode [3]];
    }
	
    // fin de l'encodage
    dest [posdest] = '\0';
}



/* décode le contenu de buffer encodé base64, met le résultat
 dans buffer et retourne le nombre de caractères convertis */

int decode64 (char *buffer)
{
    int  car;      // caractère du fichier
    char valcar [4];   // valeur après conversion des caractères
    int  i;            // compteur
    int  posorig;  // position dans la ligne passée en paramètre
    int  posdest;  // position dans la nouvelle ligne générée
	
	
    // initialisations
    posorig = 0;
    posdest = 0;
	
    // tant que non fin de ligne
    while (buffer [posorig] > ' ' && buffer [posorig] != '=')
    {
        // décoder la valeur de 4 caractères
        for (i = 0; i < 4 && buffer [posorig] != '='; i++)
        {
            // récupérer un caractère dans la ligne
            car = buffer [posorig++];
			
            // décoder ce caractère
            if ('A' <= car && car <= 'Z')
                valcar [i] = car - 'A';
            else if ('a' <= car && car <= 'z')
                valcar [i] = car + 26 - 'a';
            else if ('0' <= car && car <= '9')
                valcar [i] = car + 52 - '0';
            else if (car == '+')
                valcar [i] = 62;
            else if (car == '/')
                valcar [i] = 63;
        }
		
        // recopier les caractères correspondants dans le buffer
        buffer [posdest++] = (valcar [0] << 2) | (valcar [1] >> 4);
		
        // sauf si indicateur de fin de message
        if (i > 2)
        {
            buffer [posdest++] = (valcar [1] << 4) | (valcar [2] >> 2);
			
            if (i > 3)
                buffer [posdest++] = (valcar [2] << 6) | (valcar [3]);
        }
    }
	
    // terminer le buffer
    buffer [posdest] = '\0';
	
    // et retourner le nombre de caractères obtenus
    return (posdest);
}


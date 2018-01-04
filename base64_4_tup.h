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
 * $Id: base64_4_tup.h 7 2011-04-25 10:45:39Z lecariboumasque@gmail.com $
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

#define  octet    unsigned char

/* encode base64 nbcar caractères mémorisés
 dans orig et met le résultat dans dest */

void encode64 (char *orig, char *dest, int nbcar);

int decode64 (char *buffer);

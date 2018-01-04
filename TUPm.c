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
 * TUP Linux Client use sha2 by Aaron D. Gifford
 * --------------------------------------------
 * See sha2_4_tup.c for details about author 
 *
 * $Author: lecariboumasque@gmail.com $ . $LastChangedDate: 2012-09-26 17:47:01 +0200 (Wed, 26 Sep 2012) $
 * $Revision: 23 $ .
 * $Id: TUPm.c 23 2012-09-26 15:47:01Z lecariboumasque@gmail.com $
 *
 */
 
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <getopt.h>
#include <limits.h>
#include <syslog.h>
#include <signal.h> // pour avoir les dents blanches =D (for white teeth)

//#include <valgrind/memcheck.h> // only for deep analysis (memory leak)

// Loading TUP Libraries
#include "TUPConvergence.h"	// global TUP library
#include "TUPMonitor.h"		// monitor functions
#include "TUPSocketFactory.h"	// socket library
#include "md5_4_tup.h"		// md5 function (openssl not used anymore)
#include "base64_4_tup.h"	// base64 function ( -- )
#include "sha2_4_tup.h"		// sha functions (256/384/512)

// Daemon Conf
#define DAEMON_NAME "tupmonitorclient"
#define PID_FILE "tupm.pid"

// Platform compliant :)
#undef GET_UPTIME_BSD
#undef GET_MACADDR_BSD
#undef GET_UPTIME_NUX
#undef GET_MACADDR_NUX
#undef GET_UPTIME_SUN
#undef GET_MACADDR_SUN
#undef GET_CPUCOUNT_NUXLIKE
#undef GET_CPUCOUNT_DARWINLIKE
#undef GET_CPUCOUNT_SUNLIKE

// Platform definition are used to allow client cross compilation
#	if defined(linux) || defined(__linux) || defined(__linux__)
#			define GET_UPTIME_NUX
#			define GET_MACADDR_NUX
#			define GET_CPUCOUNT_NUXLIKE
#			define GET_PATH_NUX
#			include <linux/kernel.h>
#			include <sys/sysinfo.h>
#			include <libgen.h>
#	endif

#	if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__) || defined(__DARWIN__)
#			define GET_UPTIME_BSD
#			define GET_MACADDR_BSD
#			include <net/if_dl.h>
#			include <netinet/in.h>
#			include <sys/types.h>
#			include <sys/sysctl.h>
#			include <libgen.h>
#	endif

#	if defined(__NetBSD__)
#			define DISTRO "netbsd"
#			define GET_CPUCOUNT_NUXLIKE
#			define PORTABLE_STRNICMP
#	endif

#	if defined(__FreeBSD__) 
#			define DISTRO "bsd"
#			define GET_CPUCOUNT_NUXLIKE
#	endif

#	if defined(__OpenBSD__)
#			define DISTRO "openbsd"
#			define GET_CPUCOUNT_NUXLIKE
#	endif

#	if defined(__APPLE__) || defined(__DARWIN__)
#			define DISTRO "macos"
#			include <libgen.h>
#			define GET_CPUCOUNT_DARWINLIKE
#	endif

#	if defined(__sun__) || defined(sun)
#			define GET_MACADDR_SUN
#			define GET_UPTIME_UTMPX
#			define GET_CPUCOUNT_NUXLIKE
#			include <utmpx.h>
#			include <time.h>
#			include <strings.h>
#			include <sys/uio.h>
#			define DISTRO "sun"
#			define PORTABLE_STRNICMP
#	endif

#	ifdef GOESX
#			define DISTRO "esx"
#			define SET_DISTRO_ESX
#	endif

// constantes
#define CLIENT_TYPE "TUPm" 				//-> Update this part if you modify this program
#define CLIENTVERSION_MAJOR "2" 			//   Use a different client type, major, minor and patch
#define CLIENTVERSION_MINOR "4" 
#define CLIENTVERSION_RELEASE "R (Harlock)"
#define CLIENTCODENAME "Harlock"
#define MONITOR_ENGINE_VERSION "0x3"

#define UPDATE_PHP_FILE "/update.php" 			// Target of post requests for uptime tracking
#define MONITOR_PHP_FILE "/monitor.php" 		// Target of post requests for monitors tracking
#define CONF_FILENAME "etc/TUPm.conf"
#define LOG_FILENAME_GLOBAL "TUPm.log" 			// Store log about monitor activity
#define LOG_FILENAME_STATUS "TUPm-status.log" 		// Store status
#define LOG_FILENAME_DEBUGVERBOSE "debug.log" 		// Store debug
#define CONF_FILENAME_REPLAY "/replay/TUPReplay.log" 	// Store request with timestamp for future replay (if network is down)

#define MAX_IFS 64
#define PACKET_SIZE 1024
#define BUF_PATH 512					// Path string size including filename


// Struct for long getopt
static struct option lsswitch[] = {
	{ "debug", no_argument, NULL , 'd' },
	{ "nodaemon", no_argument, NULL , 'n' },
	{ "help", no_argument, NULL , '1' },
	{ "nolog", no_argument, NULL , 'o' },
	{ "stop", no_argument, NULL , 's' },
	{ "status", no_argument, NULL , 't' },
	{ "checkmon", no_argument, NULL , 'm'},
	{ "xtradaemondebug", no_argument, NULL , 'X' },
	{ "version", no_argument, NULL , 'V' },
	{ "encryptpass", 1 ,NULL,'e' },
	{ NULL , 0 , NULL , 0 },
};



// *********************************
// * Pre-Declarations			   *
// *********************************
void TUP_POSTRequest(char *cPrmPostRequest, char* cPrmPhpTargetFile);
void TUP_ReplayRequest(void);
void tupGet_mac(void);
static int MD5MacAddr(void);
void check_distro(void);
void get_uptime(void);
char *get_current_dir_name(void);
int get_cpucount(void);
int TUPMain ();
int TUPPrepare ();

int iTDaemonState = 1;				// Daemon state, used to exit loop when receive signal
int iTExecute = 0;				// boolean used to execute (or not) TUPMain
int iSetNoLog = 0;				// Indicate if no log option is selected
int iSetLogPath = 0;				// Is log path given in arg
int iSetNoDaemon = 0;				// Is daemon mode enable
int iTStatusState = 0;				// Detect a status request
int iSetValidateMonitor = 0;			// Check monitor call
int iSetVerboseLikeAWoman = 0;
int iTAlarm;
int iRetMain;
int iInitAlarm;	

int iUseReplay = 0;				// indicate if network connection is down and have to use replay function
int port = 80; 					// HTTP port
int iSetDebug = 0;				// Debug mode on/off
int iSetPath = 0;				// Is path to TUP.conf given in arg
int iUseProxy = 0;				// Use proxy ?
int iAlreadyEncryptedPassword = 0;			// Password is already encrypted or not ?
int iEncryptPasswordFunc = 0;			// Call password encryption function instead of program
int iUseMonitor = 0;				// Use Monitor Engine ?
int TUPMonitorInterval = 10;			// Monitor interval from conf file
int TUPUptimeInterval = 30;			// Uptime interval from conf file
int iCountMon = 0;				// Count loaded monitor
int iNumOfTimer = 2;				// Number of timer
int iCountMonError = 0;				// Count of errors during monitor processing
int iNoMoreMonLog = 0;				// Boolean allowing to display Monitor log ("Loading Monitor") once.
long ldNbCpu = 0;				// CPU Count

char TUPServer[64]; 				// Tup server FQDN
char TUPUser[25];				// TUP Login
char TUPPass[65];				// TUP Password
char TUPMachine[25];				// This machine name
char TUPHostname[64];				// TUP Hostname
char TUPInterface[32];				// We get mac addr from this interface
char TUPProxyHost[64];				// Proxy hostname
char TUPProxyPort[5];				// Proxy port
char sPwdToEncrypt[32];				// Store password to encrypt (argument to encryptpass func)

char sPostContent[1024];				// Post request buffer
char sPostMonitorContent[1024];			// Monitor post request buffer
char sOsId[257];					// Type de Linux ( = uname -s -r -m)
char sUptime[15] = "0";				// Uptime of this computer
char request_host[64]; 				// Packet size max for resquest host
char sTempLogLine[2048];				// A log line buffer for log (!! Too small = fault)
char sWakeUpFor[64] = "both";			// Record name of timer handled
char sMonRequestToken[68];			// Token string for monitor request identifier

unsigned char mac_addr[150]; 			// Mac address without ":"
char mac_hash_result[150]; 			// Result of Mac addr md5 buffer
char sExecPath[BUF_PATH];			// Path to tup binary

SHA256_CTX ctx256;				       // Context for SHA-256 encoding (used for password)
char chrPassEncryptBufferOUT[100];			// Output buffer = encrypted password

char *chrDistro = "unknown";			// Distro type
char *sUnusedReturn;				// 
char chrDistroTempConcat[1024];			// Detailled description of distro (release file content)
char chrDistrob64[2048];				// Recoit le base64 de la distro
char sConfPath[BUF_PATH] = CONF_FILENAME;	// Path to TUP.conf
char sCustomLogPath[BUF_PATH];			// Log path given by user
char sGlobalLogPath[BUF_PATH];			// Log path + filename 
char sStatusLogPath[BUF_PATH];			// log path + status filename
char sDebugLogPath[BUF_PATH];			// Log path + filename for debug information
char sPidFilePath[BUF_PATH];			// Path to pid file

struct tuptimer arrTimerDeclare[2];		// Array of timers



// * Socket Factory init  *
struct sockaddr_in serverSockAddr;
struct hostent *serverHostEnt;
int iSock_toBackend = -1;	

// * Struct receive uname -a
struct utsname utsname;

// Print information about program
void tupPrintUsage(char *chrArg0) {
	
	printf("\n");
	printf("----------------------------------------------------------\n");
	printf("= TUP [Tugs Uptime Project] Client : %s.%s %s  \n", CLIENTVERSION_MAJOR,CLIENTVERSION_MINOR,CLIENTVERSION_RELEASE);
	printf("= Release Codename : %s\n",CLIENTCODENAME);
	printf("= Monitoring Engine : %s\n",MONITOR_ENGINE_VERSION);
#	ifdef GOESX
	printf("= Compiled for ESX(i) platform \n");
#	endif
	printf("= Developper : Sebastien Tugs (uptimeprj@nextworlds.com)  \n");
	printf("= Thanx to : Olivier, SMP-FR, Kronick, mum \n");
	printf("----------------------------------------------------------\n");
	printf("\n");
	printf("Usage : %s [-conf path_to_tup.conf] [-log path_to_log_file] [-v | -h | --help] [--debug] [--nolog] [--nodaemon]\n\n", chrArg0);
	printf("Options :\n");
	printf("	-c path_to_tup.conf : Path to TUP.conf. Ex : /etc/TUPLinux/TUP.conf \n");
	printf("	(if not specified, program looks for TUP.conf into ./etc/ subdirectory)\n\n");
	printf("	-l path_to_log_file : A directory to store log files (with trailing slash) . Ex : /logs/ \n");
	printf("	(if not specified, log files are stored into ./logs/ subdirectory)\n\n");
	printf("	--debug : Force client in debug mode\n\n");
	printf("	--nodaemon : Do not use daemon mode (use crontab instead for example)\n\n");
	printf("	--nolog : Don't send events to log file\n\n");
	printf("	--stop : Stop cleanly program if daemonized\n\n");
	printf("	--status : Write TUPm status into log file (daemon mode only)\n\n");
	printf("	--checkmon : Check monitor(s) and validate format/conf\n\n");
	printf("	--encryptpass : Encrypt your password \n\n");
	printf("	-v | -h | --help : Display this message\n\n");
	exit(1);
		

}

// Do something when signal appends
void signal_handler(int sig) {
 
	switch(sig) {
		case SIGHUP:
			syslog(LOG_WARNING, "Received SIGHUP signal.");
			iTDaemonState = 0;
			break;
		case SIGTERM:
			syslog(LOG_WARNING, "Received SIGTERM signal.");
			iTDaemonState = 0;
			break;
		case SIGALRM:
			//syslog(LOG_INFO, "Received SIGALRM signal");
			iTExecute = 1;
			break;
		case SIGQUIT:
			syslog(LOG_WARNING, "Received Stop order...(Je m envais comme un prince)");
			iTDaemonState = 0;
			break;
		case SIGUSR1:
			syslog(LOG_INFO, "Receive a status request...processing");
			iTStatusState = 1;
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %i", sig);
			iTDaemonState = 0;
			break;
	}
}

void TUPDeclareSigHandler() {
	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGALRM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGUSR1, signal_handler);
}

// Stop tupm cleanly (in daemon mode)
void TUPKill(int iPid) {
	
	if (!(kill ( iPid, SIGQUIT))) {
			printf("[TUPm] Stop Daemon : pid was %i.\n",iPid);
	} else {
		if (errno == EPERM) {
			printf("[TUPm] Stop Daemon : Operation not permitted.\n");
		} else {
			printf("[TUPm] Stop Daemon : pid %i does not exist.\n",iPid);
		}
	}
}
 
// Stop tupm cleanly (in daemon mode)
void TUPStatus(int iPid) {
	
	if (!(kill ( iPid, SIGUSR1))) {
			printf("[TUPm] Status written to log file.\n");
	} else {
		if (errno == EPERM) {
			printf("[TUPm] Status request : Operation not permitted.\n");
		} else {
			printf("[TUPm] Status request : pid %i does not exist.\n",iPid);
		}
	}
}

// **************************************************************
// * MAIN
// **************************************************************
int main (int argc, char *argv[])
{

	#	ifdef GOESX
		// Use a precompiled ESX version on a standard Linux -> say no (nooo)
		if (uname(&utsname) == -1 ) {
			perror("[Error] : Not able to validate ESX platform\n");
			printf("[Error] : Not a valid ESX platform\n");
			exit(EXIT_FAILURE);
		} else {
			char sEsxTempValid[1024];
			sprintf(sEsxTempValid,"%s" , utsname.sysname);

			if(strcmp( sEsxTempValid, "VMkernel" ) == 0) {
				#			define DISTRO "esx"
				#			define VDISTRO "1"
			} else {
				printf("[Error] : Not a valid ESX platform (Current -> %s)\n\n", sEsxTempValid);
				exit(EXIT_FAILURE);
			}
		}
	#	endif




	int iPathReached = 0;					// 1 = we find program path, 0 = fail :(
	static char pidbuf[20];
	FILE *filepid;
	srand(time(NULL));  				       	// init random generation ruid
	int iCountCycle = 1;					// count execution cycle

    	// -- Proccess ID & Session ID
    	pid_t pid, sid;

	// ** AFTGBP : Advanced Function To Get Binary Path :lol:
	// ------------------------------------------------------
	// This is definitely hard to compute real binary path.
	// We'll try and advanced way (huhu) . For Linux, we can use /proc/self/exe which is a symlink
	// to program file including directory. For others OS, we'll try to find the path with argv[0]
	// and finally into values of getenv("PATH") . 
	// After all, if we're not able to find bin path, this program will self descruct ^^ xD

#	ifndef GOESX
#	ifdef GET_PATH_NUX

	// For Linux, easy as far as we can read /proc/self/exe <- symlink to filename and path ^^
	int length;
	char fullpath[PATH_MAX];
	char bufpath[PATH_MAX];
	length = readlink("/proc/self/exe", fullpath, sizeof(fullpath));
     
	if (length < 0 || length >= PATH_MAX) {
		fprintf(stderr, "[ERROR] - resolving symlink /proc/self/exe :/ \n");
		//exit(EXIT_FAILURE);
		iPathReached = 0;
	} else {
		fullpath[length] = '\0';	
		sUnusedReturn = realpath(fullpath,bufpath); // seems to resolve symlink to realpath
		sprintf(sExecPath,"%s",dirname(strdup(bufpath)));
		iPathReached = 1;
	}
#	endif
#	endif

	// Not a linux os or /proc/self/exe fails, try argv[0]
	int iIsGoodPath = 0;

	if( iPathReached == 0 ) {
		char arrArgv0TempBuf[PATH_MAX];
		sUnusedReturn = realpath(argv[0],arrArgv0TempBuf);
		iIsGoodPath = access( arrArgv0TempBuf, X_OK );
		
		if( iIsGoodPath ) {
			iPathReached = 0;
		} else {
			sprintf(sExecPath,"%s",dirname(strdup(arrArgv0TempBuf)));
			iPathReached = 1;
		}
	}

	// Fail with argv[0] ? Loop $PATH to find program
	if( iPathReached == 0 ) {
		char parsePath[PATH_MAX];
		char *binFind;
		iIsGoodPath = 0;
		binFind=basename(strdup(argv[0]));
		TUPPathParseAndFind(parsePath,binFind);
		iIsGoodPath = access( parsePath, X_OK );
		//free(binFind);

		if( iIsGoodPath ) {
			iPathReached = 0;
		} else {
			sprintf(sExecPath,"%s",dirname(strdup(parsePath)));
			iPathReached = 1;
		}
	}

	// not able to find path...damned i'm a looser xD
	if( iPathReached == 0 ) {
		printf("[FATAL] Not able to find program path :/...\n");
		exit(EXIT_FAILURE);
	}


	// ---------------------------------------------------------
	
	// ** Parsing args / switches                .   
	int c , iIsConfR, iIsLogW, iIsPidR;	
	extern char *optarg;
	int option_index = 0;

	while( (c = getopt_long(argc, argv, "c:l:v|h", lsswitch, &option_index)) != -1) {

	switch(c){
	    	case 's':
			// Stop Daemon sending SIGQUIT
			sprintf(sPidFilePath,"%s/pid/%s",sExecPath,PID_FILE);

			iIsPidR = access( sPidFilePath , R_OK );
			if( iIsPidR ) {
				printf("[Error] Not able to read pid file...\n");
				exit(EXIT_FAILURE);
			} else {
				if ( (filepid = fopen (sPidFilePath, "r")) != NULL) {

					sUnusedReturn = fgets (pidbuf, sizeof (pidbuf), filepid);
					TUPKill(atoi(pidbuf));
					remove(sPidFilePath);
					fclose(filepid);
				} else {
					printf("[Error] Not able to read pid file...\n");
					exit(EXIT_FAILURE);
				}
			}
	       		exit(EXIT_SUCCESS);
		break;
		case 't':
			// Write status to log file if receiving SIGUSR1
			sprintf(sPidFilePath,"%s/pid/%s",sExecPath,PID_FILE);
		
			iIsPidR = access( sPidFilePath , R_OK );
			if( iIsPidR ) {
				printf("[Error] Not able to read pid file...\n");
				exit(EXIT_FAILURE);
			} else {
				if ( (filepid = fopen (sPidFilePath, "r")) != NULL) {

					sUnusedReturn = fgets (pidbuf, sizeof (pidbuf), filepid);
					TUPStatus(atoi(pidbuf));
					fclose(filepid);
				} else {
					printf("[Error] Not able to read pid file...\n");
					exit(EXIT_FAILURE);
				}
			}
	       		exit(EXIT_SUCCESS);
		break;
	    	case 'c':
	  		sprintf(sConfPath,"%s", optarg);

			iIsConfR = access( optarg , R_OK );
			if( iIsConfR ) {
				printf("[Error] TUP.conf not found or no read access to this file...\n");
				exit(0);
			}
	  		iSetPath = 1;
		break;
	    	case 'l':
			iIsLogW = access( optarg , W_OK );
			if( iIsLogW ) {
				printf("[Error] Specified log directory does not exist or is not writable...\n");
				exit(0);
			}
			iSetLogPath = 1;
			sprintf(sCustomLogPath,"%s",optarg);
		break;
	    	case 'o':		
			iSetNoLog = 1;
		break;
	   	case 'd':
			iSetDebug = 1;
		break;
	    	case 'X':
			iSetVerboseLikeAWoman = 1;
		break;
	    	case 'n':
			iSetNoDaemon = 1;
		break;
	    	case 'e':
			if (optarg) {
                      		sprintf(sPwdToEncrypt, "%s" , optarg);
				iEncryptPasswordFunc = 1;
			} else {
				printf("[Error] Encryptpass needs a clear password as argument\n");
				exit(0);
			}
		break;
	    	case 'm':
			iSetValidateMonitor = 1;
		break;
	   	case '1':
			tupPrintUsage(argv[0]);
			exit(0);
		break;
   	    	case 'h':
			tupPrintUsage(argv[0]);
			exit(0);
		break;
   	    	case 'v':
			tupPrintUsage(argv[0]);
			exit(0);
		break;
  	    	case 'V':
			tupPrintUsage(argv[0]);
			exit(0);
		break;
	    	default:
			tupPrintUsage(argv[0]);
			exit(0);
		break;
		} // end switch

	}  // end while
	free(optarg);

				
	#if defined(DEBUG)
		iSetNoDaemon = 1;
	#endif
 
	// -------------- Just wanna encrypt a clear password
	if( iEncryptPasswordFunc ) {

		char chrEncryptTempBuffer[65];
		
		SHA256_Init(&ctx256);
		SHA256_Update(&ctx256, (unsigned char*)sPwdToEncrypt, strlen(sPwdToEncrypt));
		SHA256_End(&ctx256, chrEncryptTempBuffer);

		printf("\nYour Encrypted password : %s \n\n(store it into TUPm.conf)\n\n----\n",chrEncryptTempBuffer);
		exit(EXIT_SUCCESS);
	} // end encrypt pass


	// -------------- Just wanna check monitors configuration
	if( iSetValidateMonitor ) {

		int iCTTer = 0;	
		int iCTCountMonError = 0;
		int iCTCountMon = 0;
		char sCTFullCommand[512];
		char *sCTBuffReplace;
		FILE *CTfpipe;
		char CTline[256];
		char *sCTCommandResult;

		printf("\n------ Monitor(s) Validation Process : Starting.......\n\n");

		struct tupmon *CTlistmon = TUPLoadMonitor(sExecPath,&iCTCountMon,1,1,1,"/tmp");
		qsort(CTlistmon, iCTCountMon, sizeof( struct tupmon ) , tupmon_cmp);
	
		while (iCTTer < iCTCountMon) {

			printf("\n[Monitor Check] (%i) Trying to execute monitor : %s\n",iCTTer,CTlistmon[iCTTer].tupmon_name);

			sCTBuffReplace = str_replace(CTlistmon[iCTTer].tupmon_filename," ","\\ ");
	
			if( sCTBuffReplace == NULL ) {
				sprintf(sCTFullCommand,"%s %s",CTlistmon[iCTTer].tupmon_filename,CTlistmon[iCTTer].tupmon_parameters);
			} else {
				sprintf(sCTFullCommand,"%s %s",sCTBuffReplace,CTlistmon[iCTTer].tupmon_parameters);
			}	
			free(sCTBuffReplace);

			printf("---> Order : %i\n",CTlistmon[iCTTer].tupmon_order);
			printf("---> Command to launch : %s\n",sCTFullCommand);

			// Execute command
			printf("---> Testing command ....\n");
			if ( !(CTfpipe = (FILE*)popen(sCTFullCommand,"r")) ) {  
				printf("\n--> ERROR - Not able to execute command : %s\n",CTlistmon[iCTTer].tupmon_name, sCTFullCommand);
				iCTCountMonError++;
				pclose(CTfpipe);

			} else {

				sCTCommandResult = fgets( CTline, sizeof(CTline), CTfpipe);
		
				if( sCTCommandResult == NULL ) { 
			
					printf("\n--> ERROR - Error executing command or empty value (check +x property)\n", iCTTer);

					iCTCountMonError++;
					pclose(CTfpipe);

				} else {

					pclose(CTfpipe);
					
					sCTBuffReplace = str_replace(sCTCommandResult,"\n","");
					if( sCTBuffReplace != NULL ) {
						sprintf(sCTCommandResult,"%s",sCTBuffReplace);
					}
					free(sCTBuffReplace);

					if( !CTlistmon[iCTTer].tupmon_isactive ) {
						printf("\n---> This Monitor is DISABLE\n");
					} else {
						printf("\n---> This Monitor is ENABLE\n");
					}
					printf("---> Parsing attribute NAME : %s\n",CTlistmon[iCTTer].tupmon_name);
					printf("---> Parsing attribute Command Result : %s\n",sCTCommandResult);
					printf("---> Parsing attribute TYPE : %s\n",CTlistmon[iCTTer].tupmon_type);
					printf("---> Parsing attribute Service Description : %s\n",CTlistmon[iCTTer].tupmon_service_desc);
					printf("---> Parsing attribute GROUP : %s\n",CTlistmon[iCTTer].tupmon_group);
					printf("---> Parsing attribute Stop On Error : %i\n",CTlistmon[iCTTer].tupmon_stoponerror);


					if( strcmp(sCTCommandResult,"(null)") == 0 ) {
						printf("\n---> ERROR - Error processing command (Result empty)\n");
						iCTCountMonError++;
					} // if strcmp null

				} // end fpipe=null

			} // end !fpipe

			iCTTer++;
		} // end while

		free(CTlistmon);

		printf("\n------> Count of monitor(s) well formated: %i",iCTCountMon);
		printf("\n------> Count of monitor(s) returning NULL value : %i",iCTCountMonError);
		printf("\n------> Count of valid monitor(s) : %i / %i \n\n",iCTCountMon-iCTCountMonError,iCTCountMon);
		exit(EXIT_SUCCESS);

	} // end iSetValidateMonitor
	// -------------- end monitor check


	if (!iSetNoDaemon) {

		iSetDebug = 0;

		// Setup signal handling before we start
		TUPDeclareSigHandler();

		// Setup syslog logging - see SETLOGMASK(3)
		#if defined(DEBUG)
		    setlogmask(LOG_UPTO(LOG_DEBUG));
		    openlog(DAEMON_NAME, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
		#else
		    setlogmask(LOG_UPTO(LOG_INFO));
		    openlog(DAEMON_NAME, LOG_CONS, LOG_USER);
		#endif

		// -- Starting TUP Monitoring Client as Daemon
		syslog(LOG_INFO, "Starting TUPm as daemon");

		// -- Fork process
		pid = fork();
		if (pid < 0) {
			printf("[FATAL] - Not able to fork TUPm process\n");
			exit(EXIT_FAILURE);
		} 

    		if (pid > 0) {
       		    exit(EXIT_SUCCESS);
      		}

		umask(0);

		// -- Set sid to process forked (child process)
		sid = setsid();
		if (sid < 0) {
			printf("[FATAL] - Not able to create sid for TUPm forked process\n");
			exit(EXIT_FAILURE);
		}

		// -- Change working directory
		if ((chdir("/")) < 0) {
			printf("[FATAL] - Not able to set working directory\n");
			exit(EXIT_FAILURE);
		}

		sprintf(sPidFilePath,"%s/pid/%s",sExecPath,PID_FILE);
		if( !TUPcWritePid(sPidFilePath,sid) ) {
			printf("[FATAL] - Not able to write pid file\n");
			exit(EXIT_FAILURE);
		}

		// if XTradebug
		if( iSetVerboseLikeAWoman ) {
			if( !iSetLogPath  ) {
				sprintf(sDebugLogPath,"%s/logs/%s",sExecPath,LOG_FILENAME_DEBUGVERBOSE);
			} else {

				sprintf(sDebugLogPath,"%s/%s",sCustomLogPath,LOG_FILENAME_DEBUGVERBOSE);
			}

			sprintf(sTempLogLine,"(tupmdebug) Client Info : type[%s] v_major[%s] v_minor[%s] patch[%s] codename[%s] monitor_engine[%s]",CLIENT_TYPE,CLIENTVERSION_MAJOR,CLIENTVERSION_MINOR,CLIENTVERSION_RELEASE,CLIENTCODENAME,MONITOR_ENGINE_VERSION); 

			TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine);
	
		}

		// Prepare Exec
		int iRetPrepare = TUPPrepare();
		if( !iRetPrepare ) {
			if( !iSetNoLog ) { TUPcWriteALineOfLog(sGlobalLogPath,"(tupm) Something wrong in prepare function..."); }
			exit(EXIT_FAILURE);
		} 

		// -- Close out standard fd
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		

		syslog(LOG_INFO, "TUPm forked as process id %i",sid);
		
		// -- Daemon loop. Using iInitAlarm to start first timer
		if( iSetVerboseLikeAWoman  ) { 

			sprintf(sTempLogLine,"(tupmdebug) Timer Init v:%i",arrTimerDeclare[0].tuptimer_value); 
			TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine);
			sprintf(sTempLogLine,"(tupmdebug) TUPm was forked with process id:%i",sid); 
			TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine);
		}

		iInitAlarm = alarm(arrTimerDeclare[0].tuptimer_value);

		// First sent of uptime / monitor (is enable)
		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Entering Main %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

		iRetMain = TUPMain();

		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Leaving Main %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

		// -- Loop until iTDaemonState 0 = signal to exit program
		while( iTDaemonState ) {

			if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Loop %i - Waiting for SIG ALARM",iCountCycle); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

			// use select instead of sleep to wait until a signal (exit type or SIGALRM for timer)
			select(0,NULL,NULL,NULL,NULL);
			
			if( iTExecute ) { // if it's time to action, launching tupMain
				
				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Execute %i",iCountCycle); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }
				if( arrTimerDeclare[1].tuptimer_value == arrTimerDeclare[0].tuptimer_value) {
					sprintf(sWakeUpFor,"%s","both");
					arrTimerDeclare[0].tuptimer_value = arrTimerDeclare[0].tuptimer_origvalue;
					arrTimerDeclare[1].tuptimer_value = arrTimerDeclare[1].tuptimer_origvalue;
				} else {
					sprintf(sWakeUpFor,"%s",arrTimerDeclare[0].tuptimer_name);
					arrTimerDeclare[1].tuptimer_value = arrTimerDeclare[1].tuptimer_value - arrTimerDeclare[0].tuptimer_value;
					arrTimerDeclare[0].tuptimer_value = arrTimerDeclare[0].tuptimer_origvalue;

				}

				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) WakeUp %s",sWakeUpFor); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				qsort(arrTimerDeclare, iNumOfTimer, sizeof( struct tuptimer ) , tuptimer_cmp);
				
				#if defined(DEBUG)
					syslog(LOG_INFO, "Tupm Timer . Execute iteration num : %i",iCountCycle);
					syslog(LOG_INFO, "Tupm TImer . Wake up for : %s",arrTimerDeclare[0].tuptimer_name);
				#endif

				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) End Execute %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				iCountCycle++;
				iTAlarm = alarm(arrTimerDeclare[0].tuptimer_value);

#				if defined(__sun__) || defined(sun)
					TUPDeclareSigHandler(); // mandatory on Solaris platform
#				endif

				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Main under execute %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				iRetMain = TUPMain();

				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) End Main under execute %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }
				iTExecute = 0;
			} // end if iTExecute

			if( iTStatusState ) {
				if( !iSetNoLog && !iSetNoDaemon) {
					sprintf(sTempLogLine,"(tupm) Status Request - Processing\n -> Process id is : %i\n -> Cycle is : %i\n -> Last count of Loaded monitor(s) : %i\n -> Log path is : %s\n -> Conf Path is : %s\n -> PID Path is : %s\n -> Last Uptime is : %s (%i h)\n -> OS id is : %s\n -> Mac Addr md5 is : %s\n -> Last wake up for : %s",sid,iCountCycle,iCountMon,sGlobalLogPath,sConfPath,sPidFilePath,sUptime,atoi(sUptime)/3600,sOsId,mac_hash_result,sWakeUpFor); 
					
					TUPcWriteALineOfLog(sStatusLogPath,sTempLogLine); 
				}
				iTStatusState = 0;
			}

		} // end main while

		syslog(LOG_INFO, "Stopping process cleanly");
		if( !iSetNoLog && !iSetNoDaemon) { TUPcWriteALineOfLog(sGlobalLogPath,"(tupm) Stopping daemon mode"); }
		exit(0);

	} else {
		
		iSetVerboseLikeAWoman = 0;
		int iRetPrepare =  TUPPrepare();

		if( !iRetPrepare ) {
			if( !iSetNoLog ) { TUPcWriteALineOfLog(sGlobalLogPath,"(tupm) Something wrong in prepare function..."); }
			exit(EXIT_FAILURE);
		}  

		iRetMain = TUPMain();
		
		if( !iSetNoLog ) { sprintf(sTempLogLine,"(tupm) End of statement (%i)(%i)",iRetPrepare,iRetMain); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }
		exit(0);
	}

  
}

int TUPPrepare() {

	// ----------- PREPARE TUPm Exec ---------------
	char arrBufSection[32];
	int iIsStatusHere = 0;
	int iIsLogHere = 0;
	int iValidMandatory = 0;
	char arrTemporaryBuffer[100];


	// ** if no arg with path to TUP.conf, compute it starting with current program directory
  	if( iSetPath == 0 ) {
		sprintf(sConfPath,"%s/%s",sExecPath,CONF_FILENAME);
  	} // end if iSetPath
	
	// ** we log only if NoLog switch not specified
	if( !iSetNoLog ) {

		// if custom log path is specified, we use it
		if( !iSetLogPath  ) {
			sprintf(sGlobalLogPath,"%s/logs/%s",sExecPath,LOG_FILENAME_GLOBAL);
			sprintf(sStatusLogPath,"%s/logs/%s",sExecPath,LOG_FILENAME_STATUS);
		} else {
			sprintf(sGlobalLogPath,"%s/%s",sCustomLogPath,LOG_FILENAME_GLOBAL);
			sprintf(sStatusLogPath,"%s/%s",sCustomLogPath,LOG_FILENAME_STATUS);
		}



	} // end set no log	

	if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Path configured . Conf : %s / Log : %s",sConfPath,sGlobalLogPath); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

	// ** Parse configuration file with ConfLoader
	if ( ini_getsection(1, arrBufSection, sizeof arrBufSection, sConfPath) == 0)  {
		printf("[Error] TUP.conf not found or error in file (not enough parameters or bad value(s)...)\n");
		return 0;
	} 
  	

	// ** If Specified in conf file, delete log
	if( ini_getl("TUPAccount", "TUPFlushLogAtStart", 0 , sConfPath) ) {
		
		//Check if file are here and writable
		iIsLogHere = !access( sGlobalLogPath , W_OK );	
		iIsStatusHere = !access( sStatusLogPath , W_OK );

		if( iIsLogHere ) unlink(sGlobalLogPath);
		if( iIsStatusHere ) unlink(sStatusLogPath);
	}

	if( !iSetNoLog && iSetNoDaemon) { TUPcWriteALineOfLog(sGlobalLogPath,"(tupm) Starting as regular mode (nodaemon)"); }
	if( !iSetNoLog && !iSetNoDaemon) { TUPcWriteALineOfLog(sGlobalLogPath,"(tupm) Starting daemon mode"); }
	      
	if (iSetDebug){
		printf("\n******************************** \n");
	    	printf("*** [ENTERING DEBUG MODE]   **** \n");
	    	printf("******************************** \n\n");
	    	printf("[Mesg] -> TUP.conf Path Finder : %s\n\n",sConfPath);
		iSetDebug = 1;
	}


	// ** Some values are mandatory
	if( ini_gets("TUPAccount", "TUPUser", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {
		sprintf(TUPUser,"%s",arrTemporaryBuffer);
		iValidMandatory = 1;
	} else {
		iValidMandatory = 0;
	}

	if( ini_getl("TUPAccount", "TUPEncryptedPass", 0 , sConfPath) ) {
		iAlreadyEncryptedPassword = 1;
	}

	if( ini_gets("TUPAccount", "TUPPass", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {


		if( iAlreadyEncryptedPassword ) {

			if( iSetDebug ) {
				printf("--> Password is already encrypted (TUPEncryptedPass = 1)\n");
			}

			sprintf(TUPPass,"%s",arrTemporaryBuffer);
		} else {
			SHA256_Init(&ctx256);
			SHA256_Update(&ctx256, (unsigned char*)arrTemporaryBuffer, strlen(arrTemporaryBuffer));
			SHA256_End(&ctx256, chrPassEncryptBufferOUT);

			sprintf(TUPPass,"%s",chrPassEncryptBufferOUT);
		}

		if( iSetDebug ) {
			printf("--> Encrypted Password (sha256) : %s \n",TUPPass);
		}

		iValidMandatory = 1;
	} else {
		iValidMandatory = 0;
	}

	if( ini_gets("TUPAccount", "TUPMachine", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {
		sprintf(TUPMachine,"%s",arrTemporaryBuffer);
		iValidMandatory = 1;
	} else {
		iValidMandatory = 0;
	}

	if( ini_gets("TUPServer", "TUPHostname", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {
		sprintf(TUPHostname,"%s",arrTemporaryBuffer);
		iValidMandatory = 1;
	} else {
		iValidMandatory = 0;
	}

	if( ini_gets("TUPNetwork", "TUPInterface", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {
		sprintf(TUPInterface,"%s",arrTemporaryBuffer);
		iValidMandatory = 1;
	} else {
		iValidMandatory = 0;
	}

	
	if( !iValidMandatory ) {
		printf("[Error] TUP.conf, required option not found, check it (not enough parameters or bad value(s)...\n");
		return 0;
	}
    
  	// ** Check configuration du proxy				
	if( ini_getl("Proxy", "UseProxy", 0 , sConfPath) ) {
		if( ini_gets("Proxy", "ProxyHost", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {
			printf("UseProxy set to 1 but no proxy host configured ? Please edit TUP.conf... \n\n");
			return 0;
		} else {
			sprintf(TUPProxyHost,"%s",arrTemporaryBuffer);
		}

		if( ini_gets("Proxy", "ProxyPort", "" , arrTemporaryBuffer, sizeof arrTemporaryBuffer, sConfPath) > 0 ) {
			printf("UseProxy set to 1 but no proxy host configured ? Please edit TUP.conf... \n\n");
			return 0;
		} else {
			sprintf(TUPProxyPort,"%s",arrTemporaryBuffer);
		}
		iUseProxy = 1;
	}
  


	// ** If proxy configured, get values
	if ( iUseProxy ) {
	   	   
		sprintf(TUPServer,"%s",TUPProxyHost);
		sscanf(TUPProxyPort,"%d",&port);
		sprintf(request_host,"%s",TUPHostname);
	   
	} else { // No proxy, we go straight
	  
		sprintf(TUPServer,"%s",TUPHostname);
		sprintf(request_host,"%s",TUPHostname);
	   
	}

	// ** Get cpu count  
	ldNbCpu = get_cpucount();

	if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) CPU Count OK . Count : %ld",ldNbCpu); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

	if( iSetDebug ) {
		printf("--> CPU Count : %ld \n" , ldNbCpu);
	}
	
	if( !iSetNoLog ) { sprintf(sTempLogLine,"(uptime) CPU Count is %ld",ldNbCpu); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }

	// ** Get Mac Address
	tupGet_mac();
  
	// ** If mac address is empty, error.
	if( !strcmp((const char*)mac_addr,"") ) {
		printf("[Error] Error getting Mac Address. Check interface name in TUP.conf \n\n");
		return 0;;
	}

	if( !iSetNoLog ) { sprintf(sTempLogLine,"(uptime) Mac Address is %s",mac_addr); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }

	// ** Hash mac address
	MD5MacAddr();
      
	if( !iSetNoLog ) { sprintf(sTempLogLine,"(uptime) MD5 of Mac Address is %s",mac_hash_result); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }

	if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Mac Addr OK . Val: %s",mac_hash_result); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

  	// ** Get distro informations (test release files)
  	check_distro();


 	// ** Get uname -a
	if (uname(&utsname) == -1 ) {
		perror("uname()");
		sprintf(sOsId,"%s" ,"Linux (Undefined)");
	} else {
		sprintf(sOsId,"%s+%s+(%s)" , utsname.sysname, utsname.release, utsname.machine);
	}
	
	if( !iSetNoLog ) { sprintf(sTempLogLine,"(uptime) Operating System ID is %s",sOsId); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }

	if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Distro and OS Id OK . Val: %s",sOsId); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

	// Get Monitor engine option
	iUseMonitor = ini_getl("TUPMonitor", "TUPMonitorEngine", 0 , sConfPath);
	

	// Timer prepare
	TUPMonitorInterval = ini_getl("TUPMonitor", "TUPMonitorInterval", 10 , sConfPath);

		if( TUPMonitorInterval < 5 ) {
			TUPMonitorInterval = 5*60;
		} else {
			TUPMonitorInterval = TUPMonitorInterval * 60;
		}

	TUPUptimeInterval = ini_getl("TUPAccount", "TUPUptimeInterval", 30 , sConfPath);

		if( TUPUptimeInterval < 30 ) {
			TUPUptimeInterval = 30*60;
		} else {
			TUPUptimeInterval = TUPUptimeInterval * 60;
		}

	sprintf(arrTimerDeclare[0].tuptimer_name,"%s","monitor");
	arrTimerDeclare[0].tuptimer_origvalue = TUPMonitorInterval;
	arrTimerDeclare[0].tuptimer_value = TUPMonitorInterval;

	sprintf(arrTimerDeclare[1].tuptimer_name,"%s","uptime");
	arrTimerDeclare[1].tuptimer_origvalue = TUPUptimeInterval;
	arrTimerDeclare[1].tuptimer_value = TUPUptimeInterval;
	
	qsort(arrTimerDeclare, iNumOfTimer, sizeof( struct tuptimer ) , tuptimer_cmp);


	// Test DNS resolution and write result to debug file
	if( iSetVerboseLikeAWoman  ) { 


		struct hostent *tempHostTestResol;

		if ((tempHostTestResol = gethostbyname (TUPHostname)) != NULL)
		{	

			struct in_addr **inaddrTupSrvIP;
			inaddrTupSrvIP = (struct in_addr **)tempHostTestResol->h_addr_list;

			sprintf(sTempLogLine,"(tupmdebug) IP from dns resolution is : %s",inet_ntoa(*inaddrTupSrvIP[0])); 
			TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine);
		} 


	}

	// ------------ END PREPARE TUPm Exec ----------

	return 1;

}


// -- Main function of TUP Program. Sending uptime and processing monitor
int TUPMain () {

	

	// ** use TUPSocketFactory to open socket
	int iRetInitSock = initSocket (&iSock_toBackend, &serverSockAddr, serverHostEnt, port, TUPHostname);

	if( iRetInitSock ) {

		if( iSetDebug ) {
			printf("--> Socket is ON : %i \n" , iSock_toBackend);
		}

	} else {

		if( iSetDebug ) {
			printf("--> Socket is down, use replay (%i)\n" , iSock_toBackend);
		}
		if( !iSetNoLog ) {TUPcWriteALineOfLog(sGlobalLogPath,"(monitor) Using replay because of socket down"); }		
		iUseReplay = 1;
		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Socket Factory use Replay (sock down) : %i",iSock_toBackend); 
		TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }
	}

	if( (strcmp(sWakeUpFor,"both") == 0) || (strcmp(sWakeUpFor,"uptime") == 0) ){
		// ** Get Uptime !
		get_uptime();

		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Uptime Wakeup: %s",sUptime); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

		if( !iSetNoLog ) { sprintf(sTempLogLine,"(uptime) Uptime count is %s",sUptime); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }


		// ** Display informations about post on debug mode
		if( iSetDebug ) {
			printf("--> REQUEST ServerName : %s \n" , TUPServer);
			printf("--> REQUEST Host : %s \n\n" , request_host);
			printf("--> REQUEST Distrib : %s \n\n" , chrDistro);
		}


		// ** Convert distro informations into base64 & prepare POST
		if( strlen(chrDistroTempConcat) != 0 ) {
		
			encode64(chrDistroTempConcat, chrDistrob64 , strlen(chrDistroTempConcat));

			sprintf(sPostContent,"username=%s&pass=%s&zsec=s256&uptime=%s&os=%s&mac=%s&machine=%s&distrib=%s&cnb=%ld&distribcontent=%s&",TUPUser,TUPPass,sUptime,sOsId,mac_hash_result,TUPMachine,chrDistro,ldNbCpu,chrDistrob64);

		} else {

			sprintf(sPostContent,"username=%s&pass=%s&zsec=s256&uptime=%s&os=%s&mac=%s&machine=%s&distrib=%s&cnb=%ld&distribcontent=&",TUPUser,TUPPass,sUptime,sOsId,mac_hash_result,TUPMachine,chrDistro,ldNbCpu);

		}

		// ** Display informations about post on debug mode
		if( iSetDebug ) {

			printf("--> POST length : %i \n" , (int)strlen(sPostContent));
			printf("--> POST value : %s \n\n" , sPostContent);
		}
	

	
		if( iRetInitSock ) {

			TUP_POSTRequest(sPostContent,UPDATE_PHP_FILE);
			TUP_ReplayRequest();
		}


		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) End Uptime WakeUP %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

	} // End WakeUpFor Uptime



	if( (strcmp(sWakeUpFor,"both") == 0) || (strcmp(sWakeUpFor,"monitor") == 0) ){

		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Monitor WakeUP %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

		// ** Monitor engine request
		if( !iUseMonitor ) {
		
			if( iSetDebug ) {
				printf("\n--> Monitor Engine is OFF\n\n");
			}

		if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) But Engine is OFF... %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

		} else {

		// ********************************************************************
		// * MONITOR LAUNCH		      			              *
		// ********************************************************************

			int iTer = 0;
			// compute Token
			sprintf(sMonRequestToken,"%s",TUPBuildToken());
	
			if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Entering Monitor . Iteration: %i",iTer); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

			if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Request Token: %s",sMonRequestToken); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }
		
			char sFullCommand[1024];
			char *sBuffReplace2,*sBuffReplace;
			FILE *fpipe;
			char line[256];
			char *sCommandResult;

			struct tupmon *listmon = TUPLoadMonitor(sExecPath,&iCountMon,iSetDebug,iSetNoLog,iSetNoDaemon,sGlobalLogPath);
			qsort(listmon, iCountMon, sizeof( struct tupmon ) , tupmon_cmp);
			
			if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Monitor Processing . C[%i]",iCountMon); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

			if( !iSetNoLog && !iNoMoreMonLog ) { sprintf(sTempLogLine,"(monitor) Loading Monitor [%i]",iCountMon); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); iNoMoreMonLog = 1;}


			while (iTer < iCountMon) {
			
				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Monitor -> Loop : %i",iTer); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				if( iSetDebug ) {
					printf("\n--> Processing Monitor %i : %s\n",iTer,listmon[iTer].tupmon_name);
				}


				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Here we go for %s",listmon[iTer].tupmon_name); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				sBuffReplace = str_replace(listmon[iTer].tupmon_filename," ","\\ ");
				if( sBuffReplace == NULL ) {
					sprintf(sFullCommand,"%s %s",listmon[iTer].tupmon_filename,listmon[iTer].tupmon_parameters);
				} else {
					sprintf(sFullCommand,"%s %s",sBuffReplace,listmon[iTer].tupmon_parameters);
				}	
				free(sBuffReplace);

				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Replace slash : Passed %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				if( iSetDebug ) {
					printf("\n--> Monitor %i Order : %i\n",iTer,listmon[iTer].tupmon_order);
					printf("\n--> Monitor %i cmd : %s\n",iTer,sFullCommand);
				}	

				if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Monitor info completed : %i -> %s",listmon[iTer].tupmon_order,sFullCommand); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				// Execute command
				if ( !(fpipe = (FILE*)popen(sFullCommand,"r")) )
				{  
					if( iSetDebug ) {
						printf("\n--> Monitor (%s): Not able to execute command : %s",listmon[iTer].tupmon_name, sFullCommand);

					}
			
					if( !iSetNoLog ) { sprintf(sTempLogLine,"(monitor) Error processing command : %s",sFullCommand); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }	

					iCountMonError++;
					pclose(fpipe);

					if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Error processing this mon %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

				} else {

					sCommandResult = fgets( line, sizeof(line), fpipe);
					
					if( sCommandResult == NULL ) { 

						if( !iSetNoLog && !iSetNoDaemon ) { sprintf(sTempLogLine,"(monitor) Error executing command : %s (check +x property)",sFullCommand); TUPcWriteALineOfLog(sGlobalLogPath,sTempLogLine); }
						
						if( iSetNoDaemon && iSetDebug ) { printf("\n--> Monitor %i inf : Error executing command (check +x property)\n", iTer); }

						iCountMonError++;
						pclose(fpipe);

						if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Error executing command for this mon %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

					} else {


						if( iSetDebug ) {
						#if !defined(__sun__) && !defined(sun)
							printf("\n--> Monitor %i inf : PID=%i",iTer,getpid());
							printf("\n--> Monitor %i inf : PPID=%i",iTer,getppid());
						#endif
							printf("\n--> Monitor %i inf : RES=%s",iTer,sCommandResult);
						}

						memset(&sPostMonitorContent[0], 0, sizeof(sPostMonitorContent));

						sprintf(sPostMonitorContent,"username=%s&pass=%s&zsec=s256&mac=%s&mn=%s&mt=%s&msd=%s&mso=%i&msg=%s&mss=%i&ret=%s&nw=%i&ruid=%i&ts=%s&token=%s&",TUPUser,TUPPass,mac_hash_result,listmon[iTer].tupmon_name,listmon[iTer].tupmon_type,listmon[iTer].tupmon_service_desc,listmon[iTer].tupmon_order,listmon[iTer].tupmon_group,listmon[iTer].tupmon_stoponerror,sCommandResult,iUseReplay,rand(),TUPcGetDateTime(),sMonRequestToken);
				
						pclose(fpipe);

						if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) M# Build POST : Passed --> %s",sPostMonitorContent); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

						sBuffReplace2 = str_replace(sPostMonitorContent,"\n","");
						if( sBuffReplace2 != NULL ) {
							sprintf(sPostMonitorContent,"%s",sBuffReplace2);
						}
						free(sBuffReplace2);

						if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) M# Replace 2 : Passed %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

						if( strcmp(sCommandResult,"(null)") == 0 ) {
							if( !iSetNoLog ) {TUPcWriteALineOfLog(sGlobalLogPath,"(monitor) Error processing command"); }
							iCountMonError++;

						} else {
					
							if( iUseReplay ) {
					
								if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) M# Use Replay %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }
								char sReplayLogPath[1024];

								sprintf(sReplayLogPath,"%s%s",sExecPath,CONF_FILENAME_REPLAY);
								int iTwR = TUPcWriteToFile(sReplayLogPath,sPostMonitorContent);

								if( iSetDebug && iTwR == 0 ) {
									printf("\n--> Replay monitor %i: Not able to write request to log replay\n",iTer);
								} else {
									if( iSetDebug ) {
										printf("\n--> Replay monitor %i: Written to replay log\n",iTer);
									}
								}


							} else {
	
								if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) M# Begin Send POST : Passed -> %s / %i",sPostMonitorContent,(int)strlen(sPostMonitorContent)); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

								TUP_POSTRequest(sPostMonitorContent,MONITOR_PHP_FILE);	

								if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) M# End Send POST : Passed %s","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

							}

						} // if strcmp null

					} // end fpipe=null

				} // end !fpipe

				iTer++;
			} // end while


			free(listmon);
			sprintf(sMonRequestToken,"%s","");
			if( iSetDebug ) { printf("\n[DEBUG INFO] - Count of error(s) during monitor processing : %i\n\n",iCountMonError); }

			if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) Count of error(s) during monitor processing -> %i",iCountMonError); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

		} // end monitor on/off
		// ************************************************************ End Monitor
	
	} // end WakeUpFor Monitor


	if( !iUseReplay ) {

		closeSocket (iSock_toBackend);

	}

	if( iSetVerboseLikeAWoman  ) { sprintf(sTempLogLine,"(tupmdebug) End Processing.... see ya","-"); TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); }

  return 1;
}



// ** Replay request if TUPReplay.log contains some.
void TUP_ReplayRequest (void) {

	char sReplayLogPath[1024];

	sprintf(sReplayLogPath,"%s%s",sExecPath,CONF_FILENAME_REPLAY);
	if( iSetDebug ) {
		printf("\n--> Trying to replay request");
		printf("\n--> Replay log path is : %s", sReplayLogPath);
	}

	int iIsLogReplayW = access( sReplayLogPath , W_OK );
	
	
	if( iIsLogReplayW && iSetDebug ) {
		printf("\n--> Replay log file does not exist.\n");
	} else {

		int iArrCount;
		int iTer;
		char **cArrReiv = TUPcReadFile(sReplayLogPath, &iArrCount, iSetDebug);

		if( iArrCount > 0 ) {

			if( iSetDebug ) {
				printf("\n--> Will replay %i request",iArrCount);
			}

			while (iTer < iArrCount) {

				TUP_POSTRequest(cArrReiv[iTer],MONITOR_PHP_FILE);
				iTer++;
			}   

			free(cArrReiv);
			remove(sReplayLogPath);
		} else {

			if( iSetDebug ) {
				printf("\n--> No request or not able to read replay.log (R:%i)",iArrCount);
			}

			free(cArrReiv);
	
		}

	}	

}


// ----------------------------------- Effectue la requete POST
void TUP_POSTRequest (char *cPrmPostRequest, char* cPrmPhpTargetFile) {
	char buffer[8192];
	char line[PACKET_SIZE+2];


	if( iSetVerboseLikeAWoman  ) { 

			sprintf(sTempLogLine,"(tupmdebug) HTTP Request target hostname : %s",request_host); 
			TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); 
			sprintf(sTempLogLine,"(tupmdebug) Entering DATA Post : Target = %s -> %s -> %i",cPrmPhpTargetFile,cPrmPostRequest,(int)strlen(cPrmPostRequest)); 
			TUPcWriteALineOfLog(sDebugLogPath,sTempLogLine); 
	}

	sprintf(line,"POST %s?username=%s HTTP/1.1\r\n"
	"Host: %s\r\n"
	"User-Agent: %s v%s.%s %s\r\n"
	"Accept: */*\r\n"
	"Content-Type: application/x-www-form-urlencoded\r\n"
	"Content-Length: %i\r\n"
	"\r\n"
	"%s"
	,cPrmPhpTargetFile,TUPUser,request_host,CLIENT_TYPE,CLIENTVERSION_MAJOR,CLIENTVERSION_MINOR,CLIENTVERSION_RELEASE,(int)strlen(cPrmPostRequest),cPrmPostRequest);

	// Uniquemenent en mode Debug, on affiche le detail de la requete
	if( iSetDebug ) {
	      printf("\n--> Full request details : \n\n");
	      printf("%s",line);
	      printf("\n -- end -- \n\n");
	}

	send(iSock_toBackend,line,strlen(line),0);	  
	
	int bytes_read;

	bzero(buffer, sizeof(buffer));
	bytes_read = recv(iSock_toBackend, buffer, sizeof(buffer), 0);

	if( iSetDebug ) {
		if ( bytes_read > 0 )
	    		printf("%s\n", buffer);
	}

}


// **************************************************************
// * Fonctions & procesures annexes --------------------------> *
// **************************************************************


// ----------------------------------- Recuperation de l adresse MAC
void tupGet_mac() {

	#ifdef GET_MACADDR_NUX

	struct ifreq *ifr, *ifend;
	struct ifreq ifreq;
	struct ifconf ifc;
	struct ifreq ifs[MAX_IFS];
	int SockFD;

	SockFD = socket(AF_INET, SOCK_DGRAM, 0);


	if( iSetDebug ) {
		printf("--> Network Interface list : \n");
		printf("-->");
	}

	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;

	if (ioctl(SockFD, SIOCGIFCONF, &ifc) < 0)
	{
		printf("[Error] Error getting Mac Address. Check interface name in TUP.conf...\n\n");
		exit(1);
	}

	ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));

	for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
	{
	if (ifr->ifr_addr.sa_family == AF_INET)
	{	

		strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));

		    if (ioctl (SockFD, SIOCGIFHWADDR, &ifreq) < 0)
		    {
		    	printf("SIOCGIFHWADDR(%s): %m\n", ifreq.ifr_name);
		    	exit(1);
		    } // fin if ioctl

		    if( iSetDebug ) {
		    	printf(" ( %s ) ", ifreq.ifr_name);
		    }

		if( !strcmp(ifreq.ifr_name,TUPInterface) ) {
			  
			  if( iSetDebug ) {
		    			printf("\n--> Getting Mac from : %s ",ifreq.ifr_name);
		    	  }
		    	  	
				  sprintf((char *)mac_addr,"%02x%02x%02x%02x%02x%02x",
			  (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[0],
			  (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[1],
			  (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[2],
			  (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[3],
			  (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[4],
			  (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[5]);
		} // fin if TUPInterface

	} else {
			printf("[Error] Error getting Mac Address. Check interface name in TUP.conf \n\n");
		exit(1);	
	}// fin if AF_INET

	} // fin for ifr

		    if( iSetDebug ) {
		    	printf("\n\n");
		    }
	#endif // Get Mac Addr Nux	

	#ifdef GET_MACADDR_BSD

	int			mib[6];
	size_t			len;
	char			*buf;
	unsigned char		*ptr;
	struct if_msghdr	*ifm;
	struct sockaddr_dl	*sdl;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;

	if ((mib[5] = if_nametoindex(TUPInterface)) == 0) {
		printf("[Error] Error getting Mac Address. Check interface name in TUP.conf...\n\n");
		exit(1);
	}

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
		printf("[Error] Error getting Mac Address. Check interface name in TUP.conf...\n\n");
		exit(1);
	}

	if ((buf = malloc(len)) == NULL) {
		printf("[Error] Error getting Mac Address. Check interface name in TUP.conf...\n\n");
		exit(1);
	}

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		printf("[Error] Error getting Mac Address. Check interface name in TUP.conf...\n\n");
		exit(1);
	}

	ifm = (struct if_msghdr *)buf;
	sdl = (struct sockaddr_dl *)(ifm + 1);
	ptr = (unsigned char *)LLADDR(sdl);
	sprintf((char *)mac_addr,"%02x%02x%02x%02x%02x%02x", *ptr, *(ptr+1), *(ptr+2),
			*(ptr+3), *(ptr+4), *(ptr+5));
	//free(len);
	#endif // Get Mac Addr Bsd

	#ifdef GET_MACADDR_SUN

	sprintf(mac_addr, "%lx", gethostid() );

	#endif // Get Mac Addr Sun
	
} // fin tupGet_mac 

// ----------------------------------- Hash MD5 de l adresse MAC
static int MD5MacAddr(void) {
	
	unsigned char *chrTxMacAddr = mac_addr;

	md5_state_t state;
	md5_byte_t digest[16];
	char hex_output[16*2 + 1];
	int di;
    
    	strcpy(mac_hash_result,"");
    
	if( iSetDebug ) {

		#ifdef GET_MACADDR_SUN
		printf("--> HOST ID (replacing MacAddress) : %s \n" , mac_addr);
		#else
		printf("--> Mac Address parameter : %s \n" , mac_addr);
		#endif

	}
    
	md5_init(&state);
	md5_append(&state, chrTxMacAddr, strlen((char*)chrTxMacAddr));
	md5_finish(&state, digest);
	for (di = 0; di < 16; ++di)
	    sprintf(hex_output + di * 2, "%02x", digest[di]);
	   
	strcpy(mac_hash_result,hex_output);
   

	if( iSetDebug ) {
		printf("--> MD5 hash of Mac Address : %s \n\n" , mac_hash_result);
	}

	return 0;

} // fin MD5MacAddr

// ----------------------------------- Recuperation du type de distrib linux 
void check_distro()
{
	char *FileList[13];
	char *ImgList[13];
	int iTer;

	FileList[0] = "/etc/debian_release";		ImgList[0] = "debian";
	FileList[1] = "/etc/debian_version";		ImgList[1] = "debian";
	FileList[2] = "/etc/lsb-release";               ImgList[2] = "ubuntu";
	FileList[3] = "/etc/SuSE-release";		ImgList[3] = "suse";
	FileList[4] = "/etc/UnitedLinux-release";	ImgList[4] = "suse";
	FileList[5] = "/etc/gentoo-release";		ImgList[5] = "gentoo";
	FileList[6] = "/etc/redhat-release";		ImgList[6] = "redhat";
	FileList[7] = "/etc/redhat_version";		ImgList[7] = "redhat";
	FileList[8] = "/etc/fedora-release";		ImgList[8] = "fedora";
	FileList[9] = "/etc/slackware-release";		ImgList[9] = "slackware";
	FileList[10] = "/etc/slackware-version";	ImgList[10] = "slackware";
	FileList[11] = "/etc/mandrake-release";		ImgList[11] = "mandrake";
	FileList[12] = "/etc/mandriva-release";		ImgList[12] = "mandriva";
	
	FILE *fp;
    	char line[1600];
	
	for( iTer = 0 ; iTer <= 12 ; iTer++) {
    	fp=fopen(FileList[iTer], "r");

    	if(fp==NULL) {
        	// printf("NULL\n");
    	} else {
    		if( iSetDebug ) {
    			printf("--> Distrib[%i] : %s \n" , iTer, ImgList[iTer]);
    		}
    		
    		chrDistro = ImgList[iTer];
    		bzero(chrDistroTempConcat,sizeof(chrDistroTempConcat));
    		
		while(!feof(fp)) {
			bzero(line, sizeof(line));
			sUnusedReturn = fgets(line,1600,fp);
			strcat(chrDistroTempConcat,line);
	        }
    	
    		if( iSetDebug ) {
    			printf("--> Distrib Content : %s \n" , chrDistroTempConcat);
    		}
    		
    		fclose(fp);
   
    	} // fin if fp
	} // end for iTer

#	ifdef GET_UPTIME_BSD
    	    chrDistro = DISTRO;
#   endif
    	    
#	ifdef GET_UPTIME_UTMPX
    	    chrDistro = DISTRO;
#   endif

#	ifdef SET_DISTRO_ESX
    	    chrDistro = DISTRO;
#   endif	


    
}



// ----------------------------------- Get Uptime (diffÔøΩrent suivant les versions OS
void get_uptime() { 
	  /* NetBSD, FreeBSD, OpenBSD and MacOS X */
#	ifdef GET_UPTIME_BSD
		time_t uptime;
	   	int mib[2];
	  	size_t size;

	  	struct timeval boottime;

	  	time_t now;

	  	mib[0] = CTL_KERN;
	  	mib[1] = KERN_BOOTTIME;
	  	size = sizeof(boottime);

	  	time(&now);

	  	if( sysctl(mib, 2, &boottime, &size, NULL, 0) != -1 ) {
	  		if( boottime.tv_sec != 0 ) {
	  			uptime = now - boottime.tv_sec;
	  			uptime += 30;
	  		} else {
	  	    	printf("[Error] Error getting uptime...\n\n");
	  	    	exit(1);
	  		}
	  	}
	  	
	  	sprintf(sUptime,"%ld",(long)uptime);
# endif // END GET_UPTIME_BSD

	  /* Linux */
# ifdef GET_UPTIME_NUX
	    // Recup de la struct sysinfo qui va permettre de recup le uptime via si.uptime
	  	struct sysinfo si;
	          sysinfo (&si);
	          
	  sprintf(sUptime,"%ld",si.uptime);
	          
# endif // END GET_UPTIME_NUX 	

/* Solaris and HP/UX */
# ifdef GET_UPTIME_UTMPX
	 
		time_t uptime;
		
	  	/* Extract uptime from utmpx */
	  	struct utmpx id;
	  	struct utmpx* u;

	  	/* Rewind utmpx entry pointer */
	  	setutxent();

	  	id.ut_type = BOOT_TIME;
	  	u = getutxid(&id);

	  	if( u == NULL ) {
  	    	printf("[Error] Error getting uptime...\n\n");
  	    	exit(1);
	  	}

	  	uptime = time(NULL) - u->ut_tv.tv_sec;
	  	
		sprintf(sUptime,"%ld",(long)uptime);
		
# endif // END GET_UPTIME_UTMPX
} //

int get_cpucount() {

	long ldCpu_count = 0;

# ifdef GET_CPUCOUNT_NUXLIKE
	  // seems working on Linux platform _SC_NPROCESSORS_CONF = cpu count, return -1 if fail
	  if( (ldCpu_count = sysconf(_SC_NPROCESSORS_CONF)) < 0 ) {
		  ldCpu_count = 1;
	  } else {
		  ldCpu_count = sysconf(_SC_NPROCESSORS_CONF);
	  }
# endif // END GET_CPUCOUNT_NUXLIKE	

# ifdef GET_CPUCOUNT_DARWINLIKE
	   size_t len = 2;  
	   int mib[len];
	   const char *s = "hw.ncpu";
	   int val = -1;
	   size_t len_mib = sizeof(int);
	   
	   mib[0] = CTL_HW;  
	   mib[1] = HW_NCPU;  

	   sysctlnametomib( s, mib, &len );  

	   if ( sysctl( mib, len, &(val), &(len_mib), NULL, 0) == -1 ) {  
		   ldCpu_count = 1;
	   } else {  
		   ldCpu_count = val;  
	   }  
# endif // END GET_CPUCOUNT_DARWINLIKE	

	   return ldCpu_count;
	   
 } // END CPU COUNT	

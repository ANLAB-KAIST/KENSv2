#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MODE_SINGLE_PROCESS	0
#define MODE_MULTI_PROCESSES	1

typedef enum {
	FALSE = 0,
	TRUE = 1
} BOOL;

/*********************************************************************/
/* server configurations */
/*********************************************************************/
static int mode = MODE_SINGLE_PROCESS;

static BOOL no_log = FALSE;

/*********************************************************************/
/* socket library */
/*********************************************************************/

int socket_server_init(int port)
{
	int sd;
	struct sockaddr_in server;
	const int one = 1;

	if ( (sd = ksocket(AF_INET,SOCK_STREAM,0)) < 0 ) return -1;

	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);

	/*
	if ( setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
			(char *)&one, sizeof(one)) == -1 ) {
		return -1;
	}*/

	if ( kbind(sd,(struct sockaddr *)&server,sizeof(server)) < 0 ) {
		return -1;
	}

	if ( klisten(sd,5) < 0 ) return -1;

	return sd;
}

int socket_server_wait(int sd)
{
	int nsd,clientlen;
	struct sockaddr_in client;
	unsigned char *p;

	clientlen = sizeof(client);

	fprintf(stderr,"wait for client...\n");

	do {
		nsd = kaccept(sd,(struct sockaddr *)&client, &clientlen);
	} while ( nsd <= 0 );

	p = (unsigned char *)&client.sin_addr;

	return nsd;
}


/*********************************************************************/
/* core daemon */
/*********************************************************************/

static void sighandle_SIGCHLD(int arg)
{
	pid_t pid;
	int status;

	while (1) {
		pid = waitpid(-1,&status,WNOHANG);
		
		if ( pid == 0 ) {
			/* no dead children, but some live ones */
			break;
		} else if ( pid == -1 && errno == ECHILD ) {
			/* no more children, dead or running */
			break;
		}
	}

	signal(SIGCHLD, sighandle_SIGCHLD);
}

void serve(int sd)
{
	int n;
	char buf[8192];
	struct sockaddr_in name;
	int name_len = sizeof(struct sockaddr_in);

	/*
	kgetsockname(sd,&name,&name_len);
	fprintf(stderr,"my connection %s:%d\n",
			inet_ntoa(name.sin_addr),ntohs(name.sin_port)
	);
	*/
	kgetpeername(sd,&name,&name_len);
	fprintf(stderr,"start to serve connection from %s:%d\n",
			inet_ntoa(name.sin_addr),ntohs(name.sin_port)
	);


	while ( kreadline(sd,buf,8192) > 0 ) {
		if ( !no_log )
			fprintf(stderr,"[%s:%d] %s",
					inet_ntoa(name.sin_addr),ntohs(name.sin_port),buf);
		kwrite(sd,buf,strlen(buf));
	}

	fprintf(stderr,"[%s:%d] EOF\n",
			inet_ntoa(name.sin_addr),ntohs(name.sin_port));

	kclose(sd);
}

void echo_daemon(int sock)
{
	pid_t pid;
	int sd;

	if ( mode == MODE_MULTI_PROCESSES ) 
		signal(SIGCHLD, sighandle_SIGCHLD);

	while (1) {
		if ( (sd = socket_server_wait(sock)) < 0 ) {
			goto cleanup;
		}

		if ( mode == MODE_MULTI_PROCESSES ) {
			if ( (pid = fork()) > 0 ) {
				/* let it go */
				goto cleanup;
			} else if ( pid < 0 ) {
				/* failed to fork */
			} else {
				/* just let it go */
			}
		}

		/* handle request */
		serve(sd);

cleanup:
		if ( mode == MODE_MULTI_PROCESSES && pid == 0 ) break;
	}
}


static void print_usage(char *prog)
{
	fprintf(stderr,"%s [-s|-m|-q|-p port|-d dir|-l flie|-e file]\n",prog);
	fprintf(stderr," -q      : run in no logging mode\n");
	fprintf(stderr," -s      : run in single process mode\n");
	fprintf(stderr," -m      : run in multi processes mode\n");
	fprintf(stderr," -p port : listen port\n");
}


int main(int argc,char *argv[])
{
	BOOL badops = FALSE;
	pid_t pid;
	struct stat st;
	int sd;
	char *progname = argv[0];

	int port = 9729;

	/* parse parameters */
	argc--;
	argv++;

	while ( argc >= 1 ) {
		if ( strcmp(*argv,"-p") == 0 ) {
			if ( --argc < 1 ) goto bad;
			port = atoi(*(++argv));
		} else if ( strcmp(*argv,"-q") == 0 ) {
			no_log = TRUE;
		} else if ( strcmp(*argv,"-s") == 0 ) {
			mode = MODE_SINGLE_PROCESS;
		} else if ( strcmp(*argv,"-m") == 0 ) {
			mode = MODE_MULTI_PROCESSES;
		} else {
bad:
			fprintf(stderr,"unknown option %s\n",*argv);
			badops = TRUE;
			break;
		}
		argc--;
		argv++;
	}

	if ( badops ) {
		print_usage(progname);
		exit(1);
	}

	/* intialize server sock */
	if ( (sd = socket_server_init(port)) < 0 ) {
		perror("Fail : initialize server socket");
		exit(1);
	}

/*	if ( (pid = fork()) < 0 ) {
		perror("Fail : fork core daemon");
	} else if ( pid == 0 ) {
		umask(0177);

		pid = getpid();

		if ( setsid() < 0 ) {
			perror("Fail : become session leader");
			goto shutdown;
		}*/

		echo_daemon(sd);
	/*}*/

shutdown:
	if ( mode == MODE_SINGLE_PROCESS && sd > 0 ) kclose(sd);

	return 0;
}

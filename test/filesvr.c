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

typedef enum {
	FALSE = 0,
	TRUE = 1
} BOOL;

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

	/*do {*/
		nsd = kaccept(sd,(struct sockaddr *)&client, &clientlen);
	/*} while ( nsd <= 0 );*/

	p = (unsigned char *)&client.sin_addr;

	return nsd;
}


/*********************************************************************/
/* core daemon */
/*********************************************************************/

void serve(int sd, int fd)
{
	int len, file_len, total;
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

	/*
	fprintf(stderr,"file transferring...");

	while ( (n=read(fd,buf,8192)) > 0 ) {
		fprintf(stderr, "n:%d\n", n);
		kwrite(sd,buf,n);
	}*/

	total = 0;
	kread(sd,buf,sizeof(buf));
	file_len = atoi(buf);

	while ( (len=kread(sd,buf,sizeof(buf))) > 0 ) {
		total += len;
		fprintf(stderr, "%d/%d bytes received.\n", total, file_len);
		write(fd,buf,len);
		if(total >= file_len) break;
	}

	kwrite(sd,"OK",3);
	fprintf(stderr,"complete!\n");

	kclose(sd);
}

void echo_daemon(int sock, int fd)
{
	pid_t pid;
	int sd;

	/*
	while (1) {
		if ( (sd = socket_server_wait(sock)) < 0 ) {
			goto cleanup;
		}*/

		sd = socket_server_wait(sock);

		/* handle request */
		serve(sd, fd);
/*
cleanup:
		if ( pid == 0 ) break;
	}*/
}


static void print_usage(char *prog)
{
	fprintf(stderr,"%s [-p port|-f file]\n",prog);
	fprintf(stderr," -p port : listen port\n");
	/*fprintf(stderr," -f file : file to transfer\n");*/
}


int main(int argc,char *argv[])
{
	BOOL badops = FALSE;
	pid_t pid;
	struct stat st;
	int sd;
	int fd;
	char *progname = argv[0];
	char *filename;

	int port = 9730;

	/* parse parameters */
	argc--;
	argv++;

	while ( argc >= 1 ) {
		if ( strcmp(*argv,"-p") == 0 ) {
			if ( --argc < 1 ) goto bad;
			port = atoi(*(++argv));
		/*} else if ( strcmp(*argv,"-f") == 0 ) {
			if ( --argc < 1 ) goto bad;
			filename = *(++argv);*/
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

	fd = open("rcvfile", O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		perror("Fail : open file to transfer");
		exit(1);
	}

	/* intialize server sock */
	if ( (sd = socket_server_init(port)) < 0 ) {
		perror("Fail : initialize server socket");
		exit(1);
	}

	echo_daemon(sd, fd);

shutdown:
	if ( sd > 0 ) kclose(sd);
	close(fd);

	return 0;
}

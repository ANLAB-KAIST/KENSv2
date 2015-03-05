#include <stdio.h>

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "ksocket.h"

#define BUF_SIZE	8192

void print_usage(char *prog)
{
	fprintf(stderr,"Usage %s ip_address:port\n",prog);
}


int main(int argc,char *argv[])
{
	int sd,len;
	char *progname = argv[0];
	char *opt,*p;
	struct sockaddr_in sin;
	char snd_buf[BUF_SIZE],rcv_buf[BUF_SIZE];

	if ( argc != 2 ) {
		print_usage(progname);
		exit(1);
	}

	opt = strdup(argv[1]);
	p = strchr(opt,':');
	if ( p == NULL ) {
		print_usage(progname);
		exit(1);
	}
	*p = '\0';

	memset(&sin,0x00,sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(p+1));
	if ( !inet_aton(opt,&sin.sin_addr) ) {
		print_usage(progname);
		exit(1);
	}

	if ( (sd = ksocket(AF_INET,SOCK_STREAM,0)) <= 0 ) {
		perror("ksocket");
		exit(1);
	}
	if ( kconnect(sd,(struct sockaddr *)&sin,sizeof(sin)) < 0 ) {
		perror("kconnect");
		exit(1);
	}

	printf("connected to echo server which runs on KENS\n");

	while ( fgets(snd_buf,BUF_SIZE,stdin) != NULL ) {
		/*printf("\"%s\"\n",snd_buf);*/

		len = kwrite(sd,snd_buf,strlen(snd_buf));
		/*printf("%d bytes were sent\n",len);*/

		len = kreadline(sd,rcv_buf,sizeof(rcv_buf));
		if ( len > 0 )
			printf("[%s:%d] %s",
					inet_ntoa(sin.sin_addr),ntohs(sin.sin_port),rcv_buf);
		else {
			printf("connection closed by foriegn host\n");
			break;
		}
	}

	kclose(sd);

	return 0;
}

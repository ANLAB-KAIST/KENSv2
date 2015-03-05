#include <stdio.h>

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ksocket.h"

#define BUF_SIZE	8192

void print_usage(char *prog)
{
	fprintf(stderr,"Usage %s ip_address:port filename\n",prog);
}


int main(int argc,char *argv[])
{
	int sd,len,file_len,total;
	char *progname = argv[0];
	char *opt,*p;
	struct sockaddr_in sin;
	char snd_buf[BUF_SIZE],rcv_buf[BUF_SIZE];
	FILE *fp;

	if ( argc != 3 ) {
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

	fp = fopen(argv[2], "rb");
	if (fp == NULL) {
		perror("Fail: file open");
		exit(1);
	}

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

	printf("connected to file server which runs on KENS\n");

	/*
	while ( (len=kread(sd,rcv_buf,sizeof(rcv_buf))) > 0 ) {

		fprintf(stderr, "len=%d\n", len);
		write(fd,rcv_buf,len);
	}*/

	total = 0;
	fseek(fp, 0, SEEK_END);
	file_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	sprintf(snd_buf, "%d", file_len);
	kwrite(sd,snd_buf,strlen(snd_buf));
	sleep(1);

	while( (len=fread(snd_buf,1,8192,fp)) > 0 ) {
		total += len;
		fprintf(stderr, "%d bytes transferred.\n", total);
		kwrite(sd,snd_buf,len);
	}

	fprintf(stderr, "transferring complete.\n");
	while( (len=kread(sd,rcv_buf,8192)) > 0 );
	sleep(1);
	fprintf(stderr, "connection closed.\n");

	kclose(sd);
	fclose(fp);

	return 0;
}

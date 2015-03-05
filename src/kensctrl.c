#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "ksocket.h"


void print_usage(char *prog)
{
	fprintf(stderr,"Usage: %s get OPTNAME [OPTVALUE]\n", prog);
	fprintf(stderr,"          set OPTNAME OPTVALUE\n");
	fprintf(stderr,"Examples:\n");
	fprintf(stderr,"	get delay\n");
	fprintf(stderr,"	get drop_rate\n");
	fprintf(stderr,"	get reorder_rate\n");
	fprintf(stderr,"	get enable_seth 0\n");
	fprintf(stderr,"	get disable_seth 1\n");
	fprintf(stderr,"	get krip_update_interval\n");
	fprintf(stderr,"	get krip_timeout\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"	set delay 500\n");
	fprintf(stderr,"	set drop_rate 0.1\n");
	fprintf(stderr,"	set reorder_rate 0.2\n");
	fprintf(stderr,"	set enable_seth 0\n");
	fprintf(stderr,"	set disable_seth 1\n");
	fprintf(stderr,"	set krip_update_interval 3000\n");
	fprintf(stderr,"	set krip_timeout 10000\n");
}


int main(int argc,char *argv[])
{
	char *progname = argv[0];
	int isget;
	int optname;
	char optval[4];
	int optlen = sizeof(optval);

	if (argc < 3 || argc > 4) {
		print_usage(progname);
		exit(1);
	}

	if (strcmp(argv[1], "get") == 0)
		isget = 1;
	else if (strcmp(argv[1], "set") == 0 && argc == 4)
		isget = 0;
	else {
		print_usage(progname);
		exit(1);
	}

	if (strcmp(argv[2], "delay") == 0)
	{
		optname = KO_DL_DELAY;
		if (!isget)
			*(int*)optval = atoi(argv[3]);
	}
	else if (strcmp(argv[2], "drop_rate") == 0)
	{
		optname = KO_DL_DROP_RATE;
		if (!isget)
			*(float*)optval = atof(argv[3]); 
	}
	else if (strcmp(argv[2], "reorder_rate") == 0)
	{
		optname = KO_DL_REORDER_RATE;
		if (!isget)
			*(float*)optval = atof(argv[3]);
	}
	else if (strcmp(argv[2], "enable_seth") == 0)
	{
		optname = KO_DL_ENABLE_SETH;
		if (argc != 4) {
			print_usage(progname);
			exit(1);
		}
		*(int*)optval = atoi(argv[3]);
	}
	else if (strcmp(argv[2], "disable_seth") == 0)
	{
		optname = KO_DL_DISABLE_SETH;
		if (argc != 4) {
			print_usage(progname);
			exit(1);
		}
		*(int*)optval = atoi(argv[3]);
	}
	else if (strcmp(argv[2], "krip_update_interval") == 0)
	{
		optname = KO_KRIP_UPDATE_INTERVAL;
		if (!isget)
			*(int*)optval = atoi(argv[3]);
	}
	else if (strcmp(argv[2], "krip_timeout") == 0)
	{
		optname = KO_KRIP_TIMEOUT;
		if (!isget)
			*(int*)optval = atoi(argv[3]);
	}
	else {
		print_usage(progname);
		exit(1);
	}

	if (isget)
	{
		if (kgetkensopt(optname, optval, &optlen) == 0)
		{
			switch (optname)
			{
				case KO_DL_DELAY:
					printf("delay: %d\n", *(int*)optval);
					break;
				case KO_DL_DROP_RATE:
					printf("drop_rate: %f\n", *(float*)optval);
					break;
				case KO_DL_REORDER_RATE:
					printf("reorder_rate: %f\n", *(float*)optval);
					break;
				case KO_DL_ENABLE_SETH:
					printf("enable_seth: %d\n", *(int*)optval);
					break;
				case KO_DL_DISABLE_SETH:
					printf("disable_seth: %d\n", *(int*)optval);
					break;
				case KO_KRIP_UPDATE_INTERVAL:
					printf("krip_update_interval: %d\n", *(int*)optval);
					break;
				case KO_KRIP_TIMEOUT:
					printf("krip_timeout: %d\n", *(int*)optval);
					break;
			}
		}
		else
			printf("failed\n");
	}
	else
	{
		if (ksetkensopt(optname, optval, optlen) == 0)
			printf("ok\n");
		else
			printf("failed\n");
	}

	return 0;
}


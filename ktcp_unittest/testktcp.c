/*
 * testktcp.c
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */


#include <stdio.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include "ktcp_easy_impl.h"
#include "ktcp_easy_lib.h"
#include <arpa/inet.h>
#include "testktcp.h"
#include "ktcp_test_lib.h"
#include <unistd.h>
#include <signal.h>
#include <wait.h>
#include <time.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define DO_TEST(func) doTest(func, #func)

extern int __ref_boundary_on;
extern int __cc;

static int use_ref_for_target = 0;
static int use_target_for_ref = 0;
static int create_report = 0;
static int timeout = 10;

ktcp_easy_impl* __target;
ktcp_easy_impl* __reference;
ktcp_easy_lib* __target_env;
ktcp_easy_lib* __reference_env;

ktcp_easy_impl* reference_startup(ktcp_easy_lib* lib);
ktcp_easy_impl* my_startup(ktcp_easy_lib* lib);

static int final_return = 0;

static int init_framework(void)
{
	__test_lib_init();
	__target_env = __create_test_instance(false);
	__reference_env = __create_test_instance(true);

	if(use_ref_for_target)
		__target = reference_startup(__target_env);
	else
		__target = my_startup(__target_env);
	if(use_target_for_ref)
		__reference = my_startup(__reference_env);
	else
		__reference = reference_startup(__reference_env);

	return 0;
}

static int close_framework(void)
{
	__target->shutdown(__target);
	__reference->shutdown(__reference);
	__free_test_instance(__target_env);
	__free_test_instance(__reference_env);
	__test_lib_shutdown();
	return 0;
}

typedef void (*testFunction) (const char* name) ;

static int pid=-1;

static void sighandler(int sig)
{
	alarm(0);
	kill(pid, SIGINT);
	printf("TEST TIMEOUT\n");
	fflush(stdout);
}

CU_Suite* currentSuite;

static void doTest(testFunction func, const char* name)
{

	FILE* __past_stdout = NULL;
	if(create_report)
	{
		__past_stdout = stdout;
		char buf[128];
		sprintf(buf, "%s.report", name);
		stdout = fopen(buf, "w");
	}
	int ret = 0;
	fflush(stdout);
#ifdef USE_FORK
	if((pid = fork()) == 0)
	{
#endif
		CU_initialize_registry();
		printf("-----------------------------------------------------------\n");
		printf("Starting %s\n", name);
		fflush(stdout);

		func(name);
		CU_basic_set_mode(CU_BRM_VERBOSE);

		CU_basic_run_tests();

		printf("%s: progress = %d/%d\n",
				currentSuite->pName,
				currentSuite->uiNumberOfTests
				- CU_get_number_of_tests_failed(),
				currentSuite->uiNumberOfTests);
		ret = CU_get_number_of_tests_failed();
		CU_cleanup_registry();
		printf("-----------------------------------------------------------\n");
		fflush(stdout);

#ifdef USE_FORK
		exit(ret);
	}
	else
	{
		alarm(timeout);
		waitpid(pid, &ret, 0);
#endif
		if(ret != 0)
		{
			printf("Fail!\n");
			final_return++;
		}
		else
			printf("Success!\n");
#ifdef USE_FORK
	}
#endif
	if(create_report)
	{
		fclose(stdout);
		stdout = __past_stdout;
	}
}


static void testOpen(const char* name)
{
	currentSuite = CU_add_suite(name, init_framework, close_framework);
	CU_ADD_TEST(currentSuite, __testOpen);
}

static void testBind(const char* name)
{
	currentSuite = CU_add_suite(name, init_framework, close_framework);
	CU_ADD_TEST(currentSuite,  __testBind_Simple);
	CU_ADD_TEST(currentSuite,  __testBind_GetSockName);
	CU_ADD_TEST(currentSuite,  __testBind_DoubleBind);
	CU_ADD_TEST(currentSuite,  __testBind_OverlapPort);
	CU_ADD_TEST(currentSuite,  __testBind_OverlapClosed);
	CU_ADD_TEST(currentSuite,  __testBind_DifferentIP_SamePort);
	CU_ADD_TEST(currentSuite,  __testBind_SameIP_DifferentPort);
}

static void testConnect(const char* name)
{
	currentSuite = CU_add_suite(name, init_framework, close_framework);
	CU_ADD_TEST(currentSuite,  __testConnect_Simple_Default_IP);
	CU_ADD_TEST(currentSuite,  __testConnect_Simple_Second_IP);
	CU_ADD_TEST(currentSuite,  __testConnect_Simultaneous);
}

static void testListen(const char* name)
{
	currentSuite = CU_add_suite(name, init_framework, close_framework);

	CU_ADD_TEST(currentSuite,  __testListen_Accept_Before_Connect);
	CU_ADD_TEST(currentSuite,  __testListen_Accept_After_Connect);
	CU_ADD_TEST(currentSuite,  __testListen_Accept_Multiple);
	CU_ADD_TEST(currentSuite,  __testListen_Multiple_Interfaces);
}

static void testClose(const char* name)
{
	currentSuite = CU_add_suite(name, init_framework, close_framework);

	CU_ADD_TEST(currentSuite,  __testClose_Passive_Close_First);
	CU_ADD_TEST(currentSuite,  __testClose_Passive_Close_Later);
	CU_ADD_TEST(currentSuite,  __testClose_Active_Close_First);
	CU_ADD_TEST(currentSuite,  __testClose_Active_Close_Later);
}

static void testTransfer(const char* name)
{
	currentSuite = CU_add_suite(name, init_framework, close_framework);

	CU_ADD_TEST(currentSuite,  __testTransfer_Passive_Close_First_Send);
	CU_ADD_TEST(currentSuite,  __testTransfer_Passive_Close_Later_Send);
	CU_ADD_TEST(currentSuite,  __testTransfer_Active_Close_First_Send);
	CU_ADD_TEST(currentSuite,  __testTransfer_Active_Close_Later_Send);

	CU_ADD_TEST(currentSuite,  __testTransfer_Passive_Close_First_Receive);
	CU_ADD_TEST(currentSuite,  __testTransfer_Passive_Close_Later_Receive);
	CU_ADD_TEST(currentSuite,  __testTransfer_Active_Close_First_Receive);
	CU_ADD_TEST(currentSuite,  __testTransfer_Active_Close_Later_Receive);
}

static void help(const char* name)
{
	printf("Usage : %s options\n", name);
	printf("--seed -s [seed]\n"
			"--source -S [my|reference]\n"
			"--reference -R [my|reference]\n"
			"--report -r\n"
			"--unreliable -U\n"
			"--timeout -t [second]\n"
			"--drop-rate [num/1000]\n"
			"--reorder-rate [num/1000]\n"
			"--duplicate-rate [num/1000]\n"
			"--corruption-rate [num/1000]\n"
			"--boundary -b\n"
			"--network-delay -d [net delay in ms]\n"
			"--help\n");
	exit(1);
}

int main(int argc, char** argv)
{
	static int long_opt;
	int option_index;
	int seed = 0;
	static struct option long_options[] =
	{
			{"seed", required_argument,        0, 's'},
			{"source", required_argument,       0, 'S'},
			{"reference",   required_argument,       0, 'R'},
			{"report",  no_argument,  0, 'r'},
			{"unreliable",  no_argument,  0, 'U'},
			{"timeout",  required_argument,  0, 't'},
			{"boundary",  required_argument,  0, 'b'},
			{"drop-rate",  required_argument,  &long_opt, 1},
			{"reorder-rate",  required_argument,  &long_opt, 2},
			{"duplicate-rate",  required_argument,  &long_opt, 3},
			{"corruption-rate",  required_argument,  &long_opt, 4},
			{"network-delay",  required_argument,  0, 'd'},
			{"congestion-control",  no_argument,  0, 'c'},
			{0, 0, 0, 0}
	};


	while (1)
	{
		long_opt = 0;
		int c = getopt_long (argc, argv, "s:S:R:rUt:bd:c",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		if(long_opt)
		{
			switch(long_opt)
			{
			case 1:
				__drop_rate_1000 = atoi(optarg);
				printf("drop_rate:%d/1000\n", __drop_rate_1000);
				break;
			case 2:
				__reorder_rate_1000 = atoi(optarg);
				printf("reorder_rate:%d/1000\n", __reorder_rate_1000);
				break;
			case 3:
				__duplicate_rate_1000 = atoi(optarg);
				printf("duplicate_rate:%d/1000\n", __duplicate_rate_1000);
				break;
			case 4:
				__corruption_rate_1000 = atoi(optarg);
				printf("corruption_rate:%d/1000\n", __corruption_rate_1000);
				break;
			}
		}
		else
		{
			switch (c)
			{
			case 0:
				break;

			case 's':
				seed = atoi(optarg);
				break;

			case 'S':
				if(strcmp(optarg, "reference") == 0 || strcmp(optarg, "ref") == 0)
				{
					printf("using reference solution as the testing target.\n");
					use_ref_for_target = 1;
				}
				else if(strcmp(optarg, "my") == 0)
				{
					printf("using my solution as the testing target.\n");
					use_ref_for_target = 0;
				}
				else
				{
					printf("Unknown source %s, using my solution as the testing target.\n", optarg);
					use_ref_for_target = 0;
				}
				break;
			case 't':
			{
				int new_timeout = atoi(optarg);
				if(new_timeout > 0)
					timeout = new_timeout;
				break;
			}

			case 'U':
				__unreliable = 1;
				printf("unreliable_mode\n");
				break;

			case 'R':
				if(strcmp(optarg, "reference") == 0 || strcmp(optarg, "ref") == 0)
				{
					printf("using reference solution as the testing reference.\n");
					use_target_for_ref = 0;
				}
				else if(strcmp(optarg, "my") == 0)
				{
					printf("using my solution as the testing reference.\n");
					use_target_for_ref = 1;
				}
				else
				{
					printf("Unknown source %s, using reference solution as the testing reference.\n", optarg);
					use_target_for_ref = 0;
				}
				break;
			case 'r':
				printf("report creation mode.\n");
				create_report = 1;
				break;
			case 'b':
				printf("boundary value mode.\n");
				__ref_boundary_on = 1;
				break;
			case 'd':
			{
				int net_delay = atoi(optarg);
				printf("network delay: %dms.\n", net_delay);
				__network_delay = net_delay;
				break;
			}
			case 'c':
			{
				printf("congestion control: on\n");
				__cc = 1;
				break;
			}
			default:
				help(argv[0]);
			}
		}
	}


	if(seed)
	{
		srand(seed);
		printf("using random seed %d.\n", seed);
	}
	else
	{
		seed = time(0);
		srand(seed);
		printf("using random seed with current_time: %d.\n", seed);
	}
	signal(SIGALRM, sighandler);

	DO_TEST(testOpen);
	DO_TEST(testBind);
	DO_TEST(testConnect);
	DO_TEST(testListen);
	DO_TEST(testClose);
	DO_TEST(testTransfer);

	return final_return;
}

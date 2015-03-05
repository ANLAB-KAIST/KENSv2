/*
 * ktcp_test_lib.h
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */

#ifndef KTCP_TEST_LIB_H_
#define KTCP_TEST_LIB_H_

#include "ktcp_easy_lib.h"
#include "testktcp.h"
#include "linked_list.h"

extern int __unreliable;
extern int __drop_rate_1000;
extern int __reorder_rate_1000;
extern int __duplicate_rate_1000;
extern int __corruption_rate_1000;
extern int __network_delay;
#define __REORDER_STEP 3

void __test_lib_init(void);
void __test_lib_shutdown(void);

typedef struct app_t
{
	my_context ctx;
	ktcp_easy_impl* impl;
	int is_open;
	int active_open_calls;
	list passive_open_calls;
	list error_msg;
	void* app_data;
	int app_data_len;
}application;

typedef struct timer_t
{
	int wakeup_time;
	my_context ctx;
	ktcp_easy_impl* impl;
}timer;

extern int now;

application* __find_app(ktcp_easy_impl* impl, my_context ctx);
timer* __find_timer(ktcp_easy_impl* impl, my_context ctx);
void __close_app(application* app);

ktcp_easy_lib* __create_test_instance(bool isReference);

void __free_test_instance(ktcp_easy_lib* target);

void __register_ip(ktcp_easy_lib* instance, uint32_t listen_ip);

void __init_pcap_record(const char* file_header);

void __pcap_close(void);

int __flush_packets(int limit_input);

#endif /* KTCP_TEST_LIB_H_ */

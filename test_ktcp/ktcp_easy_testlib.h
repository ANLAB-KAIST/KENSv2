/*
 * ktcp_easy_testlib.h
 *
 *  Created on: 2013. 7. 19.
 *      Author: leeopop
 */

#ifndef KTCP_EASY_TESTLIB_H_
#define KTCP_EASY_TESTLIB_H_

#define __FAVOR_BSD
#include <stddef.h>
#include "../src/ktcp_easy_impl.h"
#include "../src/ktcp_easy_lib.h"
#include <arpa/inet.h>
#include "../src/linked_list.h"
#include <stdlib.h>
#include <errno.h>
#include <memory.h>

#define RETURN_MAGIC 0 //0xD60DDC7 //224452039
#define MULTIPLE_COUNT 30000
#define DEFAULT_IP "143.248.234.1"
#define SECOND_IP "10.0.0.1"
#define THIRD_IP "192.168.0.1"
#define CLIENT_IP "110.76.78.99"
#define DEFAULT_CLIENT_IP "143.248.234.2"
#define SECOND_CLIENT_IP "10.0.0.3"
#define THIRD_CLIENT_IP "192.168.0.4"
#define SUBNET_MASK "255.255.255.0"
#define DEFAULT_WINDOW 3072

#if !defined(__bool_defined) && !defined(__cplusplus) && !defined(c_plusplus)
	#define __bool_defined
	typedef char bool;
	#define false	(0)
	#define true	(1)
#endif

typedef struct app_data_t
{
	size_t data_len;
	char data[0];
}app_data;

typedef struct ip_packet_t
{
	uint32_t src;
	uint32_t dest;
	size_t data_len;
	char data[0];
}ip_packet;

typedef struct timer_t
{
	int mtime;
	my_context ctx;
}timer;

typedef struct app_t
{
	my_context ctx;
	int is_open;
	int mtime;
	int timer_set;
	int active_open_calls;
	list passive_open_calls;
	list tcp_to_app;
	list error_msg;
}application;

extern const char* pcap_filename;

extern uint32_t default_ip;
extern uint32_t second_ip;
extern uint32_t third_ip;
extern uint32_t subnet_mask;
extern struct in_addr default_addr;
extern struct in_addr second_addr;
extern struct in_addr third_addr;
extern uint32_t default_client_ip;
extern uint32_t second_client_ip;
extern uint32_t third_client_ip;
extern struct in_addr default_client_addr;
extern struct in_addr second_client_addr;
extern struct in_addr third_client_addr;
extern struct in_addr client_addr;
extern uint32_t client_ip;

extern list tcp_to_ip;
extern list app_open;
extern int now;

extern void _ktcp_testlib_init(void);

extern application* find_app(my_context ctx);

extern application* create_app();
extern void close_app(application* app);

extern uint32_t ip_host_address(struct in_addr target);

extern int tcp_dispatch_ip(struct in_addr src_addr, struct in_addr dest_addr, void * data, size_t data_size);

extern int tcp_dispatch_app(my_context handle, const void* data, size_t data_size);

extern bool tcp_passive_open(my_context server_handle, my_context new_handle);

extern bool tcp_active_open(my_context handle);

extern int tcp_get_mtime();

extern bool tcp_register_timer(my_context context, int mtime);

extern void tcp_unregister_timer(my_context context);

extern void tcp_shutdown_app(my_context handle);

extern void ktcp_error(const char* fmt, ...);

extern void print(const char* fmt, ...);

extern uint16_t tcp_checksum(struct in_addr source, struct in_addr dest, const void* data, uint16_t length);

extern int auto_ack(uint32_t source, uint32_t destination, uint32_t seq);

extern void test_ip_dispatch_tcp(struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size);

#endif /* KTCP_EASY_TESTLIB_H_ */

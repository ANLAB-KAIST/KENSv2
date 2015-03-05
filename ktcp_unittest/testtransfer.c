/*
 * testtransfer.c
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */


#include "testktcp.h"
#include <memory.h>

#define DATA_SIZE 1024*1024

static void __testClose(ktcp_easy_impl* first_impl, my_context first, ktcp_easy_impl* second_impl, my_context second)
{
	int err = 0;

	first_impl->close(first_impl, first, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	__flush_packets(100);

	second_impl->close(second_impl, second, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	__flush_packets(100);
}

static void* generate_random(int size)
{
	char* ret = malloc(size);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ret);
	int k;
	for(k=0; k<size; k++)
		ret[k] = (char)rand();
	return ret;
}

static void __testTransfer(ktcp_easy_impl* source_impl, my_context source, void* data, int len)
{
	int remaining = len;
	void* current = data;
	while(remaining > 0)
	{
		int current_send =  (1024 < remaining) ? 1024 : remaining;
		int sent = source_impl->app_dispatch_tcp(source_impl, source, current, current_send);
		if(sent < 0)
			break;
		current += sent;
		remaining -= sent;
		if(sent == 0)
			__flush_packets(DATA_SIZE);
	}
	__flush_packets(DATA_SIZE);
}


void __testTransfer_Passive_Close_First_Send()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");


	ret = __target->accept(__target, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->connect(__reference, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__reference, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__target, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = clientApp;
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__target, server_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__target, server_socket, __reference, client_socket);
	__pcap_close();
}

void __testTransfer_Passive_Close_Later_Send()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10000);

	ret = __target->bind(__target, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");


	ret = __target->accept(__target, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->connect(__reference, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__reference, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__target, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = clientApp;
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__target, server_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__reference, client_socket, __target, server_socket);

	__pcap_close();
}

void __testTransfer_Active_Close_First_Send()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10001);

	ret = __reference->bind(__reference, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->listen(__reference, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.200");


	ret = __reference->accept(__reference, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->connect(__target, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__target, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__reference, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = __find_app(__reference, server_socket);
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__target, client_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__target, client_socket, __reference, server_socket);

	__pcap_close();
}

void __testTransfer_Active_Close_Later_Send()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10002);

	ret = __reference->bind(__reference, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->listen(__reference, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.200");


	ret = __reference->accept(__reference, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->connect(__target, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__target, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__reference, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = __find_app(__reference, server_socket);
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__target, client_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__reference, server_socket, __target, client_socket);

	__pcap_close();
}


//----------------------------------------------------------------


void __testTransfer_Passive_Close_First_Receive()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10003);

	ret = __target->bind(__target, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");


	ret = __target->accept(__target, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->connect(__reference, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__reference, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__target, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = __find_app(__target, server_socket);
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__reference, client_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__target, server_socket, __reference, client_socket);
	__pcap_close();
}

void __testTransfer_Passive_Close_Later_Receive()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10004);

	ret = __target->bind(__target, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");


	ret = __target->accept(__target, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->connect(__reference, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__reference, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__target, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = __find_app(__target, server_socket);
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__reference, client_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__reference, client_socket, __target, server_socket);

	__pcap_close();
}

void __testTransfer_Active_Close_First_Receive()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10005);

	ret = __reference->bind(__reference, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->listen(__reference, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.200");


	ret = __reference->accept(__reference, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->connect(__target, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__target, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__reference, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = clientApp;
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__reference, server_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__target, client_socket, __reference, server_socket);

	__pcap_close();
}

void __testTransfer_Active_Close_Later_Receive()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context listen_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(listen_socket);

	my_context client_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10006);

	ret = __reference->bind(__reference, listen_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __reference->listen(__reference, listen_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.200");


	ret = __reference->accept(__reference, listen_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->connect(__target, client_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__target, client_socket);
	CU_ASSERT_EQUAL_FATAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__reference, listen_socket);
	CU_ASSERT_EQUAL_FATAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL_FATAL(list_get_count(serverApp->passive_open_calls), 1);

	my_context server_socket = list_get_head(serverApp->passive_open_calls);

	application* receiverApp = clientApp;
	void* data = generate_random(DATA_SIZE);
	__testTransfer(__reference, server_socket, data, DATA_SIZE);
	CU_ASSERT_EQUAL_FATAL(receiverApp->app_data_len, DATA_SIZE);
	CU_ASSERT_EQUAL(memcmp(receiverApp->app_data, data, DATA_SIZE), 0)
	free(data);

	__testClose(__reference, server_socket, __target, client_socket);

	__pcap_close();
}

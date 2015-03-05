/*
 * testlisten.c
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */

#include "testktcp.h"

void __testListen_Accept_Before_Connect()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context server_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, server_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, server_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");


	ret = __target->accept(__target, server_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	my_context client = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);


	ret = __reference->connect(__reference, client, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	application* clientApp = __find_app(__reference, client);
	CU_ASSERT_EQUAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__target, server_socket);
	CU_ASSERT_EQUAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL(list_get_count(serverApp->passive_open_calls), 1);
	__pcap_close();
}

void __testListen_Accept_After_Connect()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context server_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10000);

	ret = __target->bind(__target, server_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, server_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");

	my_context client = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);


	ret = __reference->connect(__reference, client, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	ret = __target->accept(__target, server_socket, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	application* clientApp = __find_app(__reference, client);
	CU_ASSERT_EQUAL(clientApp->active_open_calls, 1);

	application* serverApp = __find_app(__target, server_socket);
	CU_ASSERT_EQUAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL(list_get_count(serverApp->passive_open_calls), 1);
	__pcap_close();
}

extern int __ref_retransmission_off;
extern int __unreliable;

void __testListen_Accept_Multiple()
{
	int past_ret_off = __ref_retransmission_off;
	__ref_retransmission_off = 1;
	int past_unreliable = __unreliable;
	__unreliable = 0;
	//never drop during this test

	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context server_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(10001);

	ret = __target->bind(__target, server_socket, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, server_socket, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);


	my_context* clients[10];
	int k;
	for(k=0; k<10; k++)
	{
		my_context client = __reference->open(__reference, &err);
		CU_ASSERT_EQUAL_FATAL(err, 0);
		CU_ASSERT_PTR_NOT_NULL_FATAL(client);
		clients[k] = client;
	}

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");

	for(k=0; k<10; k++)
	{
		my_context client = clients[k];
		ret = __reference->connect(__reference, client, (struct sockaddr*)&addr, len, &err);
		CU_ASSERT_EQUAL_FATAL(err, 0);
		CU_ASSERT_TRUE_FATAL(ret);
	}

	__flush_packets(50);


	application* serverApp = __find_app(__target, server_socket);
	int prev_passive_connections = list_get_count(serverApp->passive_open_calls);
	for(k=0; ; k++)
	{
		ret = __target->accept(__target, server_socket, &err);
		CU_ASSERT_EQUAL_FATAL(err, 0);
		CU_ASSERT_TRUE_FATAL(ret);
		int passive_connections = list_get_count(serverApp->passive_open_calls);
		if(passive_connections == prev_passive_connections)
			break;
		prev_passive_connections = passive_connections;
		CU_ASSERT_FATAL(k < 100);
		__flush_packets(100);
	}

	for(k=0; k<3; k++)
	{
		my_context client = clients[k];

		application* clientApp = __find_app(__reference, client);
		CU_ASSERT_EQUAL(clientApp->active_open_calls, 1);
	}

	for(k=3; k<10; k++)
	{
		my_context client = clients[k];

		application* clientApp = __find_app(__reference, client);
		CU_ASSERT_EQUAL(clientApp->active_open_calls, 0);
	}


	CU_ASSERT_EQUAL(serverApp->active_open_calls, 0);
	CU_ASSERT_EQUAL(list_get_count(serverApp->passive_open_calls), 3);
	__pcap_close();

	__ref_retransmission_off = past_ret_off;
	__unreliable = past_unreliable;
}

void __testListen_Multiple_Interfaces()
{
	__init_pcap_record(CU_get_current_test()->pName);
	int err = 0;
	int ret = 0;
	my_context server_socket1 = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket1);

	my_context server_socket2 = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket2);


	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(20000);
	addr.sin_addr.s_addr = inet_addr("10.0.0.100");

	ret = __target->bind(__target, server_socket1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("192.168.0.100");

	ret = __target->bind(__target, server_socket2, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, server_socket1, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	ret = __target->listen(__target, server_socket2, 3, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);


	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	my_context client1 = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client1);

	my_context client2 = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client2);


	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	ret = __reference->connect(__reference, client1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	addr.sin_addr.s_addr = inet_addr("192.168.0.100");
	ret = __reference->connect(__reference, client2, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);



	ret = __target->accept(__target, server_socket1, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	__flush_packets(100);

	ret = __target->accept(__target, server_socket2, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_TRUE_FATAL(ret);

	application* clientApp1 = __find_app(__reference, client1);
	CU_ASSERT_EQUAL(clientApp1->active_open_calls, 1);

	application* clientApp2 = __find_app(__reference, client2);
	CU_ASSERT_EQUAL(clientApp2->active_open_calls, 1);

	application* serverApp1 = __find_app(__target, server_socket1);
	CU_ASSERT_EQUAL(serverApp1->active_open_calls, 0);
	CU_ASSERT_EQUAL(list_get_count(serverApp1->passive_open_calls), 1);

	application* serverApp2 = __find_app(__target, server_socket2);
	CU_ASSERT_EQUAL(serverApp2->active_open_calls, 0);
	CU_ASSERT_EQUAL(list_get_count(serverApp2->passive_open_calls), 1);
	__pcap_close();
}

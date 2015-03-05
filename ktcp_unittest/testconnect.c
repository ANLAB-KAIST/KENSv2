/*
 * testconnect.c
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */


#include "testktcp.h"

void __testConnect_Simple_Default_IP()
{
	__init_pcap_record(CU_get_current_test()->pName);

	int err = 0;
	int ret = 0;
	my_context server_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket);

	my_context client_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(9999);

	ret = __reference->bind(__reference, server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr), &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	ret = __reference->listen(__reference, server_socket, 5, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	ret = __reference->accept(__reference, server_socket, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr("10.0.0.200");
	client_addr.sin_port = htons(9999);

	socklen_t len = sizeof(client_addr);
	ret = __target->connect(__target, client_socket, (struct sockaddr*)&client_addr, len, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	__flush_packets(100);

	CU_ASSERT_EQUAL_FATAL(list_get_count(__find_app(__reference, server_socket)->passive_open_calls), 1);
	CU_ASSERT_EQUAL_FATAL(__find_app(__target, client_socket)->active_open_calls, 1);

	server_addr.sin_addr.s_addr = inet_addr("10.0.0.200");
	struct sockaddr_in temp_addr;
	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__target->getpeername(__target, client_socket, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(memcmp(&temp_addr, (struct sockaddr*)&server_addr, sizeof(temp_addr)), 0);


	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__target->getsockname(__target, client_socket, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(temp_addr.sin_addr.s_addr, inet_addr("10.0.0.100"));

	__pcap_close();
}

void __testConnect_Simple_Second_IP()
{
	__init_pcap_record(CU_get_current_test()->pName);

	int err = 0;
	int ret = 0;
	my_context server_socket = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_socket);

	my_context client_socket = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket);


	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(10000);

	ret = __reference->bind(__reference, server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr), &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	ret = __reference->listen(__reference, server_socket, 5, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	ret = __reference->accept(__reference, server_socket, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr("192.168.0.200");
	client_addr.sin_port = htons(10000);

	socklen_t len = sizeof(client_addr);
	ret = __target->connect(__target, client_socket, (struct sockaddr*)&client_addr, len, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	__flush_packets(100);

	CU_ASSERT_EQUAL_FATAL(list_get_count(__find_app(__reference, server_socket)->passive_open_calls), 1);
	CU_ASSERT_EQUAL_FATAL(__find_app(__target, client_socket)->active_open_calls, 1);

	server_addr.sin_addr.s_addr = inet_addr("192.168.0.200");
	struct sockaddr_in temp_addr;
	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__target->getpeername(__target, client_socket, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(memcmp(&temp_addr, (struct sockaddr*)&server_addr, sizeof(temp_addr)), 0);


	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__target->getsockname(__target, client_socket, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(temp_addr.sin_addr.s_addr, inet_addr("192.168.0.100"));

	__pcap_close();
}

void __testConnect_Simultaneous()
{
	__init_pcap_record(CU_get_current_test()->pName);

	int err = 0;
	int ret = 0;
	my_context client_socket1 = __reference->open(__reference, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket1);

	my_context client_socket2 = __target->open(__target, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_socket2);


	struct sockaddr_in client_addr1;
	memset(&client_addr1, 0, sizeof(client_addr1));
	client_addr1.sin_family = AF_INET;
	client_addr1.sin_addr.s_addr = inet_addr("10.0.0.200");
	client_addr1.sin_port = htons(20000);

	struct sockaddr_in client_addr2;
	memset(&client_addr2, 0, sizeof(client_addr2));
	client_addr2.sin_family = AF_INET;
	client_addr2.sin_addr.s_addr = inet_addr("10.0.0.100");
	client_addr2.sin_port = htons(20000);

	ret = __reference->bind(__reference, client_socket1, (struct sockaddr*)&client_addr1, sizeof(client_addr1), &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	ret = __target->bind(__target, client_socket2, (struct sockaddr*)&client_addr2, sizeof(client_addr2), &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	socklen_t len = sizeof(client_addr1);
	ret = __reference->connect(__reference, client_socket1, (struct sockaddr*)&client_addr2, len, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	len = sizeof(client_addr2);
	ret = __target->connect(__target, client_socket2, (struct sockaddr*)&client_addr1, len, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	__flush_packets(100);

	CU_ASSERT_EQUAL_FATAL(__find_app(__reference, client_socket1)->active_open_calls, 1);
	CU_ASSERT_EQUAL_FATAL(__find_app(__target, client_socket2)->active_open_calls, 1);

	struct sockaddr_in temp_addr;
	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__reference->getpeername(__reference, client_socket1, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(memcmp(&temp_addr, (struct sockaddr*)&client_addr2, sizeof(temp_addr)), 0);

	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__target->getpeername(__target, client_socket2, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(memcmp(&temp_addr, (struct sockaddr*)&client_addr1, sizeof(temp_addr)), 0);

	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__reference->getsockname(__reference, client_socket1, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(temp_addr.sin_addr.s_addr, inet_addr("10.0.0.200"));

	memset(&temp_addr, 0, sizeof(temp_addr));
	len = sizeof(temp_addr);
	__target->getsockname(__target, client_socket2, (struct sockaddr*)&temp_addr, &len, &err);
	CU_ASSERT_EQUAL_FATAL(err, 0);
	CU_ASSERT_EQUAL(len, sizeof(temp_addr));
	CU_ASSERT_EQUAL(temp_addr.sin_addr.s_addr, inet_addr("10.0.0.100"));

	__pcap_close();
}

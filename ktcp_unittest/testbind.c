/*
 * testbind.c
 *
 *  Created on: 2013. 7. 19.
 *      Author: leeopop
 */

#include "testktcp.h"

static void close_socket(ktcp_easy_impl* impl, my_context* ctx1)
{
	int err = 0;
	__target->close(__target, ctx1, &err);
	CU_ASSERT_EQUAL_FATAL(err,0);

	int limit = 0;
	while(1)
	{
		timer* app1 = __find_timer(impl, ctx1);
		if(app1)
		{
			now = app1->wakeup_time;
			__target->timer(__target, app1->ctx, app1->wakeup_time);
			limit++;
			CU_ASSERT_FATAL(limit < 100);
		}
		else
			break;
	}
}


void __testBind_Simple()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	close_socket(__target, ctx1);
}


void __testBind_GetSockName()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	struct sockaddr* addr2 = malloc(len * 2);
	socklen_t len2  = len*2;
	err = 0;
	memset(addr2, 0, len2);
	ret = __target->getsockname(__target, ctx1, addr2, &len2, &err);
	CU_ASSERT_TRUE_FATAL(ret);
	CU_ASSERT_EQUAL(err,0);
	CU_ASSERT_EQUAL(memcmp(&addr, addr2, len), 0);


	close_socket(__target, ctx1);
}



void __testBind_DoubleBind()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	err = 0;
	addr.sin_port = htons(10000);
	//my_bind with ctx1 to port 10000 with INADDR_ADY (should fail, already bound)
	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_FALSE(ret);
	CU_ASSERT_EQUAL(err, EINVAL);
	//my_bind again to already opened socket must return false and err should be set to EINVAL


	close_socket(__target, ctx1);
}

void __testBind_OverlapPort()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	err = 0;

	my_context ctx2 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx2);
	CU_ASSERT_EQUAL_FATAL(err,0);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	addr.sin_port = htons(9999);

	err = 0;
	//my_bind with ctx2 to port 9999 with DEFAULT_IP (should fail)
	ret = __target->bind(__target, ctx2, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_FALSE(ret);
	CU_ASSERT_EQUAL(err, EADDRINUSE);
	//my_bind again to already opened address must return false and err should be set to EADDRINUSE


	close_socket(__target, ctx1);
	close_socket(__target, ctx2);
}

void __testBind_OverlapClosed()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	close_socket(__target, ctx1);
	err = 0;

	my_context ctx2 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx2);
	CU_ASSERT_EQUAL_FATAL(err,0);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	addr.sin_port = htons(9999);

	err = 0;
	ret = __target->bind(__target, ctx2, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL(err,0);
	CU_ASSERT_TRUE(ret);
	//ktcp_error("my_bind with ctx2 to closed address must succeed");



	close_socket(__target, ctx2);
}

void __testBind_DifferentIP_SamePort()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	err = 0;

	my_context ctx2 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx2);
	CU_ASSERT_EQUAL_FATAL(err,0);

	addr.sin_addr.s_addr = inet_addr("10.0.0.101");
	addr.sin_port = htons(9999);

	err = 0;
	//my_bind with ctx2 to port 9999 with DEFAULT_IP (should fail)
	ret = __target->bind(__target, ctx2, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL(err,0);
	CU_ASSERT_TRUE(ret);
	//ktcp_error("my_bind with ctx2 to different IP must succeed");

	close_socket(__target, ctx1);
	close_socket(__target, ctx2);
}

void __testBind_SameIP_DifferentPort()
{
	int err=0;
	int ret;

	my_context ctx1 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx1);
	CU_ASSERT_EQUAL_FATAL(err,0);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	addr.sin_port = htons(9999);

	ret = __target->bind(__target, ctx1, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_TRUE(ret);
	CU_ASSERT_EQUAL(err,0);

	err = 0;

	my_context ctx2 = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx2);
	CU_ASSERT_EQUAL_FATAL(err,0);

	addr.sin_addr.s_addr = inet_addr("10.0.0.100");
	addr.sin_port = htons(10000);

	err = 0;
	//my_bind with ctx2 to port 9999 with DEFAULT_IP (should fail)
	ret = __target->bind(__target, ctx2, (struct sockaddr*)&addr, len, &err);
	CU_ASSERT_EQUAL(err,0);
	CU_ASSERT_TRUE(ret);
	//ktcp_error("my_bind with ctx2 to different Port must succeed");

	close_socket(__target, ctx1);
	close_socket(__target, ctx2);
}

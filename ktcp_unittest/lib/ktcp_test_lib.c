/*
 * ktcp_test_lib.c
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */

#include "ktcp_easy_lib.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include "ktcp_test_lib.h"
#include "linked_list.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <limits.h>

static int pcap_ref_fd = -1;
static int pcap_target_fd = -1;

static list target_ip_packets;
static list ref_ip_packets;

static list target_reorder_packets[__REORDER_STEP];
static list ref_reorder_packets[__REORDER_STEP];

static list app_open;
static list timer_list;
int now;

int __unreliable = 0;
int __drop_rate_1000 = 0;
int __reorder_rate_1000 = 0;
int __duplicate_rate_1000 = 0;
int __reorder_step = 0;
int __corruption_rate_1000 = 0;
int __network_delay = 0;

struct pcap_file_header {
	uint32_t magic;
	u_short version_major;
	u_short version_minor;
	uint32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;    /* accuracy of timestamps */
	uint32_t snaplen;    /* max length saved portion of each pkt */
	uint32_t linktype;   /* data link type (LINKTYPE_*) */
};

typedef struct ip_packet_t
{
	int is_drop;
	uint32_t src;
	uint32_t dest;
	size_t data_len;
	char data[0];
}ip_packet;

static uint16_t
ip_checksum(void *ip_buf, size_t hlen)
{
	uint32_t sum = 0;
	uint16_t *v = (uint16_t*)ip_buf;
	while (hlen > 1) {
		sum += *v;
		v++;
		if (sum & 0x80000000)
			sum = (sum & 0xffff) + (sum >> 16);
		hlen -= 2;
	}
	if (hlen)
		sum += (uint16_t) *(uint16_t*)ip_buf;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t) ~sum;
}

static application* create_app()
{
	application* app = malloc(sizeof(application));
	app->active_open_calls=0;
	app->ctx=0;
	app->impl = 0;
	app->error_msg=list_open();
	app->is_open=1;
	app->passive_open_calls = list_open();
	app->app_data = 0;
	app->app_data_len = 0;

	list_add_tail(app_open, app);

	return app;
}


application* __find_app__help(ktcp_easy_impl* impl, my_context ctx, bool create)
{
	list_position iter = list_get_head_position(app_open);
	application* app = 0;
	while(iter)
	{
		application* current = (application*)list_get_at(iter);
		if(current->ctx == ctx && current->is_open)
			app = current;
		iter = list_get_next_position(iter);
	}
	if(app != NULL || !create)
		return app;
	app = create_app();
	app->ctx = ctx;
	app->impl = impl;
	return app;
}

application* __find_app(ktcp_easy_impl* impl, my_context ctx)
{
	return __find_app__help(impl, ctx, true);
}


timer* __find_timer(ktcp_easy_impl* impl, my_context ctx)
{
	list_position iter = list_get_head_position(timer_list);
	while(iter)
	{
		timer* current = (timer*)list_get_at(iter);
		if(current->ctx == ctx && current->impl == impl)
			return current;
		iter = list_get_next_position(iter);
	}
	return NULL;
}

void __pcap_close(void)
{
	if(pcap_target_fd > 0)
		close(pcap_target_fd);
	if(pcap_ref_fd > 0)
		close(pcap_ref_fd);
	pcap_target_fd = -1;
	pcap_ref_fd = -1;

	list_remove_all(app_open);
	list_remove_all(target_ip_packets);
	list_remove_all(ref_ip_packets);
	list_remove_all(timer_list);

	int k;
	for(k=0; k<__REORDER_STEP; k++)
	{
		list_remove_all(target_reorder_packets[k]);
		list_remove_all(ref_reorder_packets[k]);
	}
}

void __test_lib_init(void)
{
	now = 0;
	app_open = list_open();
	target_ip_packets = list_open();
	ref_ip_packets = list_open();
	timer_list = list_open();

	int k;
	for(k=0; k<__REORDER_STEP; k++)
	{
		target_reorder_packets[k] = list_open();
		ref_reorder_packets[k] = list_open();
	}
}

void __test_lib_shutdown(void)
{
	now = 0;
	list_close(app_open);
	list_close(timer_list);
	list_close(target_ip_packets);
	list_close(ref_ip_packets);

	int k;
	for(k=0; k<__REORDER_STEP; k++)
	{
		list_close(target_reorder_packets[k]);
		list_close(ref_reorder_packets[k]);
	}
}

void __init_pcap_record(const char* file_header)
{
	__pcap_close();
	char buf[128];
	sprintf(buf, "%s_target.pcap", file_header);
	pcap_target_fd = open(buf, O_CREAT | O_TRUNC | O_RDWR, 00644);
	sprintf(buf, "%s_ref.pcap", file_header);
	pcap_ref_fd = open(buf, O_CREAT | O_TRUNC | O_RDWR, 00644);
	atexit(__pcap_close);
	if(pcap_target_fd == -1)
		perror("pcap open");
	if(pcap_ref_fd == -1)
		perror("pcap open");
	struct pcap_file_header pcap_header;
	memset(&pcap_header, 0, sizeof(pcap_header));
	pcap_header.magic = 0xa1b2c3d4;
	pcap_header.version_major = 2;
	pcap_header.version_minor = 4;
	pcap_header.snaplen = 65535;
	pcap_header.linktype = 228;//LINKTYPE_IPV4
	if(pcap_ref_fd != -1)
	{
		write(pcap_ref_fd, &pcap_header, sizeof(pcap_header));
#ifdef SYNC_FILE
		sync();
#endif
	}
	if(pcap_target_fd != -1)
	{
		write(pcap_target_fd, &pcap_header, sizeof(pcap_header));
#ifdef SYNC_FILE
		sync();
#endif
	}

	list_remove_all(app_open);
	list_remove_all(timer_list);
	list_remove_all(target_ip_packets);
	list_remove_all(ref_ip_packets);

	int k;
	for(k=0; k<__REORDER_STEP; k++)
	{
		list_remove_all(target_reorder_packets[k]);
		list_remove_all(ref_reorder_packets[k]);
	}
}


/**
 * @breif
 * This function retuns local ip address of KTCP interface.
 *
 * @author leeopop
 * @param target target IP address (in network ordering)
 * @return local ip address that can reach target ip address (INADDR_ANY if there is no specific route)
 */
static uint32_t ip_host_address(struct in_addr target)
{
	uint32_t subnet_mask = inet_addr("255.255.255.0");
	if((inet_addr("10.0.0.100") & subnet_mask) == (target.s_addr & subnet_mask))
		return inet_addr("10.0.0.100");
	if((inet_addr("192.168.0.100") & subnet_mask) == (target.s_addr & subnet_mask))
		return inet_addr("192.168.0.100");
	return inet_addr("10.0.0.100");
}

static uint32_t ip_host_address_ref(struct in_addr target)
{
	uint32_t subnet_mask = inet_addr("255.255.255.0");
	if((inet_addr("10.0.0.200") & subnet_mask) == (target.s_addr & subnet_mask))
		return inet_addr("10.0.0.200");
	if((inet_addr("192.168.0.200") & subnet_mask) == (target.s_addr & subnet_mask))
		return inet_addr("192.168.0.200");
	return inet_addr("10.0.0.200");
}
typedef struct pcap_packet_t {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcap_packet;

/**
 * @breif
 * This function passes data to IP layer.
 *
 * @author leeopop
 * @param src_addr source IP address (in network ordering)
 * @param dest_addr destination IP address (in network ordering)
 * @param data IP payload
 * @param data_size size of data
 * @return actual written bytes (-1 means error)
 */
static int tcp_dispatch_ip(struct in_addr src_addr, struct in_addr dest_addr, void * data, size_t data_size)
{
	ip_packet * packet = malloc(sizeof(ip_packet) + data_size);
	packet->is_drop = 0;
	packet->src = src_addr.s_addr;
	packet->dest = dest_addr.s_addr;
	packet->data_len = data_size;
	memcpy(packet->data, data, data_size);

	int pcap_fd =pcap_target_fd;
	if(pcap_fd > 0)
	{
		struct ip ip;
		pcap_packet header;
		header.incl_len = data_size + sizeof(ip);
		header.orig_len = data_size + sizeof(ip);

		header.ts_sec = now / 1000;
		header.ts_usec = (now % 1000) * 1000;

		{
			memset(&ip, 0, sizeof(ip));
			ip.ip_hl = sizeof(ip) >> 2;
			ip.ip_len = sizeof(ip) + data_size; //total length including header
			ip.ip_id = 0;
			ip.ip_off = 0;
			ip.ip_p = IPPROTO_TCP;
			ip.ip_v = 4;
			ip.ip_sum = 0;
			ip.ip_ttl = 8;
			ip.ip_src.s_addr = src_addr.s_addr;
			ip.ip_dst.s_addr = dest_addr.s_addr;
			ip.ip_sum = ip_checksum(&ip, sizeof(ip));
		}

		write(pcap_fd, &header, sizeof(pcap_packet));
		write(pcap_fd, &ip, sizeof(ip));
		write(pcap_fd, data, data_size);
#ifdef SYNC_FILE
		sync();
#endif
	}
	if(__unreliable)
	{
		if(rand()%1000 < __drop_rate_1000)
		{
			packet->is_drop = 1;
		}
		else if(rand()%1000 < __reorder_rate_1000)
		{
			ip_packet* new_packet = malloc(packet->data_len + sizeof(ip_packet));
			memcpy(new_packet, packet, packet->data_len + sizeof(ip_packet));
			list_add_tail(ref_reorder_packets[rand()%__REORDER_STEP], new_packet);
			packet->is_drop = 1;
		}
		else if(rand()%1000 < __duplicate_rate_1000)
		{
			ip_packet* new_packet = malloc(packet->data_len + sizeof(ip_packet));
			memcpy(new_packet, packet, packet->data_len + sizeof(ip_packet));
			list_add_tail(ref_ip_packets, new_packet);
		}
	}
	list_add_tail(ref_ip_packets, packet);
	return data_size;
}

static int tcp_dispatch_ip_ref(struct in_addr src_addr, struct in_addr dest_addr, void * data, size_t data_size)
{
	ip_packet * packet = malloc(sizeof(ip_packet) + data_size);
	packet->is_drop = 0;
	packet->src = src_addr.s_addr;
	packet->dest = dest_addr.s_addr;
	packet->data_len = data_size;
	memcpy(packet->data, data, data_size);


	int pcap_fd =pcap_ref_fd;
	if(pcap_fd > 0)
	{
		struct ip ip;
		pcap_packet header;
		header.incl_len = data_size + sizeof(ip);
		header.orig_len = data_size + sizeof(ip);

		header.ts_sec = now / 1000;
		header.ts_usec = (now % 1000) * 1000;

		{
			memset(&ip, 0, sizeof(ip));
			ip.ip_hl = sizeof(ip) >> 2;
			ip.ip_len = sizeof(ip) + data_size; //total length including header
			ip.ip_id = 0;
			ip.ip_off = 0;
			ip.ip_p = IPPROTO_TCP;
			ip.ip_v = 4;
			ip.ip_sum = 0;
			ip.ip_ttl = 8;
			ip.ip_src.s_addr = src_addr.s_addr;
			ip.ip_dst.s_addr = dest_addr.s_addr;
			ip.ip_sum = ip_checksum(&ip, sizeof(ip));
		}

		write(pcap_fd, &header, sizeof(pcap_packet));
		write(pcap_fd, &ip, sizeof(ip));
		write(pcap_fd, data, data_size);
#ifdef SYNC_FILE
		sync();
#endif
	}
	if(__unreliable)
	{
		if(rand()%1000 < __drop_rate_1000)
		{
			packet->is_drop = 1;
		}
		else if(rand()%1000 < __reorder_rate_1000)
		{
			ip_packet* new_packet = malloc(packet->data_len + sizeof(ip_packet));
			memcpy(new_packet, packet, packet->data_len + sizeof(ip_packet));
			list_add_tail(target_reorder_packets[rand()%__REORDER_STEP], new_packet);
			packet->is_drop = 1;
		}
		else if(rand()%1000 < __duplicate_rate_1000)
		{
			ip_packet* new_packet = malloc(packet->data_len + sizeof(ip_packet));
			memcpy(new_packet, packet, packet->data_len + sizeof(ip_packet));
			list_add_tail(target_ip_packets, new_packet);
		}
	}
	list_add_tail(target_ip_packets, packet);
	return data_size;
}

static void __flush_target_packets()
{
	int pcap_fd = pcap_target_fd;

	if(__unreliable)
	{
		int current_reorder = rand()%__REORDER_STEP;
		while(list_get_count(target_reorder_packets[current_reorder]) > 0)
			list_add_head(target_ip_packets, list_remove_head(target_reorder_packets[current_reorder]));
	}

	list_position iter = list_get_head_position(target_ip_packets);
	while(iter)
	{
		list_position next = list_get_next_position(iter);
		ip_packet* packet = (ip_packet*)list_get_at(iter);
		struct in_addr src_addr;
		src_addr.s_addr = packet->src;
		struct in_addr dest_addr;
		dest_addr.s_addr = packet->dest;
		const void * data = packet->data;
		size_t data_size = packet->data_len;

		if(__unreliable)
		{
			if(rand()%1000 < __corruption_rate_1000)
				packet->data[rand()%packet->data_len] &= (char)rand();
		}
		if(packet->is_drop == 0)
		{
			if(pcap_fd > 0)
			{
				struct ip ip;
				pcap_packet header;
				header.incl_len = data_size + sizeof(ip);
				header.orig_len = data_size + sizeof(ip);

				header.ts_sec = now / 1000;
				header.ts_usec = (now % 1000) * 1000;

				{
					memset(&ip, 0, sizeof(ip));
					ip.ip_hl = sizeof(ip) >> 2;
					ip.ip_len = sizeof(ip) + data_size; //total length including header
					ip.ip_id = 0;
					ip.ip_off = 0;
					ip.ip_p = IPPROTO_TCP;
					ip.ip_v = 4;
					ip.ip_sum = 0;
					ip.ip_ttl = 8;
					ip.ip_src.s_addr = src_addr.s_addr;
					ip.ip_dst.s_addr = dest_addr.s_addr;
					ip.ip_sum = ip_checksum(&ip, sizeof(ip));
				}

				write(pcap_fd, &header, sizeof(pcap_packet));
				write(pcap_fd, &ip, sizeof(ip));
				write(pcap_fd, data, data_size);
#ifdef SYNC_FILE
				sync();
#endif
			}
			__target->ip_dispatch_tcp(__target,src_addr, dest_addr, data, data_size);
		}
		list_remove(target_ip_packets, packet);
		free(packet);
		iter = next;
	}
}

static void __flush_ref_packets()
{
	int pcap_fd = pcap_ref_fd;
	if(__unreliable)
	{
		int current_reorder = rand()%__REORDER_STEP;
		while(list_get_count(ref_reorder_packets[current_reorder]) > 0)
			list_add_head(ref_ip_packets, list_remove_head(ref_reorder_packets[current_reorder]));
	}

	list_position iter = list_get_head_position(ref_ip_packets);
	while(iter)
	{
		list_position next = list_get_next_position(iter);
		ip_packet* packet = (ip_packet*)list_get_at(iter);
		struct in_addr src_addr;
		src_addr.s_addr = packet->src;
		struct in_addr dest_addr;
		dest_addr.s_addr = packet->dest;
		const void * data = packet->data;
		size_t data_size = packet->data_len;

		if(__unreliable)
		{
			if(rand()%1000 < __corruption_rate_1000)
				packet->data[rand()%packet->data_len] &= (char)rand();
		}
		if(packet->is_drop == 0)
		{
			if(pcap_fd > 0)
			{
				struct ip ip;
				pcap_packet header;
				header.incl_len = data_size + sizeof(ip);
				header.orig_len = data_size + sizeof(ip);

				header.ts_sec = now / 1000;
				header.ts_usec = (now % 1000) * 1000;

				{
					memset(&ip, 0, sizeof(ip));
					ip.ip_hl = sizeof(ip) >> 2;
					ip.ip_len = sizeof(ip) + data_size; //total length including header
					ip.ip_id = 0;
					ip.ip_off = 0;
					ip.ip_p = IPPROTO_TCP;
					ip.ip_v = 4;
					ip.ip_sum = 0;
					ip.ip_ttl = 8;
					ip.ip_src.s_addr = src_addr.s_addr;
					ip.ip_dst.s_addr = dest_addr.s_addr;
					ip.ip_sum = ip_checksum(&ip, sizeof(ip));
				}

				write(pcap_fd, &header, sizeof(pcap_packet));
				write(pcap_fd, &ip, sizeof(ip));
				write(pcap_fd, data, data_size);
#ifdef SYNC_FILE
				sync();
#endif
			}
			__reference->ip_dispatch_tcp(__reference, src_addr, dest_addr, data, data_size);
		}
		list_remove(ref_ip_packets, packet);
		free(packet);
		iter = next;
	}
}

/**
 * @breif
 * This function passes data to application
 *
 * @author leeopop
 * @param handle abstraction of application socket
 * @param data data to be passed
 * @param data_size size of data
 * @return actual written bytes (-1 means closed socket)
 */
static int tcp_dispatch_app(bool isRef, my_context handle, const void* data, size_t data_size)
{
	application* app;
	if(isRef)
	{
		app = __find_app(__reference, handle);
	}
	else
	{
		app = __find_app(__target, handle);
	}
	void* target;
	if(app->app_data == NULL)
	{
		target = app->app_data = malloc(data_size);
		CU_ASSERT_PTR_NOT_NULL_FATAL(target);
		memcpy(target, data, data_size);
		app->app_data_len = data_size;
	}
	else
	{
		app->app_data = realloc(app->app_data, app->app_data_len + data_size);
		CU_ASSERT_PTR_NOT_NULL_FATAL(app->app_data);
		target = app->app_data + app->app_data_len;
		memcpy(target, data, data_size);
		app->app_data_len = app->app_data_len + data_size;
	}
	memcpy(target, data, data_size);

	return data_size;
}

/**
 * @breif
 * This function wakes up 'kaccept' and 'kaccept' will return @param new_handle.
 *
 * @author leeopop
 * @param server_handle TCP context to be waken up
 * @param new_handle passively opened socket used as the return value of 'kaccept'
 * @return whether operation is successful (for example, if server_handle is not blocked)
 */
static bool tcp_passive_open(bool isRef, my_context server_handle, my_context new_handle)
{
	application* app;
	if(isRef)
	{
		app = __find_app(__reference, server_handle);
	}
	else
	{
		app = __find_app(__target, server_handle);
	}

	list_add_tail(app->passive_open_calls, new_handle);
	return true;
}

/**
 * @breif
 * This function wakes up 'kconnect'.
 *
 * @author leeopop
 * @param handle TCP context to be waken up
 * @return whether operation is successful (for example, if handle is not blocked)
 */
static bool tcp_active_open(bool isRef, my_context handle)
{
	application* app;
	if(isRef)
	{
		app = __find_app(__reference, handle);
	}
	else
	{
		app = __find_app(__target, handle);
	}

	app->active_open_calls++;
	return true;
}

/**
 * @breif
 * This function returns absolute time in milliseconds.
 *
 * @return absolute time in milliseconds (use this value for time registration)
 */
static int tcp_get_mtime()
{
	return now;
}

/**
 * @breif
 * This function registers timer for each context.
 * If it is already registered, it overwrites it.
 *
 * @author leeopop
 * @param context TCP context that will be bound to this timer
 * @param absolute time to wake up (@see tcp_get_mtime)
 * @return whether registration is successful
 */
static bool tcp_register_timer(bool isRef, my_context context, int mtime)
{
	timer* timer = 0;
	if(isRef)
	{
		timer = __find_timer(__reference, context);
		if(timer == NULL)
		{
			timer = malloc(sizeof(timer));
			list_add_tail(timer_list, timer);
		}
		timer->impl = __reference;
	}
	else
	{
		timer = __find_timer(__target, context);
		if(timer == NULL)
		{
			timer = malloc(sizeof(timer));
			list_add_tail(timer_list, timer);
		}
		timer->impl = __target;
	}

	timer->ctx = context;
	timer->wakeup_time = mtime;
	return true;
}

/**
 * @breif
 * This function unregisters timer for each context.
 * If it is not registered, no action.
 *
 * @author leeopop
 * @param context TCP context that is bound to a timer
 */
static void tcp_unregister_timer(bool isRef, my_context context)
{
	timer* timer = 0;
	if(isRef)
	{
		timer = __find_timer(__reference, context);
	}
	else
	{
		timer = __find_timer(__target, context);
	}

	if(timer)
	{
		list_remove(timer_list, timer);
		free(timer);
	}
}

/**
 * @breif
 * This function shuts down tcp-app connection.
 * If it is not bound, no action.
 *
 * @author leeopop
 * @param context TCP context that is bound to an application
 */
static void tcp_shutdown_app(bool isRef, my_context handle)
{
	application* app;
	if(isRef)
	{
		app = __find_app__help(__reference, handle, false);
	}
	else
	{
		app = __find_app__help(__target, handle, false);
	}

	if(app)
	{
		app->is_open = 0;
	}
}

static bool tcp_active_open_target(my_context handle)
{
	return tcp_active_open(false, handle);
}

static bool tcp_active_open_ref(my_context handle)
{
	return tcp_active_open(true, handle);
}

static int tcp_dispatch_app_ref(my_context handle, const void* data, size_t data_size)
{
	return tcp_dispatch_app(true, handle, data, data_size);
}

static int tcp_dispatch_app_target(my_context handle, const void* data, size_t data_size)
{
	return tcp_dispatch_app(false, handle, data, data_size);
}

static bool tcp_passive_open_ref(my_context server_handle, my_context new_handle)
{
	return tcp_passive_open(true, server_handle, new_handle);
}

static bool tcp_passive_open_target(my_context server_handle, my_context new_handle)
{
	return tcp_passive_open(false, server_handle, new_handle);
}

static bool tcp_register_timer_ref(my_context context, int mtime)
{
	return tcp_register_timer(true, context, mtime);
}

static bool tcp_register_timer_target(my_context context, int mtime)
{
	return tcp_register_timer(false, context, mtime);
}

static void tcp_unregister_timer_ref(my_context context)
{
	tcp_unregister_timer(true, context);
}

static void tcp_unregister_timer_target(my_context context)
{
	tcp_unregister_timer(false, context);
}

static void tcp_shutdown_app_ref(my_context handle)
{
	tcp_shutdown_app(true, handle);
}

static void tcp_shutdown_app_target(my_context handle)
{
	tcp_shutdown_app(false, handle);
}

ktcp_easy_lib* __create_test_instance(bool isReference)
{
	ktcp_easy_lib* testlib = malloc(sizeof(ktcp_easy_lib));
	if(isReference)
	{
		testlib->ip_host_address = ip_host_address_ref;
		testlib->tcp_dispatch_ip = tcp_dispatch_ip_ref;
		testlib->tcp_active_open = tcp_active_open_ref;
		testlib->tcp_dispatch_app = tcp_dispatch_app_ref;
		testlib->tcp_passive_open = tcp_passive_open_ref;
		testlib->tcp_register_timer = tcp_register_timer_ref;
		testlib->tcp_shutdown_app = tcp_shutdown_app_ref;
		testlib->tcp_unregister_timer = tcp_unregister_timer_ref;
	}
	else
	{
		testlib->ip_host_address = ip_host_address;
		testlib->tcp_dispatch_ip = tcp_dispatch_ip;
		testlib->tcp_active_open = tcp_active_open_target;
		testlib->tcp_dispatch_app = tcp_dispatch_app_target;
		testlib->tcp_passive_open = tcp_passive_open_target;
		testlib->tcp_register_timer = tcp_register_timer_target;
		testlib->tcp_shutdown_app = tcp_shutdown_app_target;
		testlib->tcp_unregister_timer = tcp_unregister_timer_target;
	}

	testlib->tcp_get_mtime = tcp_get_mtime;

	return testlib;
}

void __free_test_instance(ktcp_easy_lib* target)
{
	free(target);
}

static int wakeup_until = 0;

static void flush_timer()
{
	while(1)
	{
		timer* minimum = 0;
		int min_time = INT_MAX;
		list_position iter = list_get_head_position(timer_list);
		while(iter)
		{
			list_position next = list_get_next_position(iter);
			timer* app = list_get_at(iter);
			if(app->wakeup_time <= wakeup_until)
			{
				if(min_time > app->wakeup_time)
				{
					min_time = app->wakeup_time;
					minimum = app;
				}
			}

			iter = next;
		}
		if(minimum == 0)
			break;

		list_remove(timer_list, minimum);
		now = minimum->wakeup_time;
		minimum->wakeup_time = 0;
		minimum->impl->timer(minimum->impl, minimum->ctx, now);
		free(minimum);
	}
}

static int max_timer()
{
	int ret = -1;
	list_position iter = list_get_head_position(timer_list);
	while(iter)
	{
		list_position next = list_get_next_position(iter);
		timer* app = list_get_at(iter);

		if(ret == -1 || ret < app->wakeup_time)
			ret = app->wakeup_time;

		iter = next;
	}
	return ret;
}

int __flush_packets(int limit_input)
{
	int limit = 0;
	while(list_get_count(ref_ip_packets) != 0
			|| list_get_count(target_ip_packets) != 0)
	{
		while(list_get_count(ref_ip_packets) != 0
				|| list_get_count(target_ip_packets) != 0)
		{
			list new_ref = ref_ip_packets;
			ref_ip_packets = list_open();
			__flush_target_packets();
			list temp = ref_ip_packets;
			ref_ip_packets = new_ref;
			__flush_ref_packets();
			CU_ASSERT_EQUAL_FATAL(list_get_count(ref_ip_packets), 0);
			list_close(ref_ip_packets);
			ref_ip_packets = temp;

			now += __network_delay;
		}
		limit++;
		int newNow = max_timer();
		if(newNow != -1)
		{
			wakeup_until = newNow;
			flush_timer();
		}
		CU_ASSERT_FATAL(limit < limit_input);
	}

	return limit;
}

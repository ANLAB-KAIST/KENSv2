/*
 * ktcp_easy_testlib.c
 *
 *  Created on: 2013. 7. 18.
 *      Author: leeopop
 */

#include "ktcp_easy_testlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/ip.h>

uint32_t default_ip;
uint32_t second_ip;
uint32_t third_ip;
uint32_t client_ip;
uint32_t default_client_ip;
uint32_t second_client_ip;
uint32_t third_client_ip;
uint32_t subnet_mask;
struct in_addr default_addr;
struct in_addr second_addr;
struct in_addr third_addr;
struct in_addr client_addr;
struct in_addr default_client_addr;
struct in_addr second_client_addr;
struct in_addr third_client_addr;

list tcp_to_ip;
list app_open;
int now;
const char* pcap_filename = 0;
static int pcap_fd = -1;

struct pcap_file_header {
	uint32_t magic;
	u_short version_major;
	u_short version_minor;
	uint32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;    /* accuracy of timestamps */
	uint32_t snaplen;    /* max length saved portion of each pkt */
	uint32_t linktype;   /* data link type (LINKTYPE_*) */
};

typedef struct pcap_packet_t {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcap_packet;

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

static void pcap_close(void)
{
	if(pcap_fd > 0)
		close(pcap_fd);
}

void _ktcp_testlib_init()
{
	default_ip = inet_addr(DEFAULT_IP);
	second_ip = inet_addr(SECOND_IP);
	third_ip = inet_addr(THIRD_IP);

	default_client_ip = inet_addr(DEFAULT_CLIENT_IP);
	second_client_ip = inet_addr(SECOND_CLIENT_IP);
	third_client_ip = inet_addr(THIRD_CLIENT_IP);
	client_ip = inet_addr(CLIENT_IP);

	subnet_mask = inet_addr(SUBNET_MASK);
	now = 0;

	default_addr.s_addr = default_ip;
	second_addr.s_addr = second_ip;
	third_addr.s_addr = third_ip;

	default_client_addr.s_addr = default_client_ip;
	second_client_addr.s_addr = second_client_ip;
	third_client_addr.s_addr = third_client_ip;
	client_addr.s_addr = client_ip;

	tcp_to_ip = list_open();
	app_open = list_open();

	if(pcap_filename)
	{
		pcap_fd = open(pcap_filename, O_CREAT | O_TRUNC | O_RDWR, 00644);
		atexit(pcap_close);
		if(pcap_fd == -1)
			perror("pcap open");
		struct pcap_file_header pcap_header;
		memset(&pcap_header, 0, sizeof(pcap_header));
		pcap_header.magic = 0xa1b2c3d4;
		pcap_header.version_major = 2;
		pcap_header.version_minor = 4;
		pcap_header.snaplen = 65535;
		pcap_header.linktype = 228;//LINKTYPE_IPV4
		if(pcap_fd != -1)
		{
			write(pcap_fd, &pcap_header, sizeof(pcap_header));
			sync();
		}
	}
}

application* find_app(my_context ctx)
{
	list_position iter = list_get_head_position(app_open);
	application* app = 0;
	while(iter)
	{
		app = (application*)list_get_at(iter);
		if(app->ctx == ctx)
			return app;
		iter = list_get_next_position(iter);
	}
	app = create_app();
	app->ctx = ctx;
	return app;
}

uint32_t ip_host_address(struct in_addr target)
{
	if((default_ip & subnet_mask) == (target.s_addr & subnet_mask))
		return default_ip;
	if((second_ip & subnet_mask) == (target.s_addr & subnet_mask))
		return second_ip;
	if((third_ip & subnet_mask) == (target.s_addr & subnet_mask))
		return third_ip;
	return default_ip;
}

int tcp_dispatch_ip(struct in_addr src_addr, struct in_addr dest_addr, void * data, size_t data_size)
{
	ip_packet * packet = malloc(sizeof(ip_packet) + data_size);
	packet->src = src_addr.s_addr;
	packet->dest = dest_addr.s_addr;
	packet->data_len = data_size;
	memcpy(packet->data, data, data_size);

	list_add_tail(tcp_to_ip, packet);

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
		sync();
	}
	return data_size;
}

void test_ip_dispatch_tcp(struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size)
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
		sync();
	}
	ip_dispatch_tcp(src_addr, dest_addr, data, data_size);
}

int tcp_dispatch_app(my_context handle, const void* data, size_t data_size)
{
	application* app = find_app(handle);
	app_data * packet = malloc(sizeof(app_data) + data_size);

	packet->data_len = data_size;
	memcpy(packet->data, data, data_size);

	list_add_tail(app->tcp_to_app, packet);
	return data_size;
}

bool tcp_passive_open(my_context server_handle, my_context new_handle)
{
	application* app = find_app(server_handle);

	list_add_tail(app->passive_open_calls, new_handle);
	return true;
}

bool tcp_active_open(my_context handle)
{
	application* app = find_app(handle);

	app->active_open_calls++;
	return true;
}

int tcp_get_mtime()
{
	return now;
}

bool tcp_register_timer(my_context context, int mtime)
{
	application* app = find_app(context);

	app->mtime = mtime;
	app->timer_set = 1;
	return true;
}

void tcp_unregister_timer(my_context context)
{
	application* app = find_app(context);

	app->mtime = 0;
	app->timer_set = 0;
}

void tcp_shutdown_app(my_context handle)
{
	application* app = find_app(handle);

	app->is_open = 0;
}

void print(const char* fmt, ...)
{
	va_list valist;
	va_start(valist, fmt);
	char buf[1024];
	strcpy(buf, fmt);
	strcat(buf, "\n");

	vfprintf(stdout, buf, valist);
	fflush(stdout);
}

void ktcp_error(const char* fmt, ...)
{
	va_list valist;
	va_start(valist, fmt);
	char buf[1024];
	strcpy(buf, fmt);
	strcat(buf, "\n");

	vfprintf(stderr, buf, valist);
	fflush(stderr);
	exit(1);
}

application* create_app()
{
	application* app = malloc(sizeof(application));
	app->active_open_calls=0;
	app->ctx=0;
	app->error_msg=list_open();
	app->is_open=1;
	app->mtime=0;
	app->passive_open_calls = list_open();
	app->timer_set=0;
	app->tcp_to_app = list_open();
	list_add_tail(app_open, app);

	return app;
}
void close_app(application* app)
{
	if(list_get_head(app->error_msg))
		ktcp_error(list_get_head(app->error_msg));
	list_close(app->error_msg);
	while(list_get_head(app->passive_open_calls))
	{
		int err = 0;
		my_close(list_remove_head(app->passive_open_calls), &err);
		if(err)
			ktcp_error("close failed while removing passive open calls");
	}
	list_close(app->passive_open_calls);
	void* data;
	while((data = list_remove_head(app->tcp_to_app)))
		free(data);
	list_close(app->tcp_to_app);
	free(app);
}

struct pseudoheader
{
	struct in_addr source;
	struct in_addr destination;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
	struct tcphdr tcp;
};

uint16_t tcp_checksum(struct in_addr source, struct in_addr dest, const void* data, uint16_t length)
{
	if(length < (sizeof (struct tcphdr)))
		return 0;
	struct pseudoheader pheader;
	pheader.source = source;
	pheader.destination = dest;
	pheader.zero = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.length = htons(length);
	memcpy(&pheader.tcp, data, sizeof(struct tcphdr));
	pheader.tcp.th_sum = 0;

	const uint16_t * pointer = (const uint16_t *)&pheader;
	uint32_t sum = 0;
	while((void*)pointer < (void*)(&pheader+1))
	{
		sum += ntohs(*pointer);
		pointer++;
	}
	pointer = data+sizeof(struct tcphdr);

	const uint8_t * last_byte = 0;
	if(length % 2 == 1)
	{
		last_byte = data + length -1;
		length--;
	}

	while((void*)pointer < (void*)(data+length))
	{
		sum += ntohs(*pointer);
		pointer++;
	}
	if(last_byte)
		sum += (*last_byte) << 8;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	uint16_t ret = (uint16_t)sum;
	return htons(~ret);
}

int auto_ack(uint32_t source, uint32_t destination, uint32_t seq)
{

	struct in_addr src, dst;

	int count = 0;
	list_position iter = list_get_head_position(tcp_to_ip);
	while(iter)
	{
		list_position next = list_get_next_position(iter);
		ip_packet* packet = (ip_packet*)list_get_at(iter);
		if((packet->src == source || source == 0)
				&&
				(packet->dest == destination || destination == 0))
		{
			struct tcphdr* header = (struct tcphdr*)packet->data;
			size_t data_len = packet->data_len - header->th_off*4;
			src.s_addr = packet->src;
			dst.s_addr = packet->dest;
			if((header->th_flags & (TH_SYN | TH_FIN)) || data_len > 0)
			{
				struct tcphdr response;
				memset(&response, 0, sizeof(response));
				response.th_flags = TH_ACK;
				if(data_len == 0)
					if(header->th_flags & (TH_SYN | TH_FIN))
						data_len = 1;
				response.th_sport = header->th_dport;
				response.th_dport = header->th_sport;
				response.th_seq = seq;
				response.th_ack = htonl(ntohl(header->th_seq) + data_len);
				response.th_off = sizeof(response)/4;
				response.th_win = htons(DEFAULT_WINDOW);
				response.th_sum = tcp_checksum(dst, src, &response, sizeof(response));

				print("ACK, %x->%x:%d", packet->dest, packet->src, ntohs(response.th_dport));
				test_ip_dispatch_tcp(dst, src, &response, sizeof(response));
				count++;
				free(packet);
				list_remove_at(iter);
			}
		}
		iter = next;
	}
	return count;
}

int count_ip(uint32_t source, uint32_t destination, uint16_t flag)
{

	int count = 0;
	list_position iter = list_get_head_position(tcp_to_ip);
	while(iter)
	{
		list_position next = list_get_next_position(iter);
		ip_packet* packet = (ip_packet*)list_get_at(iter);
		if((packet->src == source || source == 0)
				&&
				(packet->dest == destination || destination == 0))
		{
			struct tcphdr* header = (struct tcphdr*)packet->data;
			size_t data_len = packet->data_len - header->th_off*4;
			if(header->th_flags & flag)
			{
				count++;
			}
		}
		iter = next;
	}
	return count;
}

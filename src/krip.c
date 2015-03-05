#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "iniparser.h"

#include "route.h"
#include "datalink.h"
#include "krip.h"
#include "kip.h"
#include "log.h"
#include "linked_list.h"
#include "misc.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

static int _enabled;					/* Is KRIP enabled? */
static unsigned int _update_time;		/* The last advertisement Time */
static unsigned int _update_interval;	/* Advertisement interval */
static unsigned int _timeout;			/* Timeout duration. */
static bool _trigger = false;			/* Indicates whether triggered update is required. */

static list _rip_info_list;
static list _neighbor_info_list;

/* the udp socket for RIP */
static int _sock;

static void krip_send_request(neighbor_info *ni);
static void krip_send_response(neighbor_info *ni, int send_changed_info_only);
static u_int krip_get_mtime();
static void krip_dispatch_timeout();
static void krip_dispatch_in();
static void krip_dispatch_out();

#define MIN(x,y)  ((x) <= (y) ? (x) : (y))


int krip_init(dictionary *conf)
{
	char *svrname;
	char *vip, *ip, *port, *if_name;
	char *p;
	char *c;
	char file[1024], buf[512];
	FILE *fp;
	struct sockaddr_in sin;
	int listen;

	/* Parse the configuration file. ("HOSTNAME_krip" in the current working directory) */
	svrname = iniparser_getstring(conf, "KENS:server_name", "KENS");

	sprintf(file, "%s_krip", svrname);
	fp = fopen(file, "r");
	if (fp == NULL) {
		_enabled = 0;
		return 0;
	}

	/* Initialize system parameters. */
	_update_time = krip_get_mtime();

	c = iniparser_getstring(conf,"KENS:krip_update_interval","3000");
	_update_interval = atoi(c);

	c = iniparser_getstring(conf,"KENS:krip_timeout","7000");
	_timeout = atoi(c);

	_rip_info_list = list_open();
	_neighbor_info_list = list_open();

	/* Create a UDP socket for RIP communication. */
	if ((_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("krip");
		return -1;
	}

	_enabled = 1;

	/* configuration example:
	 * listen 127.0.0.1:9501
	 * 10.1.0.1 seth0 127.0.0.1:9502
	 * 10.1.1.1 seth1 127.0.0.1:9503
	 */

	while (fgets(buf, 512, fp)) {
		p = strchr(buf, '#');
		if (p != NULL) *p = '\0';
		if (buf[strlen(buf) - 1] == '\n') buf[strlen(buf) - 1] = '\0';
		
		p = buf;
		p = eat_ws(p);
		if (p == NULL) continue;

		if (strncmp(buf, "listen", 6) == 0) {
			listen = 1;

			p += 6;
			p = eat_ws(p);
		}
		else {
			listen = 0;
			
			vip = p;
			p = eat_ipaddr(vip);
			*p++ = '\0';
			p = eat_ws(p);

			if_name = p;
			p = eat_alphanum(if_name);
			*p++ = '\0';
			p = eat_ws(p);
		}

		ip = p;
		p = eat_ipaddr(ip);
		*p++ = '\0';
		port = p;
		p = eat_digit(port);

		if (listen)
		{
			/* Setup the RIP listening socket. */
			L_ROUTE("krip_init(): bind to %s:%s", ip, port);
			sin.sin_family = AF_INET;
			inet_aton(ip, &sin.sin_addr);
			sin.sin_port = htons((in_port_t)atoi(port));
			if (bind(_sock, (struct sockaddr *)&sin, sizeof(sin))) {
				perror("krip");
				return -1;
			}
		}
		else
		{
			/* Setup the neighbor information for RIP clients. */
			L_ROUTE("krip_init(): register neighbor %s(%s:%s)", vip, ip, port);
			neighbor_info *ni = (neighbor_info *)malloc(sizeof(neighbor_info));
			inet_aton(vip, &ni->virtual_addr);
			ni->krip_addr.sin_family = AF_INET;
			inet_aton(ip, &ni->krip_addr.sin_addr);
			ni->krip_addr.sin_port = htons((in_port_t)atoi(port));
			ni->ifp = ifunit(if_name);
			if (!ni->ifp) {
				L_ROUTE("krip_init(): invalid interface name: %s", if_name);
				free(ni);
				continue;
			}

			list_add_tail(_neighbor_info_list, ni);
		}
	}

	fclose(fp);

	/* Fetch the routing table entries. */
	list rte_list = rt_query();
	list_position pos;
	uint32_t now = krip_get_mtime();
	for (pos = list_get_head_position(rte_list);
			pos; pos = list_get_next_position(pos)) {
		rtentry *rte = list_get_at(pos);
		for (; rte; rte = (rtentry *)((radix_node *)rte)->rn_dupedkey) {
			if (((radix_node *)rte)->rn_mask == NULL)
				continue;
			if (rte->dst.s_addr == 0x00000000) {
				L_ROUTE("krip_init(): default gw %s", inet_ntoa(rte->gw));
			}
			else if (rte->dst.s_addr == inet_addr("127.0.0.1")) {
			}
			else {
				L_ROUTE("krip_init(): dst %s", inet_ntoa(rte->dst));
				L_ROUTE("krip_init(): mask %s", inet_ntoa(rte->mask));
				L_ROUTE("krip_init(): gw %s", inet_ntoa(rte->gw));

				rip_info *ri = (rip_info *)malloc(sizeof(rip_info));
				ri->assoc_rte = rte;
				ri->metric = 1;
				ri->change_flag = 1;
				ri->timeout = 0;		/* The initial entries will not be expired. */
				ri->from = NULL;
				list_add_tail(_rip_info_list, ri);
			}
		}
	}

	/* Send the initial request packets */
	pos = list_get_head_position(_neighbor_info_list);
	for (; pos; pos = list_get_next_position(pos)) {
		neighbor_info *ni = list_get_at(pos);
		krip_send_request(ni);
	}

	return 0;
}

int krip_shutdown(void)
{
	list_position pos;

	if (!_enabled)
		return 0;

	/* Clean up RIP info list. */
	for (pos = list_get_head_position(_rip_info_list);
			pos; pos = list_get_next_position(pos))
		free(list_get_at(pos));
	list_close(_rip_info_list);

	/* Clean up neighbor info list. */
	for (pos = list_get_head_position(_neighbor_info_list);
			pos; pos = list_get_next_position(pos))
		free(list_get_at(pos));
	list_close(_neighbor_info_list);

	close(_sock);

	return 0;
}

int krip_dispatch(void)
{
	if (!_enabled)
		return 0;

	krip_dispatch_timeout();
	krip_dispatch_in();
	krip_dispatch_out();
}

/* Handle timeouts */
static void krip_dispatch_timeout()
{
	/* _rip_info_list에서 timeout이 현재 시간보다 작은 값을 가진 entry들을 연결이 끊어진 것으로 간주,
	   각각의 member들을 적절히 설정한다. */
	list_position pos;
	uint32_t now = krip_get_mtime();
	for (pos = list_get_head_position(_rip_info_list); pos; pos = list_get_next_position(pos)) {
		rip_info *ri = list_get_at(pos);
		/* metric이 0인 것들은 초기화할 때 추가되어 있던 것이거나 이미 expire된 것들이므로 넘어간다.
		   이렇게 해주는 이유는 svr, cli처럼 RIP가 동작하지 않는 host와의 연결에 대해선 metric 값을
		   일정하게 유지시켜 잘못된 routing 정보가 전파되지 않게 하기 위한 것이다. */
		if (ri->timeout < now && ri->timeout != 0) {
			L_ROUTE("krip_dispatch_timeout(): entry for interface {%08x} has been timeout, making its metric inifinity", ri->from);
			ri->metric = RIP_METRIC_INFINITY;
			ri->change_flag = 1;
			ri->timeout = 0;
			_trigger = true;
		}
	}
}

/**
 * Handles incoming routing-request packets.
 */
static void krip_dispatch_in()
{
	fd_set fds;
	struct timeval timeout;
	int rc;
	int i;
	list_position pos;
	rip_info *ri;

	FD_ZERO(&fds);
	FD_SET(_sock, &fds);
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	/* The main loop of the RIP daemon. */
	while ((rc = select(_sock + 1, &fds, NULL, NULL, &timeout)) > 0) {
		rip_buf buf;
		uint32_t now = krip_get_mtime();
		size_t len = RIP_PACKET_MAXSIZ;
		struct sockaddr_in from;
		size_t fromlen = sizeof(from);
		len = recvfrom(_sock, buf.buf, len, 0, (struct sockaddr *)&from, &fromlen);

		/* Find the sender by matching IP addresses and ports. */
		neighbor_info *ni = NULL;
		pos = list_get_head_position(_neighbor_info_list);
		for (; pos; pos = list_get_next_position(pos)) {
			ni = list_get_at(pos);
			if (from.sin_addr.s_addr == ni->krip_addr.sin_addr.s_addr &&
					from.sin_port == ni->krip_addr.sin_port)
				break;
			/* Should be reset to perform below check routines correctly.
			   (ref http://noah.kaist.ac.kr/view.jsp?board=1353&serial=517685) */
			ni = NULL;
		}

		/* If the sender is not recoginized, skip the RIP message. */
		if (!ni) {
			L_ROUTE("krip_dispatch_in(): unknown neighbor %s:%d", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
			continue;
		}

		/* If the interface received is disabled, also skip it. */
		if (!ni->ifp->if_enabled) {
			L_ROUTE("krip_dispatch_in(): ignored response from %s {%08x}", inet_ntoa(ni->virtual_addr), ni->ifp);
			continue;
		}

		/* Process RIP packets. */
		switch (buf.rip_packet.command) {
		case RIP_REQUEST:

			/* Response to the request. */
			L_ROUTE("krip_dispatch_in(): RIP_REQUEST from %s {%08x}", inet_ntoa(ni->virtual_addr), ni->ifp);
			krip_send_response(ni, 0);
			break;

		case RIP_RESPONSE:
			/* RIP 응답 패킷을 받으면 그것을 바탕으로 자신의 routing table 정보를 업데이트한다. */

			i = 0;
			L_ROUTE("krip_dispatch_in(): RIP_RESPONSE from %s {%08x} with %d entries.",
				inet_ntoa(ni->virtual_addr),
				ni->ifp,
				(len - RIP_HEADER_SIZE) / RIP_RTE_SIZE);

			/* Look up the received routing table entries. */
			while (1) {
				bool found = false;
				rte *rte = buf.rip_packet.rte + i;
				/* Convert endians. */
				rte->family = ntohs(rte->family);
				rte->tag = ntohs(rte->tag);
				rte->metric = ntohl(rte->metric);

				/* Stop if the index reaches the number of available routing entries in the packet. */
				if (i == (len - RIP_HEADER_SIZE) / RIP_RTE_SIZE)
					break;
				L_ROUTE("krip_dispatch_in(): processing entry %d (prefix=%s, mask=%s, metric=%d)", i + 1,
						inet_ntoa(rte->prefix),
						inet_ntoa(rte->mask),
						rte->metric);

				/* 여기에서 distance vector 알고리즘이 구현된다. */
				/* Choose minimum of received metric + 1 and inifinity. */
				uint32_t new_metric = MIN(rte->metric + 1, RIP_METRIC_INFINITY);

				for (pos = list_get_head_position(_rip_info_list); pos; pos = list_get_next_position(pos)) {
					ri = list_get_at(pos);

					/* 여기에서 match된다는 뜻은 어디로 해당 IP 대역을 담당하는 routing entry를 찾았다는 뜻이다. */

					/* If a routing_info matches an entry, update related information. */
					if (ri->assoc_rte->dst.s_addr == rte->prefix.s_addr) {
						L_ROUTE("krip_dispatch_in(): ri->assoc_rte->dst = %s {%08x} has to be updated.",
							inet_ntoa(ri->assoc_rte->dst),
							ri->from);
						found = true;

						/* If ri is from the neighbor which sent the RIP message, refresh timeout. */
						if (ri->from == ni->ifp) {
							ri->timeout = now + _timeout;
						}

						/* 현재 보고 있는 rip_info가 RIP message를 받은 interface로부터 온 것이고 metric 값이 바뀌거나,
						   새 metric 값이 더 낮을 경우(더 좋은 route임을 뜻함) rip_info를 새로 업데이트한다.
						   (ref http://noah.kaist.ac.kr/view.jsp?board=1248&serial=509303) */
						if ((ri->from == ni->ifp && new_metric != ri->metric) || (ri->metric > new_metric)) {
							/* If previous ri was advertised by the sender, or the new route has lower metric,
							   update ri. */
							L_ROUTE("krip_dispatch_in(): updating existing routing info... (gw = %s {%08x}, metric = %d)",
								inet_ntoa(ni->virtual_addr),
								ni->ifp,
								new_metric);
							ri->assoc_rte->gw.s_addr = ni->virtual_addr.s_addr;
							ri->assoc_rte->rt_ifp = ni->ifp;
							ri->metric = new_metric;
							ri->change_flag = 1; /* Mark it as modified. */
							ri->from = ni->ifp;
							ip_invalidate_forward_rt_cache();
							_trigger = true;
						}
					}
				}
				if (!found) {
					/* If matching routing info is not found, create a new routing entry and routing info. */
					L_ROUTE("krip_dispatch_in(): creating a new routing entry...");
					rtentry *new_rte = (rtentry *)malloc(sizeof(rtentry));
					new_rte->dst = rte->prefix;
					new_rte->mask = rte->mask;
					new_rte->gw = ni->virtual_addr;
					new_rte->rt_ifp = ni->ifp;
					if (rt_insert(new_rte)) {
						L_ROUTE("krip_dispatch_in(): failed to insert new route");
						free(new_rte);
						break;
					}
					ri = (rip_info *)malloc(sizeof(rip_info));
					ri->assoc_rte = new_rte;
					ri->metric = new_metric;
					ri->change_flag = 1; /* Mark it as modified. */
					ri->timeout = now + _timeout; /* Initialize timeout. */
					ri->from = ni->ifp;
					list_add_tail(_rip_info_list, ri);
					ip_invalidate_forward_rt_cache();
					_trigger = true;
				}
				i++;
			}
			break;

		default:
			L_ROUTE("krip_dispatch_in(): unrecognized RIP command type (%d) from %s.",
				buf.rip_packet.command,
				inet_ntoa(ni->virtual_addr));
			break;
		}
	}
	
	if (rc < 0)
		perror("krip");
}

/**
 * Send RIP response packets to my neighbors.
 */
static void krip_dispatch_out()
{
	uint32_t now = krip_get_mtime();
	list_position pos;

	/* If _update_rime has been expired, broadcast RIP response message to neighbors. */
	if (_update_time + _update_interval < now) {
		L_ROUTE("krip_dispatch_out(): regular advertisement on time %d", now);
		for (pos = list_get_head_position(_neighbor_info_list); pos; pos = list_get_next_position(pos)) {
			neighbor_info *ni = list_get_at(pos);
			if (ni->ifp->if_enabled)
				krip_send_response(ni, 0);
		}
		_update_time = now;
	} else if (_trigger) {
	/* If this isn't a regular update, send RIP response messages as a triggered update, and clear change_flag.
	   Originally, we don't need _trigger flag because krip_send_response() advertises only changed entries,
	   but I've added it for convenient logging. */
		L_ROUTE("krip_dispatch_out(): triggered update!");
		for (pos = list_get_head_position(_neighbor_info_list); pos; pos = list_get_next_position(pos)) {
			neighbor_info *ni = list_get_at(pos);
			if (ni->ifp->if_enabled)
				krip_send_response(ni, 1);
		}
		/* krip_send_response() 내에서 clear하지 않는 이유는  */
		for (pos = list_get_head_position(_rip_info_list); pos; pos = list_get_next_position(pos)) {
			rip_info *ri = list_get_at(pos);
			ri->change_flag = 0;
		}
		_trigger = false;
	}
}

/**
 * Send a RIP request packet to a neighbor.
 * @param ni	Neighbor info including its IP address.
 */
static void krip_send_request(neighbor_info *ni)
{
	rip_buf buf;
	memset(&buf, 0, sizeof(buf));
	
	buf.rip_packet.command = RIP_REQUEST;
	buf.rip_packet.version = RIPv2;

	if (sendto(_sock, buf.buf, RIP_HEADER_SIZE, 0,
			(struct sockaddr *)&ni->krip_addr,
			sizeof(struct sockaddr_in)) == -1) {
		perror("krip");
	}
}

/**
 * Send a RIP response packet to a neighbor.
 * @param ni						Neighbor info including its IP address.
 * @param send_changed_info_only	Indicates whether send changed info only
 *									or the whole routing table.
 */
static void krip_send_response(neighbor_info *ni, int send_changed_info_only)
{
	rip_buf buf;
	memset(&buf, 0, sizeof(buf));
	
	buf.rip_packet.command = RIP_RESPONSE;
	buf.rip_packet.version = RIPv2;
	
	int num = 0;	/* Actual index. */
	int vnum = 0;	/* Virtual index for logging. */
	bool sent = false;
	list_position pos = list_get_head_position(_rip_info_list);

	/* Look up the routing info. */
	for (; pos; pos = list_get_next_position(pos)) {
		rip_info *ri = list_get_at(pos);

		/* If send_changed_info_only flag is set, skip unchanged entries. */
		if (send_changed_info_only && !ri->change_flag)
			continue;

		/* ri->from과 ni->ifp를 비교하는 것은 다음과 같은 의미이다:
		    "해당 routing info를 받은 interface와 보낼 neighbor interface를 비교한다."

		   이것을 통해 poisoned reverse나 split horizon 등의 처리를 할 수 있다.

		   Split horizon의 경우는 해당 노드에 정보를 보내지 않음으로써 가장 정확한
		   정보를 알고 있는 해당 노드의 routing table이 잘못된 정보로 채워지는 것을
		   막는 것이고, Poisoned reverse는 그러한 '역류' 경로를 무한대의 metric을
		   가지게 하며 전파를 막는 방법이다.

		   여기서는 Assignment 8번 요구사항대로 split horizon 방식을 사용하였다. */

		if (ri->from != ni->ifp) {
			/* 다를 때는 그냥 그대로 처리한다. */
			rte *rtep = buf.rip_packet.rte + num;	/* Use a location of the buffer directly as the rte pointer. */
			rtep->tag = 0;
			rtep->family = AF_INET;
			rtep->prefix = ri->assoc_rte->dst;
			rtep->mask = ri->assoc_rte->mask;	/* rip version 2 */
			rtep->nexthop.s_addr = 0;			/* rip version 2; via advertiser */
			rtep->metric = ri->metric;
			L_ROUTE("krip_send_response(): [%d] prefix=%s, mask=%s, metric=%d (from {%08x})", vnum+1,
				inet_ntoa(rtep->prefix),
				inet_ntoa(rtep->mask),
				rtep->metric, ri->from);

			/* Convert endians. */
			rtep->tag = htons(rtep->tag);
			rtep->family = htons(rtep->family);
			rtep->metric = htonl(rtep->metric);

			num++;
			vnum++;
		} else {
			/* 같다면 split horizon으로 처리하여 아예 빼버리고 다음 routing info로 넘어간다.
			   만약 poisoned reverse로 할 경우 다른 처리는 그대로 하면서 metric을 무한대로 할당하면 된다. */
			L_ROUTE("krip_send_response(): [%d] skipping an entry for split horizon. (from/to {%08x})", vnum+1, ni->ifp);
			vnum++;
			continue;
		}

		/* 한 번에 실어보낼 수 있는 양이 다 차면 보내고 다시 0번 entry부터 채운다. */
		if (num >= RIP_MAX_RTE) {
			L_ROUTE("krip_send_response(): sending %d entries to %s {%08x}", num, inet_ntoa(ni->virtual_addr), ni->ifp);
			if (sendto(_sock, buf.buf, RIP_HEADER_SIZE + RIP_RTE_SIZE * num, 0,
					(struct sockaddr *)&ni->krip_addr,
					sizeof(struct sockaddr_in)) == -1) {
				perror("krip");
			}
			sent = true;
			num = 0;
		}
	}

	/* 아직 전송하지 않고 남은 것이 있으면 마저 보낸다. */
	if (num > 0) {
		L_ROUTE("krip_send_response(): sending %d entries to %s {%08x}", num, inet_ntoa(ni->virtual_addr), ni->ifp);
		if (sendto(_sock, buf.buf, RIP_HEADER_SIZE + RIP_RTE_SIZE * num, 0,
				(struct sockaddr *)&ni->krip_addr,
				sizeof(struct sockaddr_in)) == -1) {
			perror("krip");
		}
	} else if (!sent) {
		L_ROUTE("krip_send_response(): no entries are sent to %s {%08x}", inet_ntoa(ni->virtual_addr), ni->ifp);
	}
}

/**
 * Calculates the current system time in microseconds.
 * The code is taken from ktcp.c
 */
static u_int krip_get_mtime()
{
	static struct timeval begin_tv = { 0, 0 };
	struct timeval curr_tv;

	if (begin_tv.tv_sec == 0) {
		gettimeofday(&begin_tv, NULL);
		begin_tv.tv_sec = begin_tv.tv_sec - 1;
		begin_tv.tv_usec = 0; /* Ignore the usec of begin_it. */
	}

	gettimeofday(&curr_tv, NULL);
	return (((curr_tv.tv_sec - begin_tv.tv_sec) * 1000) + (curr_tv.tv_usec / 1000));
}

int krip_get_update_interval()
{
	return _update_interval;
}

int krip_set_update_interval(int interval)
{
	_update_interval = interval;
	return 0;
}

int krip_get_timeout()
{
	return _timeout;
}

int krip_set_timeout(int timeout)
{
	_timeout = timeout;
	return 0;
}


/* vim: set fenc=utf8 ts=4 sts=4 sw=4 noet: */

#ifndef _KRIP_H_
#define _KRIP_H_

/* header file for the routed */

#include "iniparser.h"

#define RIPv2						2

#define RIP_REQUEST					1
#define RIP_RESPONSE				2

#define RIP_METRIC_INFINITY			16

#define RIP_PACKET_MINSIZ			4
#define RIP_PACKET_MAXSIZ			512

#define RIP_HEADER_SIZE				4
#define RIP_RTE_SIZE				20
#define RIP_MAX_RTE					25

#define RIP_PORT_OFFSET				1000

typedef struct _rte
{
	u_int16_t family;
	u_int16_t tag;
	struct in_addr prefix;
	struct in_addr mask;
	struct in_addr nexthop;
	u_int32_t metric;
} rte;

typedef struct _rip_packet
{
	unsigned char command;
	unsigned char version;
	unsigned char pad[2];
	rte rte[1];
} rip_packet;

typedef union _rip_buf
{
	struct _rip_packet rip_packet;
	char buf[RIP_PACKET_MAXSIZ];
} rip_buf;

typedef struct _rip_info
{
	rtentry *assoc_rte;
	u_int32_t metric;
	unsigned char change_flag;
	unsigned int timeout;
	ifnet *from;
} rip_info;

typedef struct _neighbor_info
{
	struct in_addr virtual_addr;
	struct sockaddr_in krip_addr;
	ifnet *ifp;
} neighbor_info;

int krip_init(dictionary *conf);
int krip_shutdown(void);
int krip_dispatch(void);

int krip_get_update_interval();
int krip_set_update_interval(int interval);
int krip_get_timeout();
int krip_set_timeout(int timeout);

#endif

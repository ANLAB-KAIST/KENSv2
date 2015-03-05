/*
 * kip.h
 * 
 * CS244A Winter 2001 (Assignment #3)
 *
 */


/* header file for the transport layer */

#ifndef _KIP_H_
#define _KIP_H_

#include <netinet/in.h>

#include "iniparser.h"

#include "route.h"

#define KIP_HEADER_SIZE	20
#define KIP_DEFAULT_TTL	7
#define KIP_VERSION			4

#define IPERR_TOOSMALL		-1
#define IPERR_BADVERSION	-2
#define IPERR_BADCHECKSUM	-3
#define IPERR_BADLEN		-4
#define IPERR_UNSUPPORTED	-5
#define IPERR_ROUTINGFAILED	-6

#define IP_FORWARDING		0x01
#define IP_ROUTETOIF		0x02
#define IP_ALLOWBROADCAST	0x10
#define IP_RAWOUTPUT		0x20

extern int ip_init(dictionary *conf);
extern int ip_shutdown(void);
extern int ip_input(void *ip_buf,int len);
extern int ip_output(struct in_addr src,struct in_addr dst,void *buf,size_t len,route *ro);
extern int ip_dispatch();
extern void ip_invalidate_forward_rt_cache(void);

uint32_t ip_host_address(struct in_addr in);

#endif


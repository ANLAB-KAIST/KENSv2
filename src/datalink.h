#ifndef DATALINK_H
#define DATALINK_H

#include <netinet/in.h>

#include "config.h"
#include "iniparser.h"

#ifdef HAVE_POLL
#include <poll.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#endif


#define IF_PREFIX		"seth"
#define DEFAULT_IF		IF_PREFIX"0"


#define NETWORK_BUFFER_SIZE	16384

typedef struct _mac_addr_entry {
	struct in_addr vip;
	struct sockaddr_in mac;
} MAC_ADDR_ENTRY;

#define MAC_ADDR_ENTRY_set_vip(e,v)	(e)->vip = (v)
#define MAC_ADDR_ENTRY_set_mac(e,m)	memcpy(&(e)->mac,(m),sizeof(struct sockaddr))
#define MAC_ADDR_ENTRY_get_vip(e)	((e)->vip)
#define MAC_ADDR_ENTRY_get_mac(e)	((e)->mac)

typedef struct _mac_table {
	void *ctx;
	int (*mac_add)(void **ctx,MAC_ADDR_ENTRY *e);
	struct sockaddr_in *(*mac_lookup)(void *ctx,struct in_addr vip);
	void (*mac_free)(void *ctx);
} MAC_TABLE;

#define MAC_TABLE_get_by_index(t,i)		((t)->table[(i)])
#define MAC_TABLE_get_by_addr(t,addr)	MAC_TABLE_get_by_index(t,(unsigned char)((addr).s_addr&0xff))
#define MAC_TABLE_set_by_index(t,i,e)	((t)->table[(i)] = e)
#define MAC_TABLE_set_by_addr(t,e)		MAC_TABLE_set_by_index(t,(unsigned char)((MAC_ADDR_ENTRY_get_vip(e)).s_addr&0xff),e)

typedef struct ifaddr_t ifaddr;
typedef struct ifnet_t ifnet;
typedef struct in_ifaddr_t in_ifaddr;

/* datalink driver */
typedef struct eth_driver_t eth_driver;
typedef struct lo_driver_t lo_driver;

struct ifaddr_t {
	struct ifaddr_t *ifa_next;
	ifnet *ifa_ifp;
	struct in_addr ifa_addr;
	struct in_addr ifa_netmask;
	unsigned short ifa_flags;
	short ifa_refcnt;
	int ifa_metric;
};

struct ifnet_t {
	struct ifnet_t *if_next;
	ifaddr *if_addrlist;
	char *if_name;
	short if_unit;
	short if_flags;

	int if_enabled;

	void *ctx;

#define	METHOD_POLL		0
#define METHOD_SELECT	1

	int (*if_init)(ifnet *ifp,void *arg);
	int (*if_input)(ifnet *ifp,unsigned char *buf,size_t len,struct sockaddr_in *from,int *fromlen);
	int (*if_output)(ifnet *ifp,unsigned char *data,size_t len,struct in_addr dst);
	int (*if_shutdown)(ifnet *ifp);

	/* 
	 * Jara: packet counters are mostly based on IF-MIB.
	 */
#ifdef HAVE_IF_STATS
#define IS_BROADCAST(hdr) \
	(((struct ip*)hdr)->ip_v == 4 && \
	 ((struct ip*)hdr)->ip_dst.s_addr == INADDR_BROADCAST)
#define IS_MULTICAST(hdr) \
	(((struct ip*)hdr)->ip_v == 4 && \
	 IN_MULTICAST(((struct ip*)hdr)->ip_dst.s_addr))
	  
	unsigned int ifInOctet;
	unsigned int ifInPkts;
	unsigned int ifInUcastPkts;
	unsigned int ifInMulticastPkts;
	unsigned int ifInBroadcastPkts;
	unsigned int ifInDiscards;
	unsigned int ifInErrors;

	unsigned int ifOutOctets;
	unsigned int ifOutPkts;
	unsigned int ifOutUcastPkts;
	unsigned int ifOutMulticastPkts;
	unsigned int ifOutBroadcastPkts;
	unsigned int ifOutDiscards;
	unsigned int ifOutErrors;
#endif /* HAVE_IF_STATS */
};

struct lo_driver_t {
	int sd;	/* udp socket */
#ifdef HAVE_POLL
	struct pollfd *pfd;
#else
	fd_set *fds;
#endif
	struct sockaddr_in sin;
};

struct eth_driver_t {
	int sd;	/* udp socket */
#ifdef HAVE_POLL
	struct pollfd *pfd;
#else
	fd_set *fds;
#endif
	MAC_TABLE *t_mac;
};

#define IN_ADDR(in)		((in)->if_addrlist->ifa_addr)
#define IN_MASK(in)		((in)->if_addrlist->ifa_netmask)

struct in_ifaddr_t {
	struct in_ifaddr_t *ia_next;
	ifaddr *ifa;
};

extern ifnet *_ifnet;
extern in_ifaddr *_in_ifaddr;

int dl_init(dictionary *conf);
void dl_output(ifnet *ifp,unsigned char *data,size_t len,struct in_addr dst);
void dl_dispatch(void);
void dl_shutdown(void);

MAC_TABLE *MAC_TABLE_new(void);
MAC_TABLE *MAC_TABLE_load(const char *path,const char *fn);
struct sockaddr_in *MAC_TABLE_lookup(MAC_TABLE *table,struct in_addr vip);
void MAC_TABLE_free(MAC_TABLE* table);


ifnet *ifunit(char *name);
ifaddr *ifa_ifwithaddr(struct in_addr addr);
ifaddr *ifa_ifwithdstaddr(struct in_addr addr);

int in_localnet(ifnet *ifp,struct in_addr in);


int dl_get_delay();
int dl_set_delay(int delay);
float dl_get_drop_rate();
int dl_set_drop_rate(float rate);
float dl_get_reorder_rate();
int dl_set_reorder_rate(float rate);

int dl_get_enable_seth(int major);
int dl_set_enable_seth(int major);
int dl_get_disable_seth(int major);
int dl_set_disable_seth(int major);

#endif

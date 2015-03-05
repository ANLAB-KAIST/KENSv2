#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "iniparser.h"

#include "datalink.h"
#include "kip.h"
#include "log.h"
#include "misc.h"
#include "linked_list.h"

#include "kmgmt.h"

#if defined(HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

#define FLD_ADDRESS		"address"
#define FLD_NETMASK		"netmask"
#define FLD_GATEWAY		"gateway"

extern int pcap_log_fd;
extern unsigned int random_seed;
typedef struct pcap_packet_t {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcap_packet;

ifnet *_ifnet = NULL;
static ifnet *_ifnet_tail = NULL;
static int _ifnet_count = 0;
static int _max_sd = -1;
static int _unreliable = 0;

in_ifaddr *_in_ifaddr = NULL;
static in_ifaddr *_in_ifaddr_tail = NULL;

#ifdef HAVE_POLL
static struct pollfd *_pfd;
#else
static fd_set _fds;
#endif

static unsigned char netbuf[NETWORK_BUFFER_SIZE];

/* unreliable network */
#define MAX_BUF		3
typedef struct _buffer {
	ifnet *ifp;
	unsigned char data[NETWORK_BUFFER_SIZE];
	int len;
	struct in_addr dst;
	u_int timestamp;
} buffer;

static int _delay;
static float _drop_rate;
static float _reorder_rate;

static list _delayed_packet_list;
static buffer* _reordering_buf[MAX_BUF];
static int _reordering_buf_size;
static unsigned int _last_fetch;

static void dl_dispatch_out();
static u_int dl_get_mtime();

static int dl_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values);

/*
 * loop back device
 */

/**
 * initialize local loopback device lo
 */
static int lo_init(ifnet *ifp,void *arg)
{
	lo_driver *drv;

	if ( ifp == NULL ) return 0;

	drv = (lo_driver *)ifp->ctx;

#ifdef HAVE_POLL
	drv->pfd = (struct pollfd *)arg;
	drv->pfd->fd = drv->sd;
	drv->pfd->events = POLLIN;
#else
	drv->fds = (fd_set *)arg;
	FD_SET(drv->sd,drv->fds);
#endif

	return 0;
}

static int lo_input(ifnet *ifp,unsigned char *buf,size_t len,struct sockaddr_in *from,int *fromlen)
{
	lo_driver *drv = (lo_driver *)ifp->ctx;
#ifdef HAVE_POLL
	if ( !(drv->pfd->revents & POLLIN) ) return 0;	
#else
	if ( !FD_ISSET(drv->sd,drv->fds) ) return 0;
#endif

	return recvfrom(drv->sd,buf,len,0,(struct sockaddr *)from,fromlen);
}

static int lo_output(ifnet *ifp,unsigned char *data,size_t len,struct in_addr dst)
{
	lo_driver *drv = (lo_driver *)ifp->ctx;

	return sendto(drv->sd,data,len,0,(struct sockaddr *)&drv->sin,sizeof(struct sockaddr_in));
}

static int lo_shutdown(ifnet *ifp)
{
	lo_driver *drv;

	if ( ifp == NULL ) return 0;

	if ( ifp->ctx != NULL ) 
	{
		drv = (lo_driver *)ifp->ctx;
		close(drv->sd);
	}

	return 0;
}

static void lo_setup(void)
{
	ifnet *ifp = NULL;
	ifaddr *ifa = NULL;
	lo_driver *drv;
	struct sockaddr_in sin;
	int size;

	ifp = (ifnet *)malloc(sizeof(ifnet));
	assert( ifp );

	ifp->if_next = NULL;
	ifp->if_name = strdup("lo");
	ifp->if_unit = 0;
	ifp->if_enabled = 1;

	ifa = (ifaddr *)malloc(sizeof(ifaddr));
	ifa->ifa_next = NULL;
	ifa->ifa_ifp = ifp;
	ifa->ifa_flags = 0;
	ifa->ifa_refcnt = 0;
	ifa->ifa_metric = 0;
	inet_aton("127.0.0.1",&ifa->ifa_addr);
	inet_aton("255.0.0.0",&ifa->ifa_netmask);

	_in_ifaddr_tail = (in_ifaddr *)malloc(sizeof(in_ifaddr));
	_in_ifaddr = _in_ifaddr_tail;
	assert( _in_ifaddr_tail );

	_in_ifaddr_tail->ifa = ifa;
	_in_ifaddr_tail->ia_next = NULL;

	ifp->if_addrlist = ifa;

	/* initialize driver */
	ifp->ctx = (void *)malloc(sizeof(lo_driver));
	assert(ifp->ctx);
	drv = (lo_driver *)ifp->ctx;

	if ( (drv->sd = socket(AF_INET,SOCK_DGRAM,0)) < 0 ) {
		/* error */
	}
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(0);
	sin.sin_addr.s_addr = INADDR_ANY;
	size = sizeof(struct sockaddr_in);

	if ( bind(drv->sd,(struct sockaddr *)&sin,size) < 0 ) {
		/* error */
	}

	size = sizeof(struct sockaddr_in);
	getsockname(drv->sd,(struct sockaddr *)&drv->sin,&size);

	_max_sd = ( drv->sd > _max_sd ) ? drv->sd : _max_sd;

	ifp->if_init = lo_init;
	ifp->if_input = lo_input;
	ifp->if_output = lo_output;
	ifp->if_shutdown = lo_shutdown;
	/* end of driver initialization */

	_ifnet = ifp;
	_ifnet_tail = ifp;
	_ifnet_count++;
}

/*
 * ethernet emulation setup
 */
static int ether_init(ifnet *ifp,void *arg)
{
	eth_driver *drv;

	if ( ifp == NULL ) return 0;

	drv = (eth_driver *)ifp->ctx;

#ifdef HAVE_POLL
	drv->pfd = (struct pollfd *)arg;
	drv->pfd->fd = drv->sd;
	drv->pfd->events = POLLIN;
#else
	drv->fds = (fd_set *)arg;
	FD_SET(drv->sd,(fd_set *)arg);
#endif

	return 0;
}

static int ether_input(ifnet *ifp,unsigned char *buf,size_t len,struct sockaddr_in *from,int *fromlen)
{
	eth_driver *drv = (eth_driver *)ifp->ctx;
#ifdef HAVE_POLL
	if ( !(drv->pfd->revents & POLLIN) ) return 0;	
#else
	if ( !FD_ISSET(drv->sd,drv->fds) ) return 0;
#endif

	return recvfrom(drv->sd,buf,len,0,(struct sockaddr *)from,fromlen);
}

static int ether_output(ifnet *ifp,unsigned char *data,size_t len,struct in_addr dst)
{
	eth_driver *drv = (eth_driver *)ifp->ctx;
	struct sockaddr *sin = NULL;
	caddr_t c = NULL;
	int l = 0;

	sin = (struct sockaddr *)MAC_TABLE_lookup(drv->t_mac,dst);
	if ( sin != NULL ) {
		c = (caddr_t)&((struct sockaddr_in *)sin)->sin_addr;
		T_LINK("send packet to %s(%d.%d.%d.%d:%d)",
				inet_ntoa(dst),
				(unsigned char)c[0],
				(unsigned char)c[1],
				(unsigned char)c[2],
				(unsigned char)c[3],
				ntohs( ((struct sockaddr_in *)sin)->sin_port )
			  );

		l = sendto(drv->sd,data,len,0,sin,sizeof(struct sockaddr_in));
	} else {
		T_LINK("unreachable host %s",inet_ntoa(dst));
	}

	return l;
}

static int ether_shutdown(ifnet *ifp)
{
	eth_driver *drv;

	if ( ifp == NULL ) return 0;

	if ( ifp->ctx != NULL ) {
		drv = (eth_driver *)ifp->ctx;
		close(drv->sd);
		if ( drv->t_mac != NULL )
			MAC_TABLE_free(drv->t_mac);
	}

	return 0;
}

/* end of drivers */



static int ifaddr_set(dictionary *conf,ifnet *ifp,ifaddr *ifa,char *prefix)
{
	char addr[256],mask[256];
	char *ip,*nm;
	int rc;

	sprintf(addr,"%s:"FLD_ADDRESS,prefix);
	sprintf(mask,"%s:"FLD_NETMASK,prefix);

	if ( (ip = iniparser_getstring(conf,addr,NULL)) == NULL
			|| (nm = iniparser_getstring(conf,mask,NULL)) == NULL )
		return -1;

	ifa->ifa_next = NULL;
	ifa->ifa_ifp = ifp;
	ifa->ifa_flags = 0;
	ifa->ifa_refcnt = 0;
	ifa->ifa_metric = 0;

	if ( !(rc = inet_aton(ip,&ifa->ifa_addr)) ) {
		/* error */
		return -1;
	}

	if ( !(rc = inet_aton(nm,&ifa->ifa_netmask)) ) {
		/* error */
		return -1;
	}

	if ( _in_ifaddr_tail == NULL ) {
		_in_ifaddr_tail = (in_ifaddr *)malloc(sizeof(in_ifaddr));
		_in_ifaddr = _in_ifaddr_tail;
	} else {
		_in_ifaddr_tail->ia_next = (in_ifaddr *)malloc(sizeof(in_ifaddr));
		_in_ifaddr_tail = _in_ifaddr_tail->ia_next;
	}

	assert( _in_ifaddr_tail );

	_in_ifaddr_tail->ifa = ifa;
	_in_ifaddr_tail->ia_next = NULL;

	return 0;
}

static int ifnet_init_ifaddrlist(dictionary *conf,ifnet *ifp,char *prefix)
{
	char key[256];
	int minor;
	ifaddr *ifa = NULL,*prev;
	ifaddr t;

	ifp->if_addrlist = (ifaddr *)malloc(sizeof(ifaddr));
	ifa = ifp->if_addrlist;
	assert( ifa );

	/* get major device address */
	if ( ifaddr_set(conf,ifp,ifa,prefix) ) {
		/* end */
		goto error;
	}

	prev = ifa;

	/* setup minor device addresses */
	for ( minor = 0; ; minor++ ) {
		sprintf(key,"%s:%d",prefix,minor);
		if ( ifaddr_set(conf,ifp,&t,key) ) break;
		prev->ifa_next = (ifaddr *)malloc(sizeof(ifaddr));
		assert( prev->ifa_next );
		memcpy(prev->ifa_next,&t,sizeof(ifaddr));
		prev = prev->ifa_next;
	}

error:

	return 0;
}

int ifnet_init(dictionary *conf,int major)
{
	char prefix[128];
	ifnet *ifp;
	ifaddr *ifa;
	struct sockaddr_in sin;
	struct sockaddr_in *sin2;
	char *svrname;
	eth_driver *drv;

	svrname = iniparser_getstring(conf,"KENS:server_name","KENS");

	sprintf(prefix,IF_PREFIX"%d",major);

	if ( !iniparser_find_entry(conf,prefix) ) return -1;	/* not found */

	/* we got an interface section */
	ifp = (ifnet *)malloc(sizeof(ifnet));
	assert( ifp );

	ifp->if_next = NULL;
	ifp->if_name = strdup(IF_PREFIX);
	ifp->if_unit = major;
	ifp->if_enabled = 1;

	ifnet_init_ifaddrlist(conf,ifp,prefix);

	ifa = ifp->if_addrlist;

	sprintf(prefix,"%s_"IF_PREFIX"%d",svrname,major);

	ifp->if_init = ether_init;	
	ifp->if_input = ether_input;
	ifp->if_output = ether_output;
	ifp->if_shutdown = ether_shutdown;

	/* intialize ethernet emulation driver */
	ifp->ctx = (void *)malloc(sizeof(eth_driver));
	assert( ifp->ctx );
	drv = (eth_driver *)ifp->ctx;

	drv->t_mac = MAC_TABLE_load(NULL,prefix);

	/* create socket */
	if ( (drv->sd = socket(AF_INET,SOCK_DGRAM,0)) < 0 ) {
		/* error */
	}

	_max_sd = ( drv->sd > _max_sd ) ? drv->sd : _max_sd;

	sin2 = MAC_TABLE_lookup(drv->t_mac,IN_ADDR(ifp));
	if ( sin2 == NULL ) {
		/* error */
	}
	memcpy(&sin,sin2,sizeof(struct sockaddr_in));
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if ( bind(drv->sd, (struct sockaddr *)&sin,sizeof(sin)) < 0 ) {
		/* error */
		perror("bind");
		fprintf(stderr,"failed to bind port %d",ntohs(sin.sin_port));
		fflush(stderr);
	}

	/* end of driver initialization */

	/* now append to list */
	if ( _ifnet == NULL ) {
		_ifnet = ifp;
	} else {
		_ifnet_tail->if_next = ifp;
	}
	_ifnet_tail = ifp;
	_ifnet_count++;

	return 0;
}

/**
 * @param file path to datalink configuration file 
 * @return 0 when success, other when errors
 */
int dl_init(dictionary *conf)
{
	ifnet *ifp;
	int i, major = 0;
	char *c;

	lo_setup();

	while ( !ifnet_init(conf,major) ) major++;

	_max_sd = _max_sd + 1;

#ifdef HAVE_POLL
	/* initialize pollfd */
	_pfd = (struct pollfd *)malloc(sizeof(struct pollfd)*_ifnet_count);
	assert( _pfd );

	for ( i = 0,ifp = _ifnet; i < _ifnet_count; i++,ifp = ifp->if_next ) {
		(*ifp->if_init)(ifp,&_pfd[i]);
	}
#endif

	c = iniparser_getstring(conf,"KENS:unreliable","false");
	if ( !strcasecmp(c,"true") ) {
		_unreliable = 1;

		memset(_reordering_buf, 0, sizeof(_reordering_buf));
		_reordering_buf_size = 0;

		c = iniparser_getstring(conf,"KENS:datalink_delay","0");
		_delay = atoi(c);

		c = iniparser_getstring(conf,"KENS:datalink_drop_rate","0.1");
		_drop_rate = atof(c);

		c = iniparser_getstring(conf,"KENS:datalink_reorder_rate","0.1");
		_reorder_rate = atof(c);

		_delayed_packet_list = list_open();
		_last_fetch = 0;
	}

	/* register for kmgmt */
	kmgmt_register (KMOD_DATALINK, KXML_MOD_DATALINK, dl_kmgmt_handler);

	srand((getpid()*getppid())^time(NULL));

	return 0;
}

static void output(ifnet *ifp,unsigned char *data,size_t len,struct in_addr dst)
{
	int l;

	if (!ifp->if_enabled) {
		return;
	}

	l = (*ifp->if_output)(ifp,data,len,dst);
	if ( l < 0 ) {
		T_LINK("device %s%d error : %s",ifp->if_name,ifp->if_unit,strerror(errno));

#ifdef HAVE_IF_STATS
		/* ifOutErrors */
		ifp->ifOutErrors++;
#endif /* HAVE_IF_STATS */
	} else {
		T_LINK("%d bytes sent through device %s%d",l,ifp->if_name,ifp->if_unit);
		if(pcap_log_fd != -1)
		{
			pcap_packet header;
			header.incl_len = len;
			header.orig_len = len;

			struct timeval tv;
			gettimeofday(&tv, 0);
			header.ts_sec = tv.tv_sec;
			header.ts_usec = tv.tv_usec;

			write(pcap_log_fd, &header, sizeof(pcap_packet));
			write(pcap_log_fd, data, len);
		}

#ifdef HAVE_IF_STATS
		/* 
		 * ifOutOctets
		 * ifOutUcastPkts
		 * ifOutMulticastPkts
		 * ifOutBroadcastPkts
		 */
		if (IS_BROADCAST(data))
			ifp->ifOutBroadcastPkts++;
		else if (IS_MULTICAST(data))
			ifp->ifOutMulticastPkts++;
		else
			ifp->ifOutUcastPkts++;

		ifp->ifOutPkts++;
		ifp->ifOutOctets += len;
#endif /* HAVE_IF_STATS */
	}
}

void dl_output(ifnet *ifp,unsigned char *data,size_t len,struct in_addr dst)
{
	int l,i;
	buffer *b = NULL;

	if (_unreliable) {
		/* give this packet a delay */
		b = (buffer*)malloc(sizeof(buffer));
		b->ifp = ifp;
		memcpy(b->data, data, len);
		b->len = len;
		b->dst.s_addr = dst.s_addr;
		b->timestamp = dl_get_mtime();

		list_add_tail(_delayed_packet_list, b);
	}
	else
		output(ifp, data, len, dst);
}

void dl_dispatch(void)
{
	int rc;
	int i,l;
	ifnet *ifp;
	struct sockaddr_in from;
	int fromlen;
	caddr_t c;

	if (_unreliable)
		dl_dispatch_out();

#ifdef HAVE_POLL
	if ( (rc = poll(_pfd,_ifnet_count,1)) > 0 ) {	/* wait for 1ms */
		/* do nothing */
	} else if ( rc == 0 ) {
		/* silently discard */
		return;
	} else {
		perror("datalink:poll");
		return;
	}
#else
	{
		struct timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 1000;

		/* set socket descripters */
		for ( i = 0,ifp = _ifnet; i < _ifnet_count; i++,ifp = ifp->if_next )
			(*ifp->if_init)(ifp,&_fds);

		if ( (rc = select(_max_sd,&_fds,NULL,NULL,&timeout)) > 0 ) {
			/* do nothing */
		} else if ( rc == 0 ) {
			/* silently discard */
			return;
		} else {
			perror("datalink:select");
			return;
		}
	}
#endif
	/* we have serveral packets from network */
	for ( i = 0,ifp = _ifnet; i < _ifnet_count; i++,ifp = ifp->if_next ) {
		fromlen = sizeof(struct sockaddr_in);
		l = (*ifp->if_input)(ifp,netbuf,NETWORK_BUFFER_SIZE,&from,&fromlen);
		if ( l == 0 ) continue;

		if (!ifp->if_enabled) {
			continue;
		}

		c = (caddr_t)&from.sin_addr;
		T_LINK("receive %d bytes packet from %d.%d.%d.%d:%d",
				l,
				(unsigned char)c[0],
				(unsigned char)c[1],
				(unsigned char)c[2],
				(unsigned char)c[3],
				ntohs( from.sin_port )
			  );
		if(pcap_log_fd != -1)
		{
			pcap_packet header;
			header.incl_len = l;
			header.orig_len = l;

			struct timeval tv;
			gettimeofday(&tv, 0);
			header.ts_sec = tv.tv_sec;
			header.ts_usec = tv.tv_usec;

			write(pcap_log_fd, &header, sizeof(pcap_packet));
			write(pcap_log_fd, netbuf, l);
		}

#ifdef HAVE_IF_STATS
		/* 
		 * ifInOctet
		 * ifInUcastPkts
		 * ifInMulticastPkts
		 * ifInBroadcastPkts
		 */
		if (IS_BROADCAST(netbuf))
			ifp->ifInBroadcastPkts++;
		else if (IS_MULTICAST(netbuf))
			ifp->ifInMulticastPkts++;
		else
			ifp->ifInUcastPkts++;

		ifp->ifInPkts++;
		ifp->ifInOctet += l;
#endif /* HAVE_IF_STATS */

		ip_input(netbuf,l);
	}
}

void dl_shutdown(void)
{
	if (_unreliable)
	{
		list_position pos = list_get_head_position(_delayed_packet_list);
		for (; pos; pos = list_get_next_position(pos))
			free(list_get_at(pos));
		list_close(_delayed_packet_list);
	}

	ifnet *ifp,*if_next;
	in_ifaddr *ia,*ia_next;

	for ( ia = _in_ifaddr; ia; ia = ia_next ) {
		ia_next = ia->ia_next;
		if ( ia->ifa != NULL ) free(ia->ifa);
		ia->ifa = NULL;
		ia->ia_next = NULL;
		free(ia);
	}

	for ( ifp = _ifnet; ifp; ifp = if_next ) {
		if_next = ifp->if_next;
		ifp->if_addrlist = NULL;
		free(ifp->if_name);
		if ( ifp->if_shutdown != NULL )
			(*ifp->if_shutdown)(ifp);
		free(ifp);
	}

#ifdef HAVE_POLL
	if ( _pfd != NULL ) free(_pfd);
	_pfd = NULL;
#endif
}

/*
 * utility functions
 */

/* look up interface list to find an interface match to name */
ifnet *ifunit(char *name)
{
	ifnet *ifp = _ifnet;
	char buf[32];
	char *p;
	int unit;

	sprintf(buf,"%s",name);
	p = eat_alpha(buf);
	unit = ( p == NULL ) ? 0 : atoi(p);
	if ( p != NULL ) *p = '\0';

	while ( ifp != NULL ) {
		if ( !strcmp(buf,ifp->if_name) && ifp->if_unit == unit )
			return ifp;
		ifp = ifp->if_next;
	}

	return NULL;
}

ifaddr *ifa_ifwithaddr(struct in_addr addr)
{
	in_ifaddr *inif = _in_ifaddr;
	ifaddr *ifa;

	while ( inif != NULL ) {
		ifa = inif->ifa;
		/* check address */
		if ( ifa->ifa_addr.s_addr == addr.s_addr ) return ifa;
		inif = inif->ia_next;
	}

	return NULL;
}

ifaddr *ifa_ifwithdstaddr(struct in_addr addr)
{
	/* look up routing table */
	return NULL;
}

int in_localnet(ifnet *ifp,struct in_addr in)
{
	ifaddr *ifa;

	for ( ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next ) {
		if ( (in.s_addr & ifa->ifa_netmask.s_addr)
				== (ifa->ifa_addr.s_addr & ifa->ifa_netmask.s_addr) )
			return 1;
	}

	return 0;
}

static void dl_dispatch_out()
{
	u_int now;
	int i, j;
	buffer *b, *try_b;
	int done = 0;

	now = dl_get_mtime();

	while (!done)
	{
		done = 1;

		/* fetch packets from _delayed_packet_list */
		if (list_get_count(_delayed_packet_list) > 0) {
			b = (buffer*)list_get_head(_delayed_packet_list);

			if (now - b->timestamp >= _delay) {
				list_remove_head(_delayed_packet_list);
				_reordering_buf[_reordering_buf_size++] = b;
				_last_fetch = now;
				done = 0;
			}
		}

		if (_reordering_buf_size == MAX_BUF ||
				(_reordering_buf_size >= 0 && now - _last_fetch >= 10)) {
			/* drop/reorder */
			for (i = 0; i < _reordering_buf_size; i++) {
				float r = (float)rand_r(&random_seed) / RAND_MAX;
				if (r < _drop_rate) {
					/* drop packet */
#ifdef HAVE_IF_STATS
					/*
					 * ifOutDiscards
					 */
					_reordering_buf[i]->ifp->ifOutDiscards++;
#endif /* HAVE_IF_STATS */
					free(_reordering_buf[i]);
					_reordering_buf[i] = NULL;
					T_LINK("packet dropped");
				}
				else if (r < _drop_rate + _reorder_rate)
				{
					/* reorder packet */
					j = rand_r(&random_seed) % MAX_BUF;
					buffer *temp = _reordering_buf[i];
					_reordering_buf[i] = _reordering_buf[j];
					_reordering_buf[j] = temp;
					T_LINK("packet reordered");
				}
			}

			/* send packets */
			for (i = 0; i < MAX_BUF; i++) {
				if (_reordering_buf[i] == NULL)
					continue;
				output(_reordering_buf[i]->ifp, _reordering_buf[i]->data,
						_reordering_buf[i]->len, _reordering_buf[i]->dst);
				free(_reordering_buf[i]);
				_reordering_buf[i] = NULL;
			}

			_reordering_buf_size = 0;
		}
	}
}

static u_int dl_get_mtime()
{
	/* taken from ktcp.c */
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


int dl_get_delay()
{
	if (_unreliable)
		return _delay;
	else
		return 0;
}

int dl_set_delay(int delay)
{
	if (_unreliable) {
		_delay = delay;
		T_LINK("new delay: %d", delay);
		return 0;
	}
	else
		return -1;
}

float dl_get_drop_rate()
{
	if (_unreliable)
		return _drop_rate;
	else
		return 0.0f;
}

int dl_set_drop_rate(float rate)
{
	if (_unreliable) {
		_drop_rate = rate;
		T_LINK("new drop_rate: %f", rate);
		return 0;
	}
	else
		return -1;
}

float dl_get_reorder_rate()
{
	if (_unreliable)
		return _reorder_rate;
	else
		return 0.0f;
}

int dl_set_reorder_rate(float rate)
{
	if (_unreliable) {
		_reorder_rate = rate;
		T_LINK("new reorder_rate: %f", rate);
		return 0;
	}
	else
		return -1;
}

int dl_get_enable_seth(int major)
{
	ifnet *ifp = _ifnet;
	while (ifp)
	{
		if (strcmp(ifp->if_name, IF_PREFIX) == 0 && ifp->if_unit == major)
			return ifp->if_enabled;
		ifp = ifp->if_next;
	}
	return -1;
}

int dl_set_enable_seth(int major)
{
	ifnet *ifp = _ifnet;
	while (ifp)
	{
		if (strcmp(ifp->if_name, IF_PREFIX) == 0 && ifp->if_unit == major) {
			ifp->if_enabled = 1;
			T_LINK("enable_seth: %d", major);
			return 0;
		}
		ifp = ifp->if_next;
	}
	return -1;
}

int dl_get_disable_seth(int major)
{
	ifnet *ifp = _ifnet;
	while (ifp)
	{
		if (strcmp(ifp->if_name, IF_PREFIX) == 0 && ifp->if_unit == major)
			return 1 - ifp->if_enabled;
		ifp = ifp->if_next;
	}
	return -1;
}

int dl_set_disable_seth(int major)
{
	ifnet *ifp = _ifnet;
	while (ifp)
	{
		if (strcmp(ifp->if_name, IF_PREFIX) == 0 && ifp->if_unit == major) {
			ifp->if_enabled = 0;
			T_LINK("disable_seth: %d", major);
			return 0;
		}
		ifp = ifp->if_next;
	}
	return -1;
}


#undef DEBUG

#ifdef DEBUG
#define DBG(x...) do { \
	fprintf (stderr, x); \
} while (0)
#else
#define DBG(x...)
#endif

/**
 * When KensG requests for datalink data, dl_kmgmt_handler() is called.
 * "physics" table maintains only one row.
 *    * delay (RW)
 *    * unreliable (RW)
 *    * drop_rate (RW)
 *    * reorder_rate (RW)
 * "interface" table maintains an index of "index name"
 *    * name (RO)
 *    * enable (RW)
 *    * in_octet (RO)
 *    * out_octet (RO)
 *    * in_packet (RO)
 *    * out_packet (RO)
 *
 * @param	modid module id
 *			cmd either get/set
 *			table table name, either "physics" or "interface"
 *			index index for the table.
 *			rindex for "get"
 *			nparam # of requested parameters
 *			nvalue # of returned parameters for "get"
 *			params list of requested parameters
 *			values list of returned parameters
 * @return  error code
 */
static int dl_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values)
{
	list_position param_pos = NULL;

	n_linked_list_t *entry = NULL;
	kmgmt_param_t *inattr = NULL;
	kmgmt_param_t *outattr = NULL;

#undef BUFSIZ
#define BUFSIZ	1024
	char buffer[BUFSIZ];
	char *value = NULL;

	ifnet *ifp, *if_next;

	if (cmd < 0 || cmd >= KMGMT_MAX)
	{
		return FAILED;
	}

	/* Interface Table */
	if (table != NULL && strcmp(table,"physics") == 0)
	{
		/* ignore any index */
		entry = NULL;
		inattr = NULL;
		outattr = NULL;

		if (cmd == KMGMT_GET)
		{
			entry = (n_linked_list_t*)malloc (sizeof(n_linked_list_t));
			entry->l = list_open();
			entry->index = NULL; /* no index */
		}

		param_pos = list_get_head_position (params);

		while (param_pos != NULL)
		{
			value = NULL;

			inattr = (kmgmt_param_t*)list_get_at (param_pos);
			if (!inattr)
			{
				param_pos = list_get_next_position (param_pos);
				continue;
			}

			DBG ("datalink parameters: %s - ", inattr->param);

			if (!strcmp(inattr->param, "delay"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%d", dl_get_delay());
					value = strdup (buffer);
					DBG ("%s", buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					int delay = atoi (inattr->value);
					DBG ("%d", delay);
					if (dl_set_delay (delay) != 0)
					{
						goto error;
					}
				}
			}
			else if (!strcmp(inattr->param, "unreliable"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", _unreliable?"true":"false");
					value = strdup(buffer);
					DBG ("%s", buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					DBG ("%s", inattr->value);
					if (strcmp(inattr->value, "true") == 0)
					{
						_unreliable = 1;
					}
					else if (strcmp(inattr->value, "false") == 0)
					{
						_unreliable = 0;
					}
				}
			}
			else if (!strcmp(inattr->param, "drop_rate"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%f", dl_get_drop_rate());
					value = strdup (buffer);
					DBG ("%s", buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					float drop_rate = (float)atof (inattr->value);
					DBG ("%f", drop_rate);
					if (dl_set_drop_rate (drop_rate) != 0)
					{
						goto error;
					}
				}
			}
			else if (!strcmp(inattr->param, "reorder_rate"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%f", dl_get_reorder_rate());
					value = strdup (buffer);
					DBG ("%s", buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					float rate = (float)atof (inattr->value);
					DBG ("%f", rate);
					if (dl_set_reorder_rate (rate) != 0)
					{
						goto error;
					}
				}
			}
			else
			{
				DBG ("Unknown parameter.");
			}

			DBG ("\n");

			if (cmd == KMGMT_GET)
			{
				if (value != NULL)
				{
					outattr = (kmgmt_param_t*)malloc (sizeof(kmgmt_param_t));
					outattr->param = strdup (inattr->param);
					outattr->value = value;

					list_add_tail (entry->l, (void*)outattr);
				}
			}

			param_pos = list_get_next_position (param_pos);
		}

		if (entry != NULL)
			list_add_tail (values, (void*)entry);
	}
	else if (table != NULL && strcmp(table, "interface") == 0)
	{
		/* iterate through iftable if the index matches set it to values. */
		for (ifp = _ifnet; ifp; ifp = if_next) {
			if (ifp == NULL)
				break;

			if (index != NULL)
			{
				sprintf (buffer, "%s%d", ifp->if_name, ifp->if_unit);

				if (strcmp (index, buffer) != 0)
					goto end_of_for;
			}

			entry = NULL;
			inattr = NULL;
			outattr = NULL;

			if (cmd == KMGMT_GET)
			{
				entry = (n_linked_list_t*)malloc (sizeof(n_linked_list_t));
				entry->l = list_open();
				sprintf (buffer, "%s%d", ifp->if_name, ifp->if_unit);
				entry->index = strdup (buffer);
			}

			param_pos = list_get_head_position (params);

			while (param_pos != NULL)
			{
				value = NULL;

				inattr = (kmgmt_param_t*)list_get_at (param_pos);
				if (!inattr)
				{
					param_pos = list_get_next_position (param_pos);
					continue;
				}

				if (!strcmp(inattr->param, "name"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%s%d", ifp->if_name, ifp->if_unit);
						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "enable"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%s", 
								ifp->if_enabled?"enabled":"disabled");
						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET && inattr->value != NULL)
					{
						if (!strcmp(inattr->value, "enabled"))
						{
							ifp->if_enabled = 1;
							T_LINK("enable_seth: %d", ifp->if_unit);
						}
						else if(!strcmp(inattr->value, "disabled"))
						{
							ifp->if_enabled = 0;
							T_LINK("disable_seth: %d", ifp->if_unit);
						}
					}
				}
				else if (!strcmp(inattr->param, "in_octet"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ifp->ifInOctet);
						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "out_octet"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ifp->ifOutOctets);
						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "in_packet"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ifp->ifInPkts);
						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "out_packet"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ifp->ifOutPkts);
						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else
				{
					DBG ("Unknown parameter <%s>\n", inattr->param);
				}

				if (cmd == KMGMT_GET)
				{
					if (value != NULL)
					{
						outattr = (kmgmt_param_t*)malloc (sizeof(kmgmt_param_t));
						outattr->param = strdup (inattr->param);
						outattr->value = value;

						list_add_tail (entry->l, (void*)outattr);
					}
				}

				param_pos = list_get_next_position (param_pos);
			}

			if (entry != NULL)
				list_add_tail (values, (void*)entry);

end_of_for:
			if_next = ifp->if_next;
		}
	}
	else
	{
		DBG ("Unknown Table %s", table);
		goto error;
	}

	return DONE;

error:
	if (entry != NULL)
	{
		while (outattr = (kmgmt_param_t*)list_remove_head (entry->l))
		{
			if (outattr != NULL)
			{
				if (outattr->param != NULL)
					free (outattr->param);
				if (outattr->value != NULL)
					free (outattr->value);

				free (outattr);
			}
		}

		list_close (entry->l);
		if (entry->index != NULL)
			free (entry->index);

		free (entry);
	}

	return FAILED;
}

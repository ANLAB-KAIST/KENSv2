#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <signal.h>

#include "datalink.h"
#include "kip.h"
#include "ktcp.h"
#include "log.h"

#include "kmgmt.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

/* Maximum Payload size is a full size KTCP packet */
#define MAX_PAYLOAD_SIZE	20+536
#define	KIP_HEADER_SIZE		20
#define MAX_PACKET_SIZE		(KIP_HEADER_SIZE+MAX_PAYLOAD_SIZE)

#define MAX_NUM_SOCKFDS		4

/* Maximum Transmission Unit */
#define MTU	1500
//#define MTU	30
#define KIP_DEFAULT_TIMEOUT_TTL	10
#define KIP_TIMEOUT_PERIOD	2000

static list ip_reass_ctx_list = NULL;
static int slow_timeout = 1;
typedef struct ip_reass_ctx_t {
	struct in_addr ip_src;
	struct in_addr ip_dst;
	unsigned short ip_id;	/* source id. */
	unsigned char ip_p;		/* protocol id. */
	unsigned short ip_ttl;
	unsigned short ttl;
	int done;
	uint16_t last_offset;
	list fragment_list;
} ip_reass_ctx;

/**
 * The following struct has the same structure as the original struct ip's,
 * with renamed field ipf_mff instead of ip_tos.
 */
struct ipasfrag {
	uint16_t data_length;
	uint16_t offset;
	char data[0];
};

static uint16_t ip_checksum(void *ip_buf, size_t hlen);
static void ip_forward(void *ip_buf, int len);
static void ip_dump_header(char *title,struct ip *ip);
static void ip_debug_buffer(const char *text, const void *data, int len);
static int ip_route(struct in_addr *orig_src, struct in_addr *target_dst, void *ip_buf, size_t len, int flags, route *ro);
static ip_reass_ctx* ip_reass_ctx_create(const struct ip *ip);
static void ip_reass_ctx_free(ip_reass_ctx *handle);
static struct ip* ip_reass(struct ip *ip, ip_reass_ctx *ctx);
static unsigned short ip_id;
static route iproute; /* Temporary route structure for cache. */
static rtentry rt_cache;

/**
 * initialize KIP layer. loading routing table and firewall configuration
 * should be done in this function. This function is called before KENS
 * enters its main dispatch loop.
 * @param conf a pointer to KENS configuration file hash structure
 * @return 0 when success, others when errors
 */
int ip_init(dictionary *conf)
{
	ip_id ^= (unsigned char)((getpid()*getppid()*time(NULL)) & 0xffff);
	ip_reass_ctx_list = list_open();

	rt_init(conf);

	return 0;
}

/**
 * shutdown and free whole resources which were allocated at ip_init() or
 * during KENS runtime, especially resources related to routing table and 
 * firewall. This function is called after KENS receive a termination signal
 * from user.
 * @return 0 when success, others when errors
 */
int ip_shutdown(void)
{
	rt_cleanup();
	list_close(ip_reass_ctx_list);
	return 0;
}

/** 
 * This fuction reduces the ttl of the fragment packets in reassembly list. 
 * Also, it checks the timeout.
 */
void ip_slow_timeout() {
	list_position pos, prev_pos;
	if (ip_reass_ctx_list == NULL)
		return;
	for (pos = list_get_head_position(ip_reass_ctx_list); pos; pos = list_get_next_position(pos)) {
		ip_reass_ctx *ctx = list_get_at(pos);
		ctx->ttl --;
		if (ctx->ttl == 0) {
			prev_pos = list_get_prev_position(pos);
			L_IP("ip_slow_timeout(): freeing ctx %p (id = %d)", ctx, ctx->ip_id);
			ip_reass_ctx_free(ctx); /* Removing from the list is done inside. */
			pos = prev_pos;
			if (pos == NULL)
				break;
		}
	}
}

/**
 * this function is called by KENS_dispatch_loop() in Kernel_main.c .
 * Nothing has to be more inplemented in this function.
 */
int ip_dispatch() {
	ip_slow_timeout();
	return 0;
}

/**
 * this function is called for every incoming packet from datalink.
 * You should implement logic in this function or in serveral functions
 * to process incoming packets to this host as well as packets which
 * pass through this host, routing or forwarding.
 *
 * For further information, I strongly recommend you to refer TCP/IP
 * Illustrated Volume 2.
 *
 * @param buf buffer which contains data from datalink. This buffer starts
 * from KIP header. This is a part of the global static variable of datalink.c.
 * @param len exact size of data contained in buf
 * @return 0 when success, others when errors
 */
int ip_input(void *ip_buf,int len)
{
	list_position pos;
	ip_reass_ctx *ctx;
	in_ifaddr *ia;
	unsigned short hlen, dlen;
	struct ip *ip = malloc(len);
	memcpy(ip, ip_buf, len);

	L_IP("ip_input(): received packet, validating it...");

	/* Check the minimum size of the packet (at least, should contain a hader). */
	if (len < KIP_HEADER_SIZE) {
		L_IP("ip_input(): validation failed: too small (%d)", len);
		return IPERR_TOOSMALL;
	}

	/* Check the header version. */
	if (ip->ip_v != KIP_VERSION) {
		L_IP("ip_input(): validation failed: bad version (%d)", ip->ip_v);
		return IPERR_BADVERSION;
	}
	
	/* Check the header size. */
	hlen = ip->ip_hl << 2;
	if (hlen < KIP_HEADER_SIZE) {
		L_IP("ip_input(): validation failed: header size (%d)", hlen);
		return IPERR_TOOSMALL;
	}
	
	/* Verify the checksum. */
	if (ip->ip_sum = ip_checksum(ip_buf, hlen)) { // The result must be zero(false).
		L_IP("ip_input(): validation failed: bad checksum (%d)", ip->ip_sum);
		return IPERR_BADCHECKSUM;
	}
	
	/* Convert fields to host endianness. */
	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_id = ntohs(ip->ip_id);
	ip->ip_off = ntohs(ip->ip_off);

	/* Verify that the amount of data expected is really there. */
	dlen = (unsigned short)ip->ip_len;
	if (dlen > len) /* Drop if there are insufficient bytes. */
		return IPERR_BADLEN;
	else if (dlen < len) /* Trim remaining bytes (maybe padded by the link layer). */
		len = dlen;
	dlen -= hlen;

	/* Now we have a valid IP datagram here. */
	/* And we skip the option processing. */
	ip_dump_header("ip_input(): validated packet is ", ip);
	ip_debug_buffer("            content:", (char*)ip + hlen, dlen);

	/* Perform reassembly routines if necessary */
	if (ip->ip_off & ~IP_DF) {
		L_IP("ip_input(): try reassembly (id = %d)", ip->ip_id);

		/* Find the related reassembly context of this packet. */
		for (pos = list_get_head_position(ip_reass_ctx_list); pos; pos = list_get_next_position(pos)) {
			ctx = (ip_reass_ctx*) list_get_at(pos);
			if (ctx->ip_id == ip->ip_id &&
					ctx->ip_p == ip->ip_p &&
					ctx->ip_src.s_addr == ip->ip_src.s_addr &&
					ctx->ip_dst.s_addr == ip->ip_dst.s_addr)
				goto found;
		}
		ctx = NULL;
		found:
		/* Copy flags from ip->ip_off to ip->ipf_mff overwriting ip->ip_tos. */

		/* Remove 3-bit flags and restore the original byte offset.
		   This convention is only used for stored fragments. */

		/* Attempt to reassembly. */
		if(ctx && ctx->done)
		{
			free(ip);
			return;
		}
		ip = ip_reass(ip, ctx);
		if (ip == NULL)
			return;

		hlen = ip->ip_hl << 2;
		len = ip->ip_len;
		dlen = len - hlen;
	}

	/* Check whether the packet should be forwared or not. */
	for (ia = _in_ifaddr; ia; ia = ia->ia_next) {
		L_IP("ip_input(): checking if I'm the final dest or not...(%08x, %08x)", ip->ip_dst.s_addr, ia->ifa->ifa_addr.s_addr);
		if (ip->ip_dst.s_addr == ia->ifa->ifa_addr.s_addr)
			goto ours;

		// SKIP: broadcast
	}

	// SKIP: multicast
	
	if (ip->ip_dst.s_addr == (unsigned long) INADDR_BROADCAST)
		goto ours;
	if (ip->ip_dst.s_addr == INADDR_ANY)
		goto ours;

	/* Forward the packet. */
	L_IP("ip_input(): forwarding the packet...");
	ip_forward(ip, len);
	return 0;

ours:
	/* This packet is not forwarded. */
	/* Here, we have a complete IP datagram. */

	/* We only process datagrams for TCP without demultiplexing. */
	if (ip->ip_p != IPPROTO_TCP) {
		L_IP("ip_input(): discarding unsupported protocol (%d) packet...", ip->ip_p);
		return IPERR_UNSUPPORTED;
	}

	/* Now it is ready to send to KTCP layer. */
	L_IP("ip_input(): passing the packet to the transport layer...");
	tcp_dispatch_in(ip->ip_src, ip->ip_dst, (char*)ip + hlen, dlen);
	free(ip);
	return 0;
}

/**
 * this function deals outgoing packet from this host. That is,
 * this function is directly called by Transport layer, KTCP.
 * You should implement logic to decide packet route which is sometimes
 * given by KTCP layer, fragment data and generate proper KIP header
 * for each outgoing packet. You may leave this function as a wrapper
 * to another extended KIP output function which receive an extra argument
 * ,flag, to share the facilities with packet forwarding.
 *
 * For further information, I strongly recommend you to refer TCP/IP
 * Illustrated Volume 2.
 *
 * @param src where this packet comes from in network byte order.
 * @param dst where this packet goes to in network byte order.
 * @param buf packet's payload
 * @param len length of packet's payload
 * @param ro routing information which is already cached by previous call.
 * If this argument is not null and the structure is empty, ip_output will
 * fill the structure with proper routing information for next time use.
 * If this argument is not null and the structure is not empty, ip_output will
 * use given routing information without lookup routing table.
 * @return 0 when success, others when errors
 */
int ip_output(struct in_addr src,struct in_addr dst,
		void *buf,size_t len,route *ro)
{
	unsigned char *pkt = buf;
	int hlen = sizeof(struct ip);
	char *ip_buf = malloc(sizeof(struct ip) + len);

	memset(ip_buf, 0, hlen);
	memcpy((char*)ip_buf + hlen, pkt, len);	/* copy TCP packet into local buffer */
	L_IP("ip_output(): received packet from the transport layer...");

	/* IP headers will be filled in ip_route(). */
	return ip_route(&src, &dst, ip_buf, hlen + len, 0, ro);
}

/**
 * Invlidate the current forwarding rt cache to get the fresh routing entry.
 */
void ip_invalidate_forward_rt_cache(void)
{
	iproute.ro_rt = NULL;
	iproute.ro_dst.s_addr = INADDR_ANY;
	memset(&rt_cache, 0, sizeof(struct rtentry_t));
}

/**
 * get virtual ip address of virtual network interface card
 * which is used to transmit a packet destined to 'in'.
 * this is called by TCP layer to decide source ip address
 * for outgoing packet. Thus, you should consult routing table
 * to figure out which device should be used.
 * @param in destination of a packet in network byte order
 * @return source ip address of interface card in network byte order
 */
uint32_t ip_host_address(struct in_addr in)
{
	route ro;	
	ifnet *ifp;

	for ( ifp = _ifnet; ifp; ifp = ifp->if_next )
		if ( in_localnet(ifp,in) )
			return IN_ADDR(ifp).s_addr;

	ro.ro_dst.s_addr = in.s_addr;
	ro.ro_rt = NULL;

	rt_alloc(&ro);

	if ( ro.ro_rt == NULL )
		return htonl(INADDR_ANY);

	return IN_ADDR(ro.ro_rt->rt_ifp).s_addr;
}

static char* my_inet_ntoa(struct in_addr addr)
{
	static char buf[128] = {0,};
	uint32_t _addr = ntohl(addr.s_addr);
	sprintf(buf, "%d.%d.%d.%d",
			_addr >> 24 & 0xFF,
			_addr >> 16 & 0xFF,
			_addr >> 8 & 0xFF,
			_addr & 0xFF);
	return buf;
}

/**
 * dump given KIP header into log file.
 * @param title a header for each log
 * @param ip a KIP header to dump
 */
static void ip_dump_header(char *title,struct ip *ip)
{
	char buf[80];
	inet_ntoa_r(ip->ip_src,buf,80);

	L_IP_HDR("%s", title);
	L_IP_HDR("       v=%d, p=%d, src=%s dest=%d.%d.%d.%d ttl=%d",
			ip->ip_v,
			ip->ip_p,
			buf,
			my_inet_ntoa(ip->ip_dst),
			ip->ip_ttl
	);
	L_IP_HDR("       id=%d, off=%x:%d, len=%d",
			ip->ip_id,
			(ip->ip_off & ~IP_OFFMASK) >> 13,
			(ip->ip_off & IP_OFFMASK) << 3,
			ip->ip_len
	);
}

static void
ip_debug_buffer(const char *text, const void *buffer, int len)
{
	char buf[100] = {0};
	char *data = (char*) buffer;
	L_IP("%s", text);
	if (len > 0) {
		int i;
		char *p;

		memset(buf,' ',6);
		p = buf + 6;
		L_IP("    printable data:");
		for (i = 0; i < len; i++) {
			if ((i % 64) == 0 && i != 0) {
				*p = '\0';
				L_IP("%s",buf);
				p = buf+6;
			}
			if ( isprint(data[i]) )
				*p++ = data[i];
			else
				*p++ = '.';
		}
		if ((i % 64) != 0) {
			*p = '\0';
			L_IP("%s",buf);
		}
	}
}

/**
 * Forwards the ip packet to another router, without passing to the transport layer.
 * @param buf	datagram buffer
 * @param len	length of buffer
 */
static void
ip_forward(void *ip_buf, int len)
{
	char text_buf[80];
	struct ip *ip = (struct ip *) ip_buf;
	int hlen = ip->ip_hl << 2;
	route ro;

	/* Check TTL of the packet. */
	if (ip->ip_ttl < IPTTLDEC) {
		// Send ICMP packet to notify TTL expiration, but we don't have ICMP for KENS.
		L_IP("ip_forward(): TTL has expired.");
		return;
	}
	ip->ip_ttl -= IPTTLDEC;

	/* Find the route. */
	ro.ro_dst = ip->ip_dst;
	ro.ro_rt = NULL;
	L_IP("ip_forward(): querying routing table with dst = %s", my_inet_ntoa(ro.ro_dst));
	rt_alloc(&ro);

	if (ro.ro_rt == NULL) {
		// Send ICMP packet to notify "unreachable address".
		L_IP("ip_forward(): unreachable address.");
		return;
	}

	/* Do routing... */
	inet_ntoa_r(IN_ADDR(ro.ro_rt->rt_ifp), text_buf, 80);
	L_IP("ip_forward(): found next hop: %s", text_buf);
	ip_route(&ip->ip_src, &ip->ip_dst, ip, len, IP_FORWARDING, &ro);
}

/**
 * Do the actual routing and passing datagrams to the link layer.
 * @param orig_src		original source of the packet
 * @param target_src	final destination of the packet
 * @param ip_buf		the buffer for IP packet
 * @param len			length of buffer
 * @param flags			IP option flags
 * @param ro			routing information
 */
static int
ip_route(struct in_addr *orig_src, struct in_addr *target_dst, void *ip_buf, size_t len, int flags, route *ro)
{
	char text_buf[80];
	struct in_addr *routing_dst;
	ifnet *ifp;
	ifaddr *ia;
	struct ip *ip = (struct ip *)ip_buf;
	int hlen = sizeof(struct ip);

	/* Fill in the IP header. */
	if ((flags & (IP_FORWARDING | IP_RAWOUTPUT)) == 0) {
		memset(ip, 0, hlen);
		ip->ip_hl = hlen >> 2;
		ip->ip_len = len; //total length including header
		ip->ip_id = ip_id;
		ip->ip_off = 0;
		ip->ip_p = IPPROTO_TCP;
		ip->ip_v = KIP_VERSION;
		ip->ip_sum = 0;
		ip->ip_ttl = KIP_DEFAULT_TTL;
		ip->ip_src.s_addr = orig_src->s_addr;
		ip->ip_dst.s_addr = target_dst->s_addr;
	} else {
		hlen = ip->ip_hl << 2;
	}
	ip_dump_header("ip_route(): header complete:", ip);

	/* Verify cached route. */
	if (ro == NULL && iproute.ro_rt == NULL) {
		// Consult the routing table.
		L_IP("ip_route(): consult the routing table.");
		ro = &iproute;
		memset(ro, 0, sizeof(*ro));
		ro->ro_dst = ip->ip_dst;
		rt_alloc(ro);
		rt_cache = *ro->ro_rt;
	} else if ((ro != NULL && ro->ro_rt == NULL) || iproute.ro_rt != NULL) {
		// Consult the routing table and cache it.
		ro = &iproute;
		if (ro->ro_dst.s_addr != ip->ip_dst.s_addr) {
			// Get a new entry.
			L_IP("ip_route(): discard cache and get a new entry for %s", my_inet_ntoa(ip->ip_dst));
			ro->ro_dst = ip->ip_dst;
			// TODO: should free the previous ro_rt?
			ro->ro_rt = NULL;
			rt_alloc(ro);
			rt_cache = *ro->ro_rt;
		} else {
			ro->ro_rt = &rt_cache;
			L_IP("ip_route(): use cached route.");
		}
	} else {
		// Just use the given routing info.
		L_IP("ip_route(): use the given routing.");
	}
	routing_dst = (struct in_addr *) &ro->ro_dst;

	if (ro->ro_rt == NULL)
		goto bad;
	ifp = ro->ro_rt->rt_ifp;
	ia = ro->ro_rt->rt_ifa;
	ro->ro_rt->rt_use++;
	L_IP("ip_route(): routing info: rt_flags = %04x", ro->ro_rt->rt_flags);

	if (ro->ro_rt->rt_flags & RTF_GATEWAY) {
		/* If the next hop isn't the final destination, routing_dst is changed to point to the next-hop router. */
		L_IP("ip_route(): routing to a gateway (%s)", my_inet_ntoa(ro->ro_rt->gw));
		routing_dst = (struct in_addr *) &ro->ro_rt->gw;
	}
	
	/* If still have no source IP, set it to that of the outgoing interface. */
	if (ip->ip_src.s_addr == INADDR_ANY) {
		L_IP("ip_route(): the packet has an empty src addr, so set it to addr of my outgoing interface (%s)", my_inet_ntoa(ia->ifa_addr));
		ip->ip_src = ia->ifa_addr;
	}

sendit:

	L_IP("ip_route(): final routing_dst = %s", my_inet_ntoa(*routing_dst));
	/* Send it over the network! */
	L_IP("ip_route(): checking fragmentation is needed... (hlen=%d, len=%d, mtu=%d)", hlen, ip->ip_len, MTU);
	if (ip->ip_len <= MTU) {
		ip->ip_len = htons((unsigned short)ip->ip_len);
		ip->ip_off = htons((unsigned short)ip->ip_off);
		ip->ip_id = htons((unsigned short)ip->ip_id);
		ip->ip_sum = 0;
		ip->ip_sum = ip_checksum(ip_buf, hlen);
		L_IP("ip_route(): passing the packet to the link layer...");
		dl_output(ifp, ip_buf, hlen + len, *routing_dst);

	} else {
	/* Perform fragmentation. */
		unsigned short off;
		struct ip *ip_frag_pkt = NULL; 

		/* Calculate the fragment size. */
		// assuption: hlen == sizeof(struct ip)
		hlen = sizeof(struct ip);
		if (ip->ip_off & IP_DF)
			goto bad;
		len = ((MTU-hlen) & ~7) + hlen; //make len multiple of 8

		L_IP("ip_route(): starting fragmentation with max.frag length = %d", len);
		ip_frag_pkt = (struct ip*) malloc(len);
		memset(ip_frag_pkt, 0, len);

		/* Build and send each fragment packet. */
		for (off = 0; off < (unsigned short) ip->ip_len - hlen; off += (len - hlen)) {

			ip_frag_pkt->ip_off = (((off >> 3) & IP_OFFMASK) + ((ip->ip_off & ~IP_MF) & ~IP_OFFMASK));
			if (ip->ip_off & IP_MF) /* If already IP_MF is set, let it remain. */
				ip_frag_pkt->ip_off |= IP_MF;
			if (off + len >= (unsigned short) ip->ip_len) /* When it's the last fragment... */
				len = ((unsigned short) ip->ip_len - off);
			else        /* Mark IP_MF flag on when it's in the middle of fragment sequence. */
				ip_frag_pkt->ip_off |= IP_MF;

			ip_frag_pkt->ip_hl = hlen >> 2;
			ip_frag_pkt->ip_id = ip->ip_id;
			L_IP("ip_route(): building a fragmented packet: id=%d, off=%x:%d, len=%d",
				ip_frag_pkt->ip_id,
				(ip_frag_pkt->ip_off & ~IP_OFFMASK) >> 13,
				(ip_frag_pkt->ip_off & IP_OFFMASK) << 3,
				len
			);

			ip_frag_pkt->ip_len = len;
			memcpy((char*)ip_frag_pkt + hlen, (char*)ip_buf + hlen + off, (len - hlen));
			ip_debug_buffer("            content of fragment:", (char*)ip_frag_pkt + hlen, (len - hlen));

			ip_frag_pkt->ip_len = htons((unsigned short)(len));
			ip_frag_pkt->ip_off = htons(ip_frag_pkt->ip_off);
			ip_frag_pkt->ip_id = htons((unsigned short)ip_frag_pkt->ip_id);
			ip_frag_pkt->ip_p = ip->ip_p;
			ip_frag_pkt->ip_v = KIP_VERSION;
			ip_frag_pkt->ip_sum = 0;
			ip_frag_pkt->ip_ttl = ip->ip_ttl;
			ip_frag_pkt->ip_src = ip->ip_src;
			ip_frag_pkt->ip_dst = ip->ip_dst;
			ip_frag_pkt->ip_sum = ip_checksum(ip_frag_pkt, hlen);

			L_IP("ip_route(): passing the packet to the link layer...");
			dl_output(ifp, (char*)ip_frag_pkt, len, *routing_dst);
		}
		free(ip_frag_pkt);
	}

done:
	// 아래 코드가 memory corruption 유발.
	//if (ro == &iproute && (flags & IP_ROUTETOIF) == 0 && ro->ro_rt)
	//	free(ro->ro_rt);

	/* Increment ip_id counter for easy debugging... */
	ip_id = (ip_id + 1) & 0x1fff;
	free(ip_buf);
	return 0;

bad:
	L_IP("ip_route(): routing failed!");
	free(ip_buf);
	return IPERR_ROUTINGFAILED;
}

/**
 * IP-checksum calculator from TCP/IP Illustrated Vol.2
 * @param buf	datagram buffer including the header
 * @param len	length of buffer
 */
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

/**
 * Creates a reassembly context.
 */
static ip_reass_ctx*
ip_reass_ctx_create(const struct ip *ip)
{
	ip_reass_ctx *ctx = malloc(sizeof(ip_reass_ctx));
	memset(ctx, 0, sizeof(ip_reass_ctx));
	ctx->ip_src = ip->ip_src;
	ctx->ip_dst = ip->ip_dst;
	ctx->ip_id = ip->ip_id;
	ctx->ip_p = ip->ip_p;
	ctx->ip_ttl = ip->ip_ttl;
	ctx->ttl = KIP_TIMEOUT_PERIOD;
	ctx->fragment_list = list_open();
	ctx->done = 0;
	ctx->last_offset = 0;
	list_add_tail(ip_reass_ctx_list, ctx);
	L_IP("ip_reass_ctx_create(): allocated and added %p", ctx);
	return ctx;
}

/**
 * Frees a reassembly context.
 */
static void
ip_reass_ctx_free(ip_reass_ctx *handle)
{
	list_position pos;
	if (handle == NULL)
		return;
	ip_reass_ctx *ctx = (ip_reass_ctx*) handle;
	L_IP("ip_reass_ctx_free(): freeing %p", ctx);
	list_remove(ip_reass_ctx_list, ctx);
	for (pos = list_get_head_position(ctx->fragment_list); pos; pos = list_get_next_position(pos)) {
		free(list_get_at(pos));
	}
	list_close(ctx->fragment_list);
	free(ctx);
}

/**
 * This fuction is called by ip_input function when the incoming packet is
 * a fragment packet. 
 * You should add the fragment to a proper locaiton in reassembly list.
 * If reassembly is possible, reassemble the fragments.
 * @return 0 when success.
 */
static struct ip*
ip_reass(struct ip *ip, ip_reass_ctx *ctx)
{
	unsigned char result_data[MAX_PACKET_SIZE];
	struct ip *ip_result;
	list_position pos = NULL, prev_pos, pos2;
	struct ipasfrag *fragment = NULL;
	int next, i;
	int hlen = sizeof(struct ip);

	L_IP("ip_reass(): called! (ctx=%p)", ctx);
	// 여기서 복사해주어야 fragment list 안에 이미 들어간 datagram을 ip_input()에서 다시 변경하게 되는 일이 없다.
	fragment = (struct ipasfrag*) malloc(sizeof(struct ipasfrag) + ip->ip_len);
	fragment->data_length = ip->ip_len - hlen;
	fragment->offset = ip->ip_off & IP_OFFMASK;
	memcpy(fragment+1, ((void*)ip) + hlen, fragment->data_length);

	/* We will return a new allocated pointer, so ipfrag isn't needed anymore. */


	/* If first fragment is arrived, create a reassembly context. */
	if (ctx == NULL) {
		ctx = ip_reass_ctx_create(ip);

	}
	if((ip->ip_off & ~IP_OFFMASK) == 0)
		ctx->last_offset = ip->ip_off;
	free(ip);

	/* Find a fragment which begins after the received one does. */
	list_position after = 0;
	for (pos = list_get_head_position(ctx->fragment_list); pos; pos = list_get_next_position(pos)){
		struct ipasfrag * current = (struct ipasfrag*) list_get_at(pos);
		if (fragment->offset + fragment->data_length <= current->offset) {
			L_IP("ip_reass(): found the fragment just after the received one. (off=%d, len=%d)", current->offset, current->data_length);
			after = pos;
			break;
		}
		if(fragment->offset == current->offset)
		{
			L_IP("ip_reass(): duplicate fragment. (off=%d)", fragment->offset);
			free(fragment);
			return 0;
		}
	}

	if(!after)
		list_add_tail(ctx->fragment_list, fragment);
	else
		list_insert_before(after, fragment);


	uint16_t expecting_offset = 0;
	uint16_t total_length = 0;
	for (pos = list_get_head_position(ctx->fragment_list); pos; pos = list_get_next_position(pos)){
		struct ipasfrag * current = (struct ipasfrag*) list_get_at(pos);

		if(current->offset == expecting_offset)
		{
			expecting_offset += current->data_length >> 3;
			total_length += current->data_length;
			if(ctx->last_offset && current->offset == ctx->last_offset)
				ctx->done = 1;
		}
		else
			break;
	}

	if(ctx->done)
	{
		ip_result = malloc(sizeof(struct ip) + total_length);
		ip_result->ip_off = 0;
		ip_result->ip_hl = sizeof(struct ip) >> 2;
		ip_result->ip_len = total_length + sizeof(struct ip);
		ip_result->ip_id = ctx->ip_id;
		ip_result->ip_p = ctx->ip_p;
		ip_result->ip_v = KIP_VERSION;
		ip_result->ip_src = ctx->ip_src;
		ip_result->ip_dst = ctx->ip_dst;
		ip_result->ip_ttl = ctx->ip_ttl;
		ip_result->ip_sum = 0;

		void* data = ip_result+1;

		for (pos = list_get_head_position(ctx->fragment_list); pos; pos = list_get_next_position(pos)){
			struct ipasfrag * current = (struct ipasfrag*) list_get_at(pos);

			memcpy(data, current->data, current->data_length);
			data += current->data_length;
		}

		L_IP("ip_reass(): reassembling as a copied datagram is complete. (ctx=%p, total length=%d)", ctx, total_length);
		ip_reass_ctx_free(ctx);
		return ip_result;
	}
	else
	{
		return 0;
	}
}

/* vim: set ts=4 sts=4 sw=4 noet: */

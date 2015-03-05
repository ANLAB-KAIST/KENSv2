#ifndef ROUTE_H
#define ROUTE_H

#include <sys/types.h>
#include <netinet/in.h>

#include "iniparser.h"
#include "linked_list.h"

#include "datalink.h"


typedef struct radix_node_head_t radix_node_head;
typedef struct radix_mask_t radix_mask;
typedef struct radix_node_t radix_node;
typedef struct rtentry_t rtentry;
typedef struct route_t route;

struct radix_mask_t {
	caddr_t rm_mask;
	char unused;	/* number of unused bits. thus number of 0 */
	struct radix_mask_t *rm_mklist;
	int rm_refs;
};

struct radix_node_t {
	radix_mask *rn_mklist;
	struct radix_node_t *rn_p;	/* parent pointer */

	short rn_b;		/* bit offset; -1 - index(netmask) */
	char rn_bmask;	/* bit 검사를 수행할 mask */

	unsigned char rn_flags;
	union {
		struct {
			caddr_t rn_Key;
			caddr_t rn_Mask;
			struct radix_node_t *rn_Dupedkey;
		} rn_leaf;
		struct {
			int rn_Off;
			struct radix_node_t *rn_L;
			struct radix_node_t *rn_R;
		} rn_node;
	} rn_u;
};

#define rn_dupedkey		rn_u.rn_leaf.rn_Dupedkey
#define rn_key			rn_u.rn_leaf.rn_Key
#define rn_mask			rn_u.rn_leaf.rn_Mask
#define rn_off			rn_u.rn_node.rn_Off
#define rn_l			rn_u.rn_node.rn_L
#define rn_r			rn_u.rn_node.rn_R

struct radix_node_head_t {
	radix_node *rnh_treetop;
	radix_node rnh_nodes[3];
};

struct rtentry_t {
	radix_node rt_nodes[2];	/* a leaf and an internal node */

	struct in_addr dst;		/* destination. rn_key */
	struct in_addr mask;	/* mask to direction */
	struct in_addr gw;

	short rt_flags;
	ifnet *rt_ifp;	/* interface to use */
	ifaddr *rt_ifa;	/* interface address to use */
	int rt_use;
	int rt_refcnt;

#ifdef HAVE_ROUTE_STATS
	unsigned int ipForwardAge; // TODO: seconds after the last update
	unsigned int ipForwardHitCount;
#endif /* HAVE_ROUTE_STATS */
};

struct route_t {
	rtentry *ro_rt;
	struct in_addr ro_dst;
};

int rt_init(dictionary *conf);
void rt_alloc(route *ro);
int rt_cleanup(void);
void rnh_dump(void);

/* direct routing table manipulation for dynamic routing */
list rt_query();
int rt_insert(rtentry *ent);

#define RTF_BLACKHOLE		0x0001
#define RTF_CLONING			0x0002
#define RTF_DONE			0x0004
#define RTF_DYNAMIC			0x0008
#define RTF_GATEWAY			0x0010
#define RTF_HOST			0x0020
#define RTF_LLINFO			0x0040
#define RTF_MASK			0x0080
#define RTF_MODIFIED		0x0100
#define RTF_REJECT			0x0200
#define RTF_STATIC			0x0400
#define RTF_UP				0x0800
#define RTF_SHOULD_FREED	0x1000

#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "route.h"
#include "log.h"
#include "misc.h"
#include "linked_list.h"

#include "kmgmt.h"
#include "kxml.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

static uint32_t _bit_idx[8] = {
	0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};

static char _mask_idx[33][4] = {
	{ 0xff, 0xff, 0xff, 0xff }, { 0xff, 0xff, 0xff, 0xfe },
	{ 0xff, 0xff, 0xff, 0xfc }, { 0xff, 0xff, 0xff, 0xf8 },
	{ 0xff, 0xff, 0xff, 0xf0 }, { 0xff, 0xff, 0xff, 0xe0 },
	{ 0xff, 0xff, 0xff, 0xc0 }, { 0xff, 0xff, 0xff, 0x80 },
	{ 0xff, 0xff, 0xff, 0x00 }, { 0xff, 0xff, 0xfe, 0x00 },
	{ 0xff, 0xff, 0xfc, 0x00 }, { 0xff, 0xff, 0xf8, 0x00 },
	{ 0xff, 0xff, 0xf0, 0x00 }, { 0xff, 0xff, 0xe0, 0x00 },
	{ 0xff, 0xff, 0xc0, 0x00 }, { 0xff, 0xff, 0x80, 0x00 },
	{ 0xff, 0xff, 0x00, 0x00 }, { 0xff, 0xfe, 0x00, 0x00 },
	{ 0xff, 0xfc, 0x00, 0x00 }, { 0xff, 0xf8, 0x00, 0x00 },
	{ 0xff, 0xf0, 0x00, 0x00 }, { 0xff, 0xe0, 0x00, 0x00 },
	{ 0xff, 0xc0, 0x00, 0x00 }, { 0xff, 0x80, 0x00, 0x00 },
	{ 0xff, 0x00, 0x00, 0x00 }, { 0xfe, 0x00, 0x00, 0x00 },
	{ 0xfc, 0x00, 0x00, 0x00 }, { 0xf8, 0x00, 0x00, 0x00 },
	{ 0xf0, 0x00, 0x00, 0x00 }, { 0xe0, 0x00, 0x00, 0x00 },
	{ 0xc0, 0x00, 0x00, 0x00 }, { 0x80, 0x00, 0x00, 0x00 },
	{ 0x00, 0x00, 0x00, 0x00 }
};

#define bit(x,i)	((x) & _bit_idx[(i)])

static char *rn_zeros = NULL;
static char *rn_ones = NULL;
static char *maskedKey = NULL;
static radix_node_head rn_head;


enum {
	RNF_ACTIVE = 0x01,
	RNF_NORMAL = 0x02,
	RNF_ROOT = 0x04
};

/* function definitions */
radix_mask *rm_new(struct in_addr *mask);
caddr_t rm_lookup(struct in_addr *mask);

radix_node *rn_match(radix_node_head *head,struct in_addr *v_arg);
radix_node *rn_search(radix_node *head,void *v_arg);
void rn_dump(radix_node *rn);

static int rt_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values);

#ifdef __APPLE__
static size_t strnlen(const char *s, size_t len);
static char *strndup(char const *s, size_t n);
#endif
void rnh_dump(void);


int rnh_init(radix_node_head *head)
{
	if ( rn_zeros == NULL ) {
		rn_zeros = (char *)malloc(4 * 3);	/* IPv4는 32bit */
		assert( rn_zeros );
		memset(rn_zeros,0x00,4 * 3);
		rn_ones = maskedKey = rn_zeros + 4;
		*(maskedKey++) = -1;
		*(maskedKey++) = -1;
		*(maskedKey++) = -1;
		*(maskedKey++) = -1;
	}

	/* first initialize radix node head */
	memset(head,0x00,sizeof(radix_node_head));

	head->rnh_treetop = &head->rnh_nodes[1];	/* tree top */

	/* initialize all entries */
	head->rnh_nodes[0].rn_mklist = NULL;
	head->rnh_nodes[0].rn_p = head->rnh_treetop;
	head->rnh_nodes[0].rn_b = -1;
	head->rnh_nodes[0].rn_bmask = 0;
	head->rnh_nodes[0].rn_flags = RNF_ACTIVE|RNF_ROOT;
	head->rnh_nodes[0].rn_key = rn_zeros;	/* 0 */
	head->rnh_nodes[0].rn_mask = NULL;	/* 0 */
	head->rnh_nodes[0].rn_dupedkey = NULL;

	head->rnh_nodes[1].rn_mklist = NULL;
	head->rnh_nodes[1].rn_p = head->rnh_treetop;
	head->rnh_nodes[1].rn_b = 0;
	head->rnh_nodes[1].rn_bmask = 0x80;
	head->rnh_nodes[1].rn_flags = RNF_ACTIVE|RNF_ROOT;
	head->rnh_nodes[1].rn_off = 0;
	head->rnh_nodes[1].rn_l = &head->rnh_nodes[0];
	head->rnh_nodes[1].rn_r = &head->rnh_nodes[2];

	head->rnh_nodes[2].rn_mklist = NULL;
	head->rnh_nodes[2].rn_p = head->rnh_treetop;
	head->rnh_nodes[2].rn_b = -1;
	head->rnh_nodes[2].rn_bmask = 0;
	head->rnh_nodes[2].rn_flags = RNF_ACTIVE|RNF_ROOT;
	head->rnh_nodes[2].rn_key = rn_ones;
	head->rnh_nodes[2].rn_mask = NULL;
	head->rnh_nodes[2].rn_dupedkey = NULL;

	return 0;
}

#define rm_ref(r,m)		{ (r) = (m); (m)->rm_refs++; }
#define rm_unref(r)		{ (r)->rm_refs--; (r) = NULL; }

#define rm_free(m)	{\
if ( (m) != NULL && --(m)->rm_refs == 0 ) {\
	if ( (m)->rm_mklist != NULL ) rm_unref((m)->rm_mklist);\
	free((m));\
	(m) = NULL;\
}

radix_mask *rm_new(struct in_addr *mask)
{
	radix_mask *rm;

	rm = (radix_mask *)malloc(sizeof(radix_mask));
	assert( rm );
	rm->rm_mask = rm_lookup(mask);
	rm->unused = ( rm->rm_mask == NULL ) ? 0 : ((rm->rm_mask - (caddr_t)_mask_idx)/4);
	rm->rm_mklist = NULL;
	rm->rm_refs++;	/* implicitly increase reference number */

	return rm;
}

radix_mask *rm_dup(radix_mask *mask,bool deap)
{
	radix_mask *rm;
	radix_mask *head,*sp;

	rm = (radix_mask *)malloc(sizeof(radix_mask));
	assert( rm );
	memcpy(rm, mask, sizeof(radix_mask));
	rm->rm_refs = 0;
	rm->rm_mklist = NULL;

	if ( deap ) {
		head = rm;
		for ( sp = head, rm = mask->rm_mklist;
				rm != NULL;
				rm = rm->rm_mklist, sp = sp->rm_mklist ) {
			sp->rm_mklist = rm_dup(rm,false);
		}
		rm = head;
	}

	return rm;
}

/*
radix_mask *rm_merge(radix_mask *l1,radix_mask *l2,int level)
{
	if ( l1 == NULL && l2 == NULL ) {
		return NULL;
	} else if ( l1 == NULL ) {
		return rm_dup(l2,true);
	} else if ( l2 == NULL ) {
		return rm_dup(l1,true);
	} else {
	}
}*/

caddr_t rm_lookup(struct in_addr *mask)
{
	caddr_t v = (caddr_t)mask;
	int i;

	if ( mask->s_addr == 0xffffffff )
		return NULL;	/* host route */

	/* may took 2 step */
	for ( i = 0; i < 33; i++ ) {
		if ( _mask_idx[i][0] == v[0] && _mask_idx[i][1] == v[1] 
				&& _mask_idx[i][2] == v[2] && _mask_idx[i][3] == v[3] )
			return _mask_idx[i];
	}

	return NULL;
}

int rm_add(radix_mask **h,radix_mask *rm)
{
	radix_mask *p,*q,*prev;

	if ( *h == NULL ) {
		/* alloc new */
		*h = rm_dup(rm,false);
		assert( *h );
		return 1;
	} else if ( (*h)->unused == rm->unused ) {
		return 1;
	} else if ( (*h)->unused > rm->unused ) {
		p = rm_dup(rm,false);
		p->rm_mklist = *h;
		*h = p;
		return 1;
	}

	/* we have a list */
	for ( p = (*h)->rm_mklist; p; prev = p, p = p->rm_mklist ) {
		if ( p->unused == rm->unused ) {
			return 1;
		} else if ( p->unused > rm->unused ) {
			q = rm_dup(rm,false);
			q->rm_mklist = p;
			prev->rm_mklist = q;
			return 1;
		}
	}

	return 0;
}

int rn_insert(radix_node_head *head,rtentry *ent)
{
	radix_node *top = head->rnh_treetop,*leaf,*internal;
	radix_node *prev,*t,*p,*c;
	struct in_addr key;
	int i,j,k,rc;
	caddr_t cp, cp2, cplim, mp, mp2;

	leaf = &ent->rt_nodes[0];
	internal = &ent->rt_nodes[1];

	leaf->rn_mklist = NULL;
	leaf->rn_p = internal;
	leaf->rn_bmask = 0;
	leaf->rn_flags = RNF_ACTIVE;;
	leaf->rn_key = (caddr_t)&ent->dst;
	leaf->rn_mask = rm_lookup(&ent->mask);
	leaf->rn_dupedkey = NULL;
	leaf->rn_b = -1 - ((leaf->rn_mask == NULL)
			? 0 : ((leaf->rn_mask - (caddr_t)_mask_idx)/4));
	if ( leaf->rn_mask != NULL ) {
		leaf->rn_mklist = rm_new((struct in_addr *)leaf->rn_mask);
		ent->rt_flags |= RTF_GATEWAY;
	} else {
		ent->rt_flags |= RTF_HOST;
	}

	internal->rn_mklist = NULL;
	internal->rn_p = NULL;
	internal->rn_b = 0;
	internal->rn_bmask = 0;
	internal->rn_flags = RNF_ACTIVE;
	internal->rn_off = 0;
	internal->rn_l = NULL;
	internal->rn_r = NULL;

	/* 1. rn_search로 찾는다 */
	t = rn_search(top,leaf->rn_key);

	/* 2. 만약 search로 return된 entry가 같다면 이미 존재하는 entry이므로
	 * return */

	cp = (caddr_t)&ent->dst;
	cplim = cp + 4;	/* 32bit */
	cp2 = t->rn_key;

	T_ROUTE("dst = %02x.%02x.%02x.%02x",
			(unsigned char)cp[0],(unsigned char)cp[1],
			(unsigned char)cp[2],(unsigned char)cp[3]
	);
	T_ROUTE("key = %02x.%02x.%02x.%02x",
			(unsigned char)cp2[0],(unsigned char)cp2[1],
			(unsigned char)cp2[2],(unsigned char)cp2[3]
	);

	for ( ; cp < cplim; cp++, cp2++ )
		if ( *cp != *cp2 ) goto do_insert;
	
	/* network mask를 보고 insert할 위치를 선택한다 */

	leaf->rn_p = t->rn_p;	/* should have same parents */

	mp = (caddr_t)&ent->mask;
	if ( t->rn_mask != NULL && mp < t->rn_mask ) {
		/* 첫 node에 insert해야 할 경우 */
		leaf->rn_dupedkey = t;
		
		/* fix parent node */
		if ( t->rn_p->rn_l == t )
			t->rn_p->rn_l = leaf;
		else
			t->rn_p->rn_r = leaf;
	} else {
		radix_node *rnp;

		for ( prev = t,rnp = t->rn_dupedkey;
				rnp;
				prev = rnp, rnp = rnp->rn_dupedkey ) {
			if ( mp < rnp->rn_mask ) {	/* it's time to insert? */
				prev->rn_dupedkey = leaf;
				leaf->rn_dupedkey = rnp;
				break;
			}
		}

		if ( rnp == NULL ) {	/* failed to insert.
								   should add at the end of the list */
			prev->rn_dupedkey = leaf;
		}
	}

	goto adjust_netmask;

do_insert:
	/* 3. 존재하지 않는 entry라면 return 키와 비교하여, 처음으로 다른 bit를
	 * 가려낸다 */

	for ( j = 0; !((*cp ^ *cp2) & _bit_idx[j]); j++ );
	internal->rn_off = 4 - (cplim - cp);
	internal->rn_bmask = _bit_idx[j];
	internal->rn_b = internal->rn_off * 8 + j;
	T_ROUTE("rn_off = %d rn_bmask = %02x rn_b = %d",
			internal->rn_off,
			(unsigned char)internal->rn_bmask,
			internal->rn_b
	);

	/* 4. internal node를 하나 만들고, return된 node를 backtracking하면서
	 * bit index가 더 작은 놈이 나올때 까지 거슬러 올라간다
	 */
	p = t->rn_p;
	while ( !(p->rn_flags & RNF_ROOT) && p->rn_b > internal->rn_b ) p = p->rn_p;

	/* 5. 찾은 node의 자식 node를 새 internal node로 바꾸고, bit에 따라서 
	 * 원래 있던 가지와 새로운 entry를 추가한다
	 */
	cp = (caddr_t)&ent->dst;

	if ( cp[p->rn_off] & p->rn_bmask ) {
		c = p->rn_r;
		p->rn_r = internal;
	} else {
		c = p->rn_l;
		p->rn_l = internal;
	}
	
	internal->rn_p = p;
	internal->rn_l = ( cp[internal->rn_off] & internal->rn_bmask ) ? c : leaf;
	internal->rn_r = ( cp[internal->rn_off] & internal->rn_bmask ) ? leaf : c;

	c->rn_p = internal;

adjust_netmask:
	/* 이제 network mask를 처리할 단계이다. */
	/* 현재 internal node의 자식 node들의 network mask에 대해서 adjust */
	/* FIXME : network mask adjust... */

	/* apply new network mask of leaf node */
	if ( leaf->rn_mask != NULL ) {
		/* network address. should look up position */
		radix_node *h = leaf->rn_p;
		/*int k = (leaf->rn_b * -1) -1;*/
		k = 32 - ((leaf->rn_b * -1) -1);

		T_ROUTE("find position to insert mask %s",inet_ntoa(ent->mask));
		/*T_ROUTE("bits are not used %d",k);*/
		T_ROUTE("bit position where subnet starts : %d",k);

		for ( h = leaf->rn_p, prev = NULL;
				h->rn_b > k;
				prev = h, h = h->rn_p );

		if ( prev == NULL && leaf->rn_p->rn_b <= k )
			prev = leaf->rn_p;
		/* we got proper position */
/*		if ( prev != NULL ) {*/
		if ( prev != NULL ) {
			T_ROUTE("found position (%08x) rn_b = %d",prev,prev->rn_b);
			rc = rm_add(&prev->rn_mklist,leaf->rn_mklist);
			T_ROUTE("rm_add rc = %d",rc);
		}
/*		} else if ( prev == NULL ) {*/
			/*
			T_ROUTE("failed to find position to insert netmask");
			*/
		/*}*/
	}

	/* if we insert an internal node, then let's adjust */
	if ( internal->rn_l != NULL && internal->rn_r != NULL ) {
		radix_node *h = ( internal->rn_l == leaf ) ? internal->rn_r : internal->rn_l;
		radix_mask *rm = h->rn_mklist;
		for ( rm = h->rn_mklist; rm; rm = rm->rm_mklist ) { 
			for ( t = h, prev = NULL;
					!(t->rn_flags & RNF_ROOT) && t->rn_b < rm->unused;
					prev = t, t = t->rn_p );
			if ( prev != NULL ) {
				rc = rm_add(&prev->rn_mklist,rm);
				T_ROUTE("rm_add rc = %d",rc);
			}
		}
	}

	T_ROUTE("%s insertion completed ",inet_ntoa(ent->dst));
	rnh_dump();
	
	return 0;
}

int rn_delete(radix_node_head *head,struct in_addr *key)
{
	caddr_t cp = (caddr_t)key;
	radix_node *x = rn_search(head->rnh_treetop,key);
	radix_node *c,*p;

	if ( x == NULL ) return 0;	/* not found */

	if ( memcmp(cp,x->rn_key,4) != 0 ) return 0;	/* not found */

	if ( (x->rn_flags & RNF_ROOT) != 0 ) {
		/* remove all duplicated keys */
		for ( p = x; x; x = x->rn_dupedkey ) {
			/* free duped entry */
		}
	} else {
		/* fix links */
		c = ( x->rn_p->rn_l == x ) ? x->rn_p->rn_r : x->rn_p->rn_l;
		c->rn_p = x->rn_p->rn_p;

		if ( c->rn_p->rn_l == x->rn_p ) {
			c->rn_p->rn_l = c;
		} else {
			c->rn_p->rn_r = c;
		}
		
		/* remove network masks */
	}

	/* free routing entry */

	return 0;
}

static void _rnh_free(radix_node *rn,list l)
{
	radix_mask *p,*t;

	if ( rn->rn_b >= 0 ) {	/* internal node */
		if ( rn->rn_l != NULL ) _rnh_free(rn->rn_l,l);
		rn->rn_l = NULL;
		if ( rn->rn_r != NULL ) _rnh_free(rn->rn_r,l);
		rn->rn_r = NULL;
	} else {	/* leaf node */
		/* free duplicated entries */
		if ( rn->rn_dupedkey != NULL ) _rnh_free(rn->rn_dupedkey,l);
		rn->rn_dupedkey = NULL;
	}

	/* free network mask */
	if ( rn->rn_mklist != NULL ) {
		p = rn->rn_mklist;
		while ( p != NULL ) {
			t = p->rm_mklist;
			p->rm_mklist = NULL;
			free(p);
			p = t;
		}
		rn->rn_mklist = NULL;
	}

	if ( !(rn->rn_flags & RNF_ROOT) && rn->rn_b < 0 ) {
		/* do not free root entries */
		/* root node를 제외한 모든 leaf node들은 rtentry의 첫번째 멤버임 */
		list_add_tail(l,rn);
	}
}

int rnh_free(radix_node_head *head)
{
	list l = list_open();
	rtentry *rt;

	_rnh_free(head->rnh_treetop,l);

	head->rnh_treetop = NULL;

	/* let's free whole */
	while ( (rt = (rtentry *)list_remove_head(l)) != NULL ) free(rt);

	list_close(l);

	return 0;
}

radix_node *rn_search(radix_node *head,void *v_arg)
{
	radix_node *x;
	caddr_t v = (caddr_t)v_arg;

	for ( x = head; x->rn_b >= 0; ) {
		if ( x->rn_bmask & v[x->rn_off] )
			x = x->rn_r;
		else
			x = x->rn_l;
	}

	return x;
}

radix_node *rn_match(radix_node_head *head,struct in_addr *v_arg)
{
	caddr_t v = (caddr_t)v_arg;
	radix_node *t = head->rnh_treetop, *x;
	caddr_t cp = v, cp2, cp3;
	caddr_t cplim, mstart;
	radix_node *saved_t, *top = t;
	int matched_off;

	/* open rn_search() to avoid overhead of extra function call */
	for ( ; t->rn_b >= 0; ) {
		if ( t->rn_bmask & cp[t->rn_off] )
			t = t->rn_r;
		else
			t = t->rn_l;
	}

	/* see if we match exactly as a host destination */
	cp = v;
	cp2 = t->rn_key;
	cplim = v + 4;
	for ( ; cp < cplim; cp++, cp2++ )
		if ( *cp != *cp2 )
			goto on1;

	if ( (t->rn_flags & RNF_ROOT) && t->rn_dupedkey )
		t = t->rn_dupedkey;

	return t;
on1:
	matched_off = cp - v;
	saved_t = t;

	T_ROUTE("perform network match in node %08x",t);
	do {
		if ( t->rn_mask ) {
			/* even if we don't match exactly as a host
			 * we may match if the leaf we wound up at 
			 * is a route to a net
			 */
			cp3 = matched_off + t->rn_mask;
			cp2 = matched_off + t->rn_key;
			for ( ; cp < cplim; cp++ )
				if ( (*cp2++ ^ *cp) & *cp3++ )
					break;
			if ( cp == cplim )
				return t;
			cp = matched_off + v;
		}
	} while ( (t = t->rn_dupedkey) );

	t = saved_t;

	T_ROUTE("back tracking from %08x",t);

	/* start back tracking */
	do {
		radix_mask *m;
		t = t->rn_p;
		T_ROUTE("parent node : %08x",t);
		if ( (m = t->rn_mklist) ) {
#define min(x,y)	( (x) > (y) ) ? (y) : (x)
			mstart = maskedKey;
			do {
				cp2 = mstart;
				cp3 = m->rm_mask;
				for ( cp = v; cp < cplim; )
					*cp2++ = *cp++ & *cp3++;
				T_ROUTE("masked key = %d.%d.%d.%d",
						(unsigned char)maskedKey[0],
						(unsigned char)maskedKey[1],
						(unsigned char)maskedKey[2],
						(unsigned char)maskedKey[3]
				);
				x = rn_search(t,maskedKey);
				if ( x != NULL )
					T_ROUTE("returned node : %08x %d.%d.%d.%d",
							x,
							(unsigned char)x->rn_key[0],
							(unsigned char)x->rn_key[1],
							(unsigned char)x->rn_key[2],
							(unsigned char)x->rn_key[3]
					);
				while ( x && x->rn_mask != m->rm_mask )
					x = x->rn_dupedkey;
				if ( x && memcmp(mstart,x->rn_key,4/* 32bit */) == 0 ) {
					T_ROUTE("Finally return node %08x",x);
					return x;
				}
			} while ( (m = m->rm_mklist) );
		}
	} while ( t != top );

	return NULL;
}


/*
 * Routing table initialization
 */
#ifdef HAVE_ROUTE_STATS
/* TODO: Get/Set Methods */
static unsigned int ipForwardMissCount = 0;
#endif /* HAVE_ROUTE_STATS */

int rt_init(dictionary *conf)
{
	FILE *fp;
	char file[1024],buf[512];
	int type,line = 1;
	char *name,*target,*mask,*gw,*dev;
	char *p,*s;
	token_list *tks;
	int i,ok;
	rtentry *rte;
	struct in_addr def_route;
	ifnet *ifp = ifunit(DEFAULT_IF);

	/* register for kmgmt */
	kmgmt_register (KMOD_IP, KXML_MOD_IP, rt_kmgmt_handler);

	/* load routing table */
	rnh_init(&rn_head);

	T_ROUTE("before set up default route");
	rnh_dump();

	def_route.s_addr = 0x00000000;

	/* intialize with default value */
	s = iniparser_getstring(conf,"KENS:default_route",NULL);
	if ( s != NULL ) {
		/* insert default router */
		if ( !inet_aton(s,&def_route) ) {
			fprintf(stderr,"invalid default router address\n");
			def_route.s_addr = 0x00000000;
		}

		/* let's check which devices should be used */
		for ( ifp = _ifnet; ifp; ifp = ifp->if_next )
			if ( in_localnet(ifp,def_route) )
				break;

		if ( ifp != NULL ) {
			/* build default routing entry */
			rte = (rtentry *)malloc(sizeof(rtentry));
			assert( rte );
			
			rte->dst.s_addr = 0x00000000;
			rte->mask.s_addr = 0x00000000;
			rte->gw.s_addr = def_route.s_addr;
			rte->rt_ifp = ifp;
			/* FIXME : rt_ifa? */

			/* insert default route */
			if ( rn_insert(&rn_head,rte) ) {
				fprintf(stderr,"failed to insert default route\n");
				free(rte);
			}
		}
	}

	/* insert route for local loopback */
	rte = (rtentry *)malloc(sizeof(rtentry));
	assert( rte );

	inet_aton("127.0.0.1",&rte->dst);
	rte->mask.s_addr = 0xffffffff;
	inet_aton("127.0.0.1",&rte->gw);
	rte->rt_ifp = ifunit("lo");
	if ( rn_insert(&rn_head,rte) ) {
		fprintf(stderr,"failed to insert loopback route\n");
		free(rte);
	}
	/* end of insert local loopback route */

	s = iniparser_getstring(conf,"KENS:server_name","KENS");
	sprintf(file,"%s.route",s);
	fp = fopen(file,"r");
	if ( fp == NULL ) return 0;	/* do not parse anymore */

	while ( fgets(buf,512,fp) != NULL ) {
		p = strchr(buf,'#');
		if ( p != NULL ) *p = '\0';
		if ( buf[strlen(buf)-1] == '\n' ) buf[strlen(buf)-1] = '\0';

		p = buf;
		p = eat_ws(p);
		if ( p == NULL ) goto nextline;

		tks = tokenize(p,NULL,false);

		target = mask = gw = dev = NULL;
		i = 0;
		ok = 0;
		while ( i < token_list_num(tks) ) {
			name = token_list_get(tks,i);
			if ( !strcmp(name,"host") ) {
				type = 0;	/* 0 for host route */
				if ( ++i >= token_list_num(tks) ) goto badops;
				target = token_list_get(tks,i);
			} else if ( !strcmp(name,"net") ) {
				type = 1;	/* 1 for network route */
				if ( ++i >= token_list_num(tks) ) goto badops;
				target = token_list_get(tks,i);
			} else if ( !strcmp(name,"netmask") ) {
				if ( ++i >= token_list_num(tks) ) goto badops;
				mask = token_list_get(tks,i);
			} else if ( !strcmp(name,"gw") ) {
				if ( ++i >= token_list_num(tks) ) goto badops;
				gw = token_list_get(tks,i);
			} else if ( !strcmp(name,"dev") ) {
				if ( ++i >= token_list_num(tks) ) goto badops;
				dev = token_list_get(tks,i);
			} else {
				if ( i+1 == token_list_num(tks) )
					dev = token_list_get(tks,i);
				else goto badops;
			}
			i++;
		}
		ok = 1;

		/* construct route entry */
		rte = (rtentry *)malloc(sizeof(rtentry));
		assert( rte );

		if ( !inet_aton(target,&rte->dst) ) {
			fprintf(stderr,"%s:line %d - invalid target %s\n",file,line,target);
			goto error;
		}

		if ( type == 0 ) {
			rte->mask.s_addr = 0xffffffff;
		} else if ( !inet_aton(mask,&rte->mask) ) {
			fprintf(stderr,"%s:line %d - invalid netmask %s\n",file,line,mask);
			goto error;
		}

		if ( gw != NULL ) {
			if ( !inet_aton(gw,&rte->gw) ) {
				fprintf(stderr,"%s:line %d - invalid gateway address %s\n",file,line,gw);
				goto error;
			}
		} else if ( type == 0 ) {	/* host routing일 경우 */
			rte->gw.s_addr = rte->dst.s_addr;
		}

		rte->rt_ifp = ( dev == NULL ) ? ifp : ifunit(dev);
		if ( rte->rt_ifp == NULL ) {
			fprintf(stderr,"%s:line %d - invalid device %s\n",file,line,
					( dev == NULL ) ? DEFAULT_IF : dev);
			goto error;
		}
		/* FIXME : rt_ifa? */
		
		/* insert into routing table */
		if ( rn_insert(&rn_head,rte) ) {
			fprintf(stderr,"%s:line %d - failed to insert routine entry\n",file,line);
error:
			free(rte);
		}
badops:
		if ( !ok ) {
			fprintf(stderr,"%s:line %d - bad option %s\n",file,line,token_list_get(tks,i));
		}
		token_list_free(tks);
nextline:
		line++;
	}

	return 0;
}

void rt_alloc(route *ro)
{
	radix_node *rn = NULL;
	radix_node_head *rnh = &rn_head;
	rtentry *rt = NULL;
	ifnet *ifp = NULL;

	/* FIXME : first check out whether it is in local network */
	for ( ifp = _ifnet; ifp; ifp = ifp->if_next ) {
		if ( in_localnet(ifp,ro->ro_dst) ) {
			/* local network. allocate new entry */
			ro->ro_rt = (rtentry *)malloc(sizeof(rtentry));
			assert(ro->ro_rt);
			ro->ro_rt->dst.s_addr = ro->ro_dst.s_addr;
			ro->ro_rt->mask.s_addr = 0;
			ro->ro_rt->gw.s_addr = ro->ro_dst.s_addr;
			ro->ro_rt->rt_flags = RTF_HOST|RTF_SHOULD_FREED;
			ro->ro_rt->rt_ifp = ifp;
			T_ROUTE("%s is in localnetwork",inet_ntoa(ro->ro_dst));
			return;
		}
	}

	T_ROUTE("try to locate proper routing entry");
	if ( rnh && (rn = rn_match(rnh,&ro->ro_dst)) != NULL
			&& ((rn->rn_flags & RNF_ROOT) == 0) ) {
		rt = (rtentry *)rn;
		T_ROUTE("rn = %08x if = %08x gw = %s flags = %u",
				rn,
				rt->rt_ifp,
				inet_ntoa(rt->gw),
				rt->rt_flags
		);
		rt->rt_refcnt++;
		ro->ro_rt = rt;
#ifdef HAVE_ROUTE_STATS
		/*
		 * ipForwardHitCount
		 */
		rt->ipForwardHitCount++;
#endif /* HAVE_ROUTE_STATS */
	} else {
		T_ROUTE("failed to locate routing entry");
#ifdef HAVE_ROUTE_STATS
		/*
		 * ipForwardMissCount
		 */
		ipForwardMissCount++;
#endif /* HAVE_ROUTE_STATS */
	}
}


int rt_cleanup(void)
{
	rnh_free(&rn_head);
	free(rn_zeros);

	return 0;
}

/*
 * utility function
 */

void rn_dump(radix_node *rn)
{
	char buf[128];
	radix_mask *rm;
	radix_node *n;

	if ( rn->rn_b >= 0 ) {
		L_ROUTE("I(%08x) B : %3d M : %02x OFF : %2d L : %08x R : %08x IF : %08x",
				rn,rn->rn_b,(unsigned char)rn->rn_bmask,rn->rn_off,rn->rn_l,rn->rn_r, ((rtentry*)rn)->rt_ifp);
		if ( rn->rn_mklist != NULL ) {
			for ( rm = rn->rn_mklist; rm; rm = rm->rm_mklist ) {
				L_ROUTE("  Mask : %d.%d.%d.%d(%d)",
					(unsigned char)rm->rm_mask[0],
					(unsigned char)rm->rm_mask[1],
					(unsigned char)rm->rm_mask[2],
					(unsigned char)rm->rm_mask[3],
					rm->unused);
			}
		}

		rn_dump(rn->rn_l);
		rn_dump(rn->rn_r);
	} else {
		if ( rn->rn_mask != NULL )
			sprintf(buf,"%d.%d.%d.%d",
					(unsigned char)rn->rn_mask[0],
					(unsigned char)rn->rn_mask[1],
					(unsigned char)rn->rn_mask[2],
					(unsigned char)rn->rn_mask[3]);

		L_ROUTE("L(%08x) B : %3d KEY : %-15s MASK : %-15s IF : %08x",
				rn,rn->rn_b,
				inet_ntoa(*((struct in_addr *)rn->rn_key)),
				( rn->rn_mask == NULL ) ? "255.255.255.255" : buf,
				((rtentry*)rn)->rt_ifp
		);
		
		if ( rn->rn_mklist != NULL ) {
			for ( rm = rn->rn_mklist; rm; rm = rm->rm_mklist ) {
				L_ROUTE("  Mask : %d.%d.%d.%d(%d)",
					(unsigned char)rm->rm_mask[0],
					(unsigned char)rm->rm_mask[1],
					(unsigned char)rm->rm_mask[2],
					(unsigned char)rm->rm_mask[3],
					rm->unused);
			}
		}

		/* print duplicated nodes */
		for ( n = rn->rn_dupedkey; n; n = n->rn_dupedkey ) {
			L_ROUTE("  (%08x) Duped Mask : %d.%d.%d.%d",
				n,
				(unsigned char)n->rn_mask[0],
				(unsigned char)n->rn_mask[1],
				(unsigned char)n->rn_mask[2],
				(unsigned char)n->rn_mask[3]
			);
		}
	}
}

void rn_dump_to_list(list rte_list, radix_node *rn)
{
	char buf[128];
	radix_mask *rm;
	radix_node *n;

	if ( rn->rn_b >= 0 ) {
		rn_dump_to_list(rte_list, rn->rn_l);
		rn_dump_to_list(rte_list, rn->rn_r);
	} else {
		list_add_tail(rte_list, rn);
	}
}

void rnh_dump(void)
{
	radix_node_head *rnh = &rn_head;

	L_ROUTE("-----BEGIN ROUTING TABLE-----");
	rn_dump(rnh->rnh_treetop);
	L_ROUTE("-----END ROUTING TABLE-----");
}

list rt_query()
{
	list rte_list = list_open();
	rn_dump_to_list(rte_list, rn_head.rnh_treetop);
	return rte_list;
}

int rt_insert(rtentry *ent)
{
	return rn_insert(&rn_head, ent);
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
 * When KensG requests for IP routes data, rt_kmgmt_handler() is called.
 * "route" table maintains an index of "Dest.IP/Netmask/Gateway"
 *
 * @param	modid module id
 *			cmd either get/set
 *			table table name, currently only "route" is supported
 *			index index for the table.
 *			rindex for "get"
 *			nparam # of requested parameters
 *			nvalue # of returned parameters for "get"
 *			params list of requested parameters
 *			values list of returned parameters
 * @return  error code
 */
static int rt_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values)
{
	list_position param_pos = NULL;

	n_linked_list_t *entry = NULL;
	kmgmt_param_t *inattr = NULL;
	kmgmt_param_t *outattr = NULL;

	list rte_list = rt_query();
	list_position rt_pos;

	char *address = NULL;
	char *netmask = NULL;
	char *nexthop = NULL;

	in_addr_t addr, mask, gw;

#undef BUFSIZ
#define BUFSIZ	1024
	char buffer[BUFSIZ];

	if (cmd < 0 || cmd >= KMGMT_MAX)
	{
		return FAILED;
	}

	if (table != NULL && strcmp(table,"route") == 0)
	{
		if (cmd == KMGMT_SET)
		{
			if (index == NULL)
			{
				DBG ("SET without an index is not supported.\n");
				goto error;
			}
		}

		/* 
		 * parse the index: A.B.C.D/A.B.C.D/A.B.C.D
		 */
		if (index != NULL)
		{
			char *delim = strstr (index, "/");
			char *delim2;

			if (delim == NULL)
			{
				DBG ("Unable to parse the index %s\n", index);
				index = NULL;
			}
			else
			{
				delim2 = strstr (delim + 1, "/");

				if (delim == NULL)
				{
					DBG ("Unable to parse the index %s\n", index);
					index = NULL;
				}
				else
				{
					address = strndup (index, (size_t)(delim - index));
					netmask = strndup (delim + 1, (size_t) (delim2 - delim));
					nexthop = strdup (delim2 + 1);

					addr = inet_addr (address);
					mask = inet_addr (netmask);
					gw = inet_addr (nexthop);
				}
			}
		}

		/*
		 * iterate through the route table 
		 */
		for (rt_pos = list_get_head_position(rte_list);
				rt_pos; rt_pos = list_get_next_position(rt_pos)) {

			rtentry *rte = list_get_at(rt_pos);

			for (; rte; rte = (rtentry *)((radix_node *)rte)->rn_dupedkey) {
				if (((radix_node *)rte)->rn_mask == NULL)
					continue;

				if (index != NULL)
				{
					if (rte->dst.s_addr != addr|| rte->mask.s_addr != mask ||
							rte->gw.s_addr != gw)
					{
						continue;
					}
				}

				entry = NULL;
				inattr = NULL;
				outattr = NULL;

				if (cmd == KMGMT_GET)
				{
					entry = (n_linked_list_t*)malloc (sizeof(n_linked_list_t));
					entry->l = list_open();
					sprintf (buffer, "%s/%s/%s", inet_ntoa(rte->dst), 
							inet_ntoa(rte->mask), inet_ntoa(rte->gw));
					entry->index = strdup (buffer);
				}

				param_pos = list_get_head_position (params);

				while (param_pos != NULL)
				{
					char *value = NULL;

					inattr = (kmgmt_param_t*)list_get_at (param_pos);
					if (!inattr)
						continue;

					if (!strcmp(inattr->param, "destination"))
					{
						if (cmd == KMGMT_GET)
						{
							sprintf (buffer, "%s", inet_ntoa(rte->dst));
							value = strdup (buffer);
						}
						else if (cmd == KMGMT_SET)
						{
							DBG ("set method is not supported\n");
						}
					} 
					else if (!strcmp(inattr->param, "netmask"))
					{
						if (cmd == KMGMT_GET)
						{
							sprintf (buffer, "%s", inet_ntoa(rte->mask));
							value = strdup (buffer);
						}
						else if (cmd == KMGMT_SET)
						{
							DBG ("set method is not supported\n");
						}
					}
					else if (!strcmp(inattr->param, "nexthop"))
					{
						if (cmd == KMGMT_GET)
						{
							sprintf (buffer, "%s", inet_ntoa(rte->gw));
							value = strdup (buffer);
						}
						else if (cmd == KMGMT_SET)
						{
							DBG ("set method is not supported\n");
						}
					}
					else if (!strcmp(inattr->param, "hitcount"))
					{
						if (cmd == KMGMT_GET)
						{
							sprintf (buffer, "%d", rte->ipForwardHitCount);
							value = strdup (buffer);
						}
						else if (cmd == KMGMT_SET)
						{
							DBG ("set method is not supported\n");
						}
					}
					else if (!strcmp(inattr->param, "age"))
					{
						if (cmd == KMGMT_GET)
						{
							sprintf (buffer, "%d", rte->ipForwardAge);
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
			}
		}

		if (address != NULL)
			free (address);

		if (netmask != NULL)
			free (netmask);
	}
	else
	{
		DBG ("Unknown Table\n");
	}

	return DONE;

error:
	if (address != NULL)
		free (address);

	if (netmask != NULL)
		free (netmask);

	return FAILED;
}

/* For compatibility with MacOSX */
#ifdef __APPLE__
static size_t strnlen(const char *s, size_t len)
{
	size_t i;
	for (i=0; i<len && *(s+i); i++);
	return i;
}

static char *strndup(char const *s, size_t n)
{
	size_t len = strnlen(s, n);
	char *new = malloc(len + 1);

	if (new == NULL)
		return NULL;

	new[len] = '\0';
	return memcpy(new, s, len);
}
#endif

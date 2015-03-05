#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "datalink.h"
#include "misc.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

MAC_ADDR_ENTRY *MAC_ADDR_ENTRY_new(void)
{
	MAC_ADDR_ENTRY *ret = NULL;

	ret = (MAC_ADDR_ENTRY *)malloc(sizeof(MAC_ADDR_ENTRY));
	if ( ret == NULL ) return NULL;
	
	memset(ret,0x00,sizeof(MAC_ADDR_ENTRY));
	ret->mac.sin_family = AF_INET;

	return ret;
}

void MAC_ADDR_ENTRY_free(MAC_ADDR_ENTRY *e)
{
	if ( e == NULL ) return;
	free(e);
}

/*
 * PARTRICIA tree implmentation for mac address table
 */
typedef struct _partricia_node {
	int bit_number;
	MAC_ADDR_ENTRY *addr;
	struct _partricia_node *left,*right;
} PARTRICIA_NODE;

#define pn_key	addr->vip.s_addr


static int _bit_idx[33] = {
	0x00000000,
	0x80000000, 0x40000000, 0x20000000, 0x10000000,
	0x08000000, 0x04000000, 0x02000000, 0x01000000,
	0x00800000, 0x00400000, 0x00200000, 0x00100000,
	0x00080000, 0x00040000, 0x00020000, 0x00010000,
	0x00008000, 0x00004000, 0x00002000, 0x00001000,
	0x00000800, 0x00000400, 0x00000200, 0x00000100,
	0x00000080, 0x00000040, 0x00000020, 0x00000010,
	0x00000008, 0x00000004, 0x00000002, 0x00000001
};

#define bit(x,i)	( ( (x) & _bit_idx[(i)] ) >> (32-(i)))

static void _partricia_cleanup(PARTRICIA_NODE *n)
{
	if ( n->addr != NULL ) MAC_ADDR_ENTRY_free(n->addr);
	n->addr = NULL;
	if ( n->left != NULL && n->bit_number > n->left->bit_number )
		_partricia_cleanup(n->left);
	n->left = NULL;
	if ( n->right != NULL && n->bit_number > n->right->bit_number )
		_partricia_cleanup(n->right);
	n->right = NULL;
	free(n);
}

static void partricia_cleanup(void *ctx)
{
	PARTRICIA_NODE *t = (PARTRICIA_NODE *)ctx;

	if ( t == NULL ) return;

	_partricia_cleanup(t);
}

static PARTRICIA_NODE *partricia_search(void *ctx,struct in_addr k)
{
	PARTRICIA_NODE *t = (PARTRICIA_NODE *)ctx,*p,*y;

	if ( t == NULL ) return NULL;
	y = t->left;
	p = t;

	while ( y->bit_number > p->bit_number ) {
		p = y;
		y = (bit(k.s_addr,y->bit_number)) ? y->right : y->left;
	}

	return y;
}

static struct sockaddr_in *partricia_match(void *ctx,struct in_addr k)
{
	PARTRICIA_NODE *y;

	y = partricia_search(ctx,k);
	if ( y == NULL ) return NULL;

	return ( k.s_addr == y->pn_key )
			? &MAC_ADDR_ENTRY_get_mac(y->addr)
			: (struct sockaddr_in *)NULL;
}

static int partricia_insert(void **ctx,MAC_ADDR_ENTRY *entry)
{
	PARTRICIA_NODE **t = (PARTRICIA_NODE **)ctx;
	PARTRICIA_NODE *s,*p,*y,*z;
	int i;
	struct in_addr ent_key = MAC_ADDR_ENTRY_get_vip(entry);
	
	
	if ( *t == NULL ) {	/* empty tree */
		*t = (PARTRICIA_NODE *)malloc(sizeof(PARTRICIA_NODE));
		assert( *t );
		(*t)->bit_number = 0;
		(*t)->addr = entry;
		(*t)->left = *t;
		(*t)->right = NULL;
		return 1;
	}

	y = partricia_search(*t,ent_key);
	if ( ent_key.s_addr == y->pn_key ) {
		return 0;
	}

	for ( i = 1; bit(ent_key.s_addr,i) == bit(y->pn_key,i); i++ );

	s = (*t)->left;
	p = *t;
	while ( s->bit_number > p->bit_number && s->bit_number < i ) {
		p = s;
		s = ( bit(ent_key.s_addr,s->bit_number) ) ? s->right : s->left;
	}

	z = (PARTRICIA_NODE *)malloc(sizeof(PARTRICIA_NODE));
	assert( z );

	z->addr = entry;
	z->bit_number = i;
	z->left = ( bit(ent_key.s_addr,i) ) ? s : z;
	z->right = ( bit(ent_key.s_addr,i) ) ? z : s;
	if ( s == p->left )
		p->left = z;
	else
		p->right = z;

	return 1;
}

MAC_TABLE *MAC_TABLE_new(void)
{
	MAC_TABLE *ret = NULL;

	ret = (MAC_TABLE *)malloc(sizeof(MAC_TABLE));
	if ( ret == NULL ) return NULL;

	memset(ret,0x00,sizeof(MAC_TABLE));

	ret->mac_add = partricia_insert;
	ret->mac_lookup = partricia_match;
	ret->mac_free = partricia_cleanup;

	return ret;
}

void MAC_TABLE_free(MAC_TABLE* table)
{
	if ( table == NULL ) return;

	/*
	for ( i = 0; i < 256; i++ ) {
		e = MAC_TABLE_get_by_index(table,i);
		if ( e != NULL ) MAC_ADDR_ENTRY_free(e);
	}*/
	if ( table->mac_free != NULL )
		table->mac_free(table->ctx);

	free(table);
}


int MAC_TABLE_add_entry(MAC_TABLE *table,MAC_ADDR_ENTRY *entry)
{
	return table->mac_add(&(table->ctx),entry);
}

struct sockaddr_in *MAC_TABLE_lookup(MAC_TABLE *table,struct in_addr vip)
{
	/*
	MAC_ADDR_ENTRY *e = MAC_TABLE_get_by_addr(table,vip);
	return ( e == NULL ) ? NULL : MAC_ADDR_ENTRY_get_mac(e);
	*/
	return table->mac_lookup(table->ctx,vip);
}

/**
 * load MAC table for specified subnetwork
 * @param ip virtual ip address for sub network. should be in network byte
 * order
 * @param mask network mask for sub network. should be in network byte order
 * @return loaded mac address table for subnetwork
 */
MAC_TABLE *MAC_TABLE_load(const char *path,const char *fn)
{
	FILE *fp = NULL;
	char file[1024],buf[512];
	char *vip,*ip,*port,*p;
	MAC_ADDR_ENTRY *entry;
	MAC_TABLE *ret = NULL;
	struct in_addr _vip;
	struct sockaddr_in _mac;
	int line = 1;

	memset(&_mac,0x00,sizeof(struct sockaddr_in));
	_mac.sin_family = AF_INET;

	ret = MAC_TABLE_new();
	if ( ret == NULL ) {
		goto error;
	}
	
	/* FIXME : we should get path separator from system call for portablility * */
	sprintf(file,"%s%s",( path == NULL ) ? "./" : path,fn);
	fp = fopen(file,"r");
	if ( fp == NULL ) {
		fprintf(stderr,"unable to load file %s\n",file);
		goto error;
	}

	while ( fgets(buf,512,fp) != NULL ) {
		p = strchr(buf,'#');
		if ( p != NULL ) *p = '\0';
		if ( buf[strlen(buf)-1] == '\n' ) buf[strlen(buf)-1] = '\0';

		p = buf;
		p = eat_ws(p);	/* remove leading white space */
		if ( p == NULL ) goto nextline;
		vip = p;	/* we got virtual ip */

		p = eat_ipaddr(vip);	/* look up real ip address */	
		if ( p == NULL ) {
			fprintf(stderr,"%s(line %d) invalid virtual IP address\n",file,line);
			goto nextline;
		}
		*p++ = '\0';

		p = eat_ws(p);
		if ( p == NULL ) {
			fprintf(stderr,"%s(line %d) no real IP address and port for %s\n",file,line,vip);
			goto nextline;
		}
		
		ip = p;
		p = eat_ipaddr(ip);
		if ( *p != ':' ) {
			fprintf(stderr,"%s(line %d) invalid format for IP address and port at '%s'\n",file,line,p);
			goto nextline;
		}
		*p++ = '\0';

		port = p;
		p = eat_digit(port);

		/* now let's parse ip address */
		if ( !inet_aton(vip,&_vip) ) {
			fprintf(stderr,"%s(line %d) invalid IP address format for virtual IP %s\n",file,line,vip);
			goto nextline;
		}

		/*_vip.s_addr = ntohl(_vip.s_addr);*/	/* virtual ip address는 host byte order */

		if ( !inet_aton(ip,&_mac.sin_addr) ) {
			fprintf(stderr,"%s(line %d) invalid IP address format for real IP %s\n",file,line,ip);
			goto nextline;
		}

		_mac.sin_port = htons((in_port_t)atoi(port));

		entry = MAC_ADDR_ENTRY_new();
		if ( entry == NULL ) goto error;

		MAC_ADDR_ENTRY_set_vip(entry,_vip);
		MAC_ADDR_ENTRY_set_mac(entry,&_mac);

		if ( !MAC_TABLE_add_entry(ret,entry) ) {
			fprintf(stderr,"%s(line %d) already exists %s\n",file,line,ip);
			MAC_ADDR_ENTRY_free(entry);
			goto error;
		}
		entry = NULL;
nextline:
		if ( entry != NULL ) MAC_ADDR_ENTRY_free(entry);
		entry = NULL;
		line++;
	}

	return ret;
error:
	if ( ret != NULL ) MAC_TABLE_free(ret);
	ret = NULL;

	return ret;
}

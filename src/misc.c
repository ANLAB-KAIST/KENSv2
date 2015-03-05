#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "config.h"
#include "misc.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif
/*
 * string utilities
 */

char *eat_ws(char *p)
{
	while ( isspace(*p) && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

char *eat_ipaddr(char *p)
{
	while ( (isdigit(*p) || *p == '.') && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

char *eat_digit(char *p)
{
	while ( isdigit(*p) && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

char *eat_alpha(char *p)
{
	while ( isalpha(*p) && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

char *eat_lower(char *p)
{
	while ( islower(*p) && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

char *eat_alphanum(char *p)
{
	while ( isalnum(*p) && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

char *eat_ex_chars(char *p,char *chrs)
{
	while ( strchr(chrs,*p) == NULL && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}


char *eat_chars(char *p,char *chrs)
{
	while ( strchr(chrs,*p) != NULL && *p != '\0' ) p++;
	return ( *p == '\0' ) ? NULL : p;
}

token_list *tokenize(char *src,char *del,bool copy)
{
	token_list *ret = NULL;
	char *p,*q,*r,*d;
	int n;
	char *DELIM = " \t\n\r";

	ret = (token_list *)malloc(sizeof(token_list));
	assert( ret );

	memset(ret,0x00,sizeof(token_list));

	d = ( del == NULL ) ? DELIM : del;
	p = eat_chars(src,d);	/* remove leading deliminators */

	ret->copied = ( copy ) ? strdup(p) : NULL;
	p = q = ( copy ) ? ret->copied : src;


	/* scan twice */
	n = 1;
	while ( 1 ) {
		r = eat_ex_chars(q,d);
		if ( r == NULL ) break;	/* we reach to end */
		/* we got a token */
		q = eat_chars(r,d);	/* eat deliminators */
		if ( q == NULL ) break; /* we reach to end */
		/* we got next token */
		n++;
	}

	ret->n = n;
	ret->tokens = (char **)malloc(sizeof(char *)* (ret->n));
	assert(ret->tokens);
	
	n = 0;
	ret->tokens[n] = p;
	while ( 1 ) {
		q = eat_ex_chars(p,d);
		if ( q == NULL ) break;	/* we reach to end */
		/* we got a token */
		*q++ = '\0';

		p = eat_chars(q,d);	/* eat deliminators */
		if ( p == NULL ) break; /* we reach to end */
		/* we got next token */
		ret->tokens[++n] = p;
	}

	return ret;
}

void token_list_free(token_list *l)
{
	if ( l == NULL ) return;
	if ( l->copied != NULL ) free(l->copied);
	if ( l->tokens != NULL ) free(l->tokens);
	free(l);
}

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp,struct in_addr *inp)
{
	char buf[16];
	char *p,*q;
	uint32_t t;

	if ( cp != NULL && strlen(cp) > 15 ) return 0;	/* invalid format */

	memcpy(buf,cp,16);
	buf[15] = '\0';

	p = q = buf;

	while ( isdigit(*p) ) p++;
	*p++ = '\0';
	t = atoi(q) << 24;
	q = p;
	while ( isdigit(*p) ) p++;
	*p++ = '\0';
	t |= atoi(q) << 16;
	q = p;
	while ( isdigit(*p) ) p++;
	*p++ = '\0';
	t |= atoi(q) << 8;
	q = p;
	t |= atoi(q);

	inp->s_addr = htonl(t);

	return 1;
}
#endif

int inet_ntoa_r(struct in_addr in,char *buf,size_t len)
{
	unsigned char *p = (unsigned char *)&in;

	if ( len < 16 ) return -1;
	sprintf(buf,"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);

	return strlen(buf);
}

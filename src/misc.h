#ifndef MISC_H
#define MISC_H

#include <ctype.h>
#include <netinet/in.h>

#include "config.h"

#if !defined(__bool_defined) && !defined(__cplusplus) && !defined(c_plusplus)
	#define __bool_defined
	typedef char bool;
	#define false	(0)
	#define true	(1)
#endif

char *eat_ws(char *p);
char *eat_ipaddr(char *p);
char *eat_digit(char *p);
char *eat_alpha(char *p);
char *eat_lower(char *p);
char *eat_alphanum(char *p);
char *eat_ex_chars(char *p,char *chrs);
char *eat_chars(char *p,char *chrs);

typedef struct _token_list_t {
	char *copied;
	char **tokens;
	int n;
} token_list;

void token_list_free(token_list *l);

token_list *tokenize(char *src,char *del,bool copy);
#define token_list_get(x,i)	( ((i) < (x)->n) ? (x)->tokens[(i)] : NULL )
#define token_list_num(x)			(x)->n

#ifndef HAVE_INET_ATON
int inet_aton(const char *cp,struct in_addr *inp);
#endif
int inet_ntoa_r(struct in_addr in,char *buf,size_t len);

#endif

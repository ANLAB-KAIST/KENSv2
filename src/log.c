#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include "log.h"
#include "misc.h"
#include "remote_log.h"
#include "linked_list.h"

#include "kmgmt.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

unsigned int kens_log_flag = 0;

static FILE *log = NULL;
static char *log_flags = NULL;

static int log_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values);

/*
 * dump binary chunk in hexadecimal form
 */
void LOG_dump_data(unsigned char *buf,int len)
{
	FILE *fp = stdout;
	int i,j;

	for ( i = 0; i < len; ) {
		fprintf(fp,"  ");

		for ( j = i; j < i+8; j++ ) {
			if ( j < len ) {
				if ( isprint(buf[j]) ) fprintf(fp," %c ",buf[j]);
				else fprintf(fp,"%02x ",(unsigned char)buf[j]);
			}
		}

		i += 8;

		for ( j = i; j < i+8; j++ ) {
			if ( j < len ) {
				if ( isprint(buf[j]) ) fprintf(fp,"  %c",buf[j]);
				else fprintf(fp," %02x",(unsigned char)buf[j]);
			}
		}

		fprintf(fp,"\n");
		i += 8;
	}
}

/*
 * logging facilities
 */

void LOG_init(dictionary *conf,char *fn,char *opts)
{
	token_list *tks = NULL;
	char *s;
	int i;

	/* register for kmgmt */
	kmgmt_register (KMOD_LOG, KXML_MOD_LOG, log_kmgmt_handler);

	if ( fn == NULL
			&& ( conf == NULL
				|| (fn = iniparser_getstring(conf,"KENS:logfile",NULL)) == NULL
			)
			&& (fn = getenv(ENV_KENS_LOG_FILE)) == NULL )
		fn = "kens.log";

	if ( opts == NULL
			&& ( conf == NULL
				|| (opts = iniparser_getstring(conf,"KENS:log_level",NULL)) == NULL
			)
			&& (opts = getenv(ENV_KENS_LOG_FLAG)) == NULL )
		return;

	log_flags = strdup(opts);

	/* let's parse options */
	tks = tokenize(opts,",|:",true);
	if ( tks == NULL || token_list_num(tks) == 0 ) {
		if ( tks != NULL ) token_list_free(tks);
		return;
	}

	i = 0;
	while ( i < token_list_num(tks) ) {
		s = token_list_get(tks,i);
		if ( !strcmp(s,"tcp") ) {
			kens_log_flag |= LOG_TCP;
		} else if ( !strcmp(s,"tcp_layer") ) {
			kens_log_flag |= LOG_TCP_ALL;
		} else if ( !strcmp(s,"ip") ) {
			kens_log_flag |= LOG_IP;
		} else if ( !strcmp(s,"ip_layer") ) {
			kens_log_flag |= LOG_IP_ALL;
		} else if ( !strcmp(s,"icmp") ) {
			kens_log_flag |= LOG_ICMP;
		} else if ( !strcmp(s,"link") || !strcmp(s,"datalink") ) {
			kens_log_flag |= LOG_LINK;
		} else if ( !strcmp(s,"link_layer") ) {
			kens_log_flag |= LOG_LINK_ALL;
		} else if ( !strcmp(s,"kernel") ) {
			kens_log_flag |= LOG_KERNEL;
		} else if ( !strcmp(s,"socket") || !strcmp(s,"sock") ) {
			kens_log_flag |= LOG_SOCK_ALL;
		} else if ( !strcmp(s,"library") || !strcmp(s,"lib") ) {
			kens_log_flag |= (LOG_SOCK_FUNC|LOG_SOCK_CTRL);
		} else if ( !strcmp(s,"kens") || !strcmp(s,"kernel") ) {
			kens_log_flag |= LOG_SOCK_KRNL;
		} else if ( !strcmp(s,"mactable") || !strcmp(s,"mac") ) {
			kens_log_flag |= LOG_LINK_MAC;
		} else if ( !strcmp(s,"route") ) {
			kens_log_flag |= LOG_IP_ROUTE;
		} else if ( !strcmp(s,"all") ) {
			kens_log_flag = 0xffffffff;
		}
		i++;
	}

	token_list_free(tks);

	log = fopen(fn,"a+");
	assert( log );

#ifdef HAVE_REMOTE_LOG
	rlog_init (conf);
#endif /* HAVE_REMOTE_LOG */
}

/*
 * dump KIP header
 */
/*
void LOG_dump_ip(struct ip *ip)
{
	char src[20],dst[20];

	sprintf(src,"%s",inet_ntoa(ip->ip_src));
	sprintf(dst,"%s",inet_ntoa(ip->ip_dst));

	LOG_print(LOG_IP_DUMP,"from %s to %s\nver=%d hdr_len=%d tos=0x%02x len=0x%04x id=0x%04x off=0x%04x ttl=%-3d p=%-3d sum=0x%04x",src,dst,ip->ip_v,ip->ip_hl,ip->ip_tos,ntohs(ip->ip_len),ntohs(ip->ip_id),ntohs(ip->ip_off),ip->ip_ttl,ip->ip_p,ntohs(ip->ip_sum));
}*/

void LOG_print(const char *hdr,char *fmt,...)
{
	va_list args;
	time_t t;
	struct tm *ts = NULL;
	char hugebuf[1024*2];

	va_start(args,fmt);

	vsprintf(hugebuf,fmt,args);
	hugebuf[1024*2-1] = '\0';

	va_end(args);

	if (log != NULL)
	{
		time(&t);
		ts = localtime(&t);

		fprintf(log,"%04d-%02d-%02d %02d:%02d:%02d [%d] %s %s\n",
				ts->tm_year+1900,
				ts->tm_mon+1,
				ts->tm_mday,
				ts->tm_hour,
				ts->tm_min,
				ts->tm_sec,
				getpid(),
				( hdr == NULL ) ? "" : hdr,
				hugebuf);
		fflush(log);
	}

	/* if any remote server is designated */
#ifdef HAVE_REMOTE_LOG
	rlog_send (hdr, hugebuf);
#endif /* HAVE_REMOTE_LOG */
}

void LOG_trace(const char *hdr,const char *fn,int line,char *fmt,...)
{
	va_list args;
	time_t t;
	struct tm *ts = NULL;
	char hugebuf[1024*2];

	va_start(args,fmt);

	vsprintf(hugebuf,fmt,args);
	hugebuf[1024*2-1] = '\0';

	va_end(args);

	if ( log != NULL )
	{
		time(&t);
		ts = localtime(&t);

		fprintf(log,"%04d-%02d-%02d %02d:%02d:%02d [%d] %s %s(%d) %s\n",
				ts->tm_year+1900,
				ts->tm_mon+1,
				ts->tm_mday,
				ts->tm_hour,
				ts->tm_min,
				ts->tm_sec,
				getpid(),
				( hdr == NULL ) ? "" : hdr,
				( fn == NULL ) ? "" : fn,
				line,
				hugebuf);
		fflush(log);
	}

#ifdef HAVE_REMOTE_LOG
	rlog_send (hdr, hugebuf);
#endif /* HAVE_REMOTE_LOG */
}

char *LOG_get_flags(void) {
	return log_flags;
}

void LOG_shutdown(void)
{
	if ( log != NULL ) {
		fclose(log);
		log = NULL;
	}

#ifdef HAVE_REMOTE_LOG
	rlog_shutdown ();
#endif /* HAVE_REMOTE_LOG */

	if ( log_flags != NULL ) 
		free(log_flags);

	log_flags = NULL;
}

#define DEBUG	0

#ifdef DEBUG
#define DBG(x...) do { \
	fprintf (stderr, x); \
} while (0)
#else
#define DBG(x...)
#endif

/**
 * When KensG requests for logging data, log_kmgmt_handler() is called.
 * "remote" table maintains only one row.
 *    * server (RW) remote logging server
 * "facilities" table maintains only one row.
 *    * tcp (RW)
 *    * tcp_layer (RW)
 *    * ip (RW)
 *    * ip_layer (RW)
 *    * icmp (RW)
 *    * link (RW)
 *    * link_layer (RW)
 *    * kernel (RW)
 *    * socket (RW)
 *    * library (RW)
 *    * kens (RW)
 *    * mactable (RW)
 *    * route (RW)
 *
 * @param	modid module id
 *			cmd either get/set
 *			table table name, either "remote" or "facilities"
 *			index index for the table.
 *			rindex for "get"
 *			nparam # of requested parameters
 *			nvalue # of returned parameters for "get"
 *			params list of requested parameters
 *			values list of returned parameters
 * @return  error code
 */
static int log_kmgmt_handler (int modid, int cmd, char *table, char *index, 
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

	if (cmd < 0 || cmd >= KMGMT_MAX)
	{
		return FAILED;
	}

	if (table != NULL && strcmp(table, "common") == 0)
	{
	}
	else if (table != NULL && strcmp(table, "remote") == 0)
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

			if (!strcmp(inattr->param, "server"))
			{
				if (cmd == KMGMT_GET)
				{
					char *name = get_remote_server_name ();
					sprintf (buffer, "%s", 
							name?name:"undefined");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					rlog_set_server (inattr->value);
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
	else if (table != NULL && strcmp(table, "facilities") == 0)
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

			if (!strcmp(inattr->param, "tcp"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_TCP)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_TCP;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_TCP);
					}
				}
			}
			else if (!strcmp(inattr->param, "tcp_layer"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_TCP_ALL)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_TCP_ALL;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_TCP_ALL);
					}
				}
			}
			else if (!strcmp(inattr->param, "ip"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_IP)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_IP;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_IP);
					}
				}
			}
			else if (!strcmp(inattr->param, "ip_layer"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_IP_ALL)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_IP_ALL;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_IP_ALL);
					}
				}
			}
			else if (!strcmp(inattr->param, "icmp"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_ICMP)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_ICMP;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_ICMP);
					}
				}
			}
			else if (!strcmp(inattr->param, "link"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_LINK)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_LINK;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_LINK);
					}
				}
			}
			else if (!strcmp(inattr->param, "link_layer"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_LINK_ALL)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_LINK_ALL;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_LINK_ALL);
					}
				}
			}
			else if (!strcmp(inattr->param, "kernel"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_KERNEL)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_KERNEL;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_KERNEL);
					}
				}
			}
			else if (!strcmp(inattr->param, "socket"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_SOCK_ALL)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_SOCK_ALL;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_SOCK_ALL);
					}
				}
			}
			else if (!strcmp(inattr->param, "library"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&(LOG_SOCK_FUNC|LOG_SOCK_CTRL))?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= (LOG_SOCK_FUNC|LOG_SOCK_CTRL);
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~(LOG_SOCK_FUNC|LOG_SOCK_CTRL));
					}
				}
			}
			else if (!strcmp(inattr->param, "kens"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_SOCK_KRNL)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_SOCK_KRNL;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_SOCK_KRNL);
					}
				}
			}
			else if (!strcmp(inattr->param, "mactable"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_LINK_MAC)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_LINK_MAC;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_LINK_MAC);
					}
				}
			}
			else if (!strcmp(inattr->param, "route"))
			{
				if (cmd == KMGMT_GET)
				{
					sprintf (buffer, "%s", (kens_log_flag&LOG_IP_ROUTE)?"true":"false");
					value = strdup (buffer);
				}
				else if (cmd == KMGMT_SET && inattr->value != NULL)
				{
					if (strcmp(inattr->value,"true") == 0)
					{
						kens_log_flag |= LOG_IP_ROUTE;
					}
					else if (strcmp(inattr->value,"false") == 0)
					{
						kens_log_flag &= (~LOG_IP_ROUTE);
					}
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

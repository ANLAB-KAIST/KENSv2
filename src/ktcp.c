#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>

#include "kernel.h"
#include "kip.h"
#include "route.h"
#include "ktcp.h"
#include "linked_list.h"

#include "misc.h"
#include "log.h"

#include "kmgmt.h"
#include "kxml.h"

#include "ktcp_easy_impl.h"
#include "ktcp_easy_lib.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

#define TCP_RELI
#define TCP_RETR
#define TCP_AIMD

#if defined(_WIN32)
	typedef unsigned int tcp_seq;
	typedef unsigned short u_int16_t;
	typedef unsigned char u_int8_t;
	struct tcphdr
	{
		u_int16_t th_sport;		/* source port */
		u_int16_t th_dport;		/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_int8_t th_x2:4;		/* (unused) */
		u_int8_t th_off:4;		/* data offset */
		u_int8_t th_flags;
	#  define TH_FIN	0x01
	#  define TH_SYN	0x02
	#  define TH_RST	0x04
	#  define TH_PUSH	0x08
	#  define TH_ACK	0x10
	#  define TH_URG	0x20
		u_int16_t th_win;		/* window */
		u_int16_t th_sum;		/* checksum */
		u_int16_t th_urp;		/* urgent pointer */
	};
	int gettimeofday(struct timeval *tv, struct timezone *tz) {
		return 0;
	}
	#define write(s,b,l) send(s,b,l,0)
	#define read(s,b,l) recv(s,b,l,0)
#else
	#include <netinet/tcp.h>
#endif


/**************************************************************************/
/*                     Definition of Local Types                          */
/**************************************************************************/

#define SHS (sizeof(struct tcphdr)) /* TCP header size. */
#define MPS (536 - 20) /* Maximum payload size. */
#define MSS (SHS + MPS) /* Maximum segment size. */
#define MSL (120) /* Maximum segment lifetime (RFC793 specifies as 2 minutes). */
#define DEFAULT_NEXT_PORT (3000)
#define DEFAULT_WINDOW_SIZE (3072) /* Default window size. */
#define MAX_TRIAL (10) /* Maximum transmission trials. */


struct kens_easy_mapping_t;

typedef struct tcp_context_t {

	bool is_bound;					/* is this socket in conn_ctx_list */

#define PIPE_NO_RD		0x40000000	/* data pipe can not be read */
#define PIPE_NO_WR		0x80000000	/* data pipe can not be written */
#define PIPE_NO_RDWR	(PIPE_NO_RD|PIPE_NO_WR)
#define PIPE_CLOSED		PIPE_NO_RDWR	/* data pipe has been closed */
#define PIPE_FD(x)		(int)((x) & (~PIPE_CLOSED))	/* extract file descriptor
										from pipe variable */
	int pipe;					/* data pipe passed from kernel simulator */

	route ro;					/* routing table cache.
								   just pass it to IP layer */
	
	/* belows are ONLY used in server or passive socket */
	struct tcp_context_t *bind_ctx; /* server socket which listens TCP connection */
	list accept_pending_ctx_list;

	my_context easy_context;
	struct kens_easy_mapping_t* mapping;

} tcp_context;

typedef struct kens_easy_mapping_t
{
	tcp_context* kens;
	my_context easy;
}*kens_easy_mapping;
typedef struct kens_easy_timer_t
{
	int mtime;
	my_context easy;
}kens_easy_timer;


struct ktcp_t ktcp;

/**************************************************************************/
/*                   Declaration of Local Functions                       */
/**************************************************************************/

void tcp_dispatch_timer();
bool tcp_dispatch_out();
static list_position tcp_find_timer(my_context ctx);
int tcp_get_mtime();

#define MIN(x,y)  ((x) <= (y) ? (x) : (y))
#define MAX(x,y)  ((x) >= (y) ? (x) : (y))

tcp_context* tcp_get_kens_from_easy(my_context easy)
{
	list_position iter = list_get_head_position(ktcp.easy_context_list);
	while(iter)
	{
		kens_easy_mapping map = (kens_easy_mapping)list_get_at(iter);
		if(map->easy == easy)
			return map->kens;
		iter = list_get_next_position(iter);
	}
	return NULL;
}

void tcp_shutdown(void)
{
	ktcp.my_tcp->shutdown(ktcp.my_tcp);

	list_close(ktcp.allocated_ctx_list);
	list_close(ktcp.conn_ctx_list);
	list_close(ktcp.async_pending_ctx_list);
	list_close(ktcp.easy_context_list);
	list_close(ktcp.timer_list);

	return;
}

tcp_socket tcp_open(int *err)
{
	tcp_context *ctx;
	*err = 0;

	ctx = (tcp_context *)malloc(sizeof(tcp_context));
	if ( ctx == NULL ) {
		*err = ENOMEM;
		return NULL;
	}

	my_context easy_context = ktcp.my_tcp->open(ktcp.my_tcp, err);
	if(easy_context == 0)
	{
		free(ctx);
		return NULL;
	}

	memset(ctx, 0, sizeof(tcp_context));
	ctx->pipe = -1;
	ctx->accept_pending_ctx_list = list_open();

	list_add_tail(ktcp.allocated_ctx_list, ctx);

	ctx->easy_context = easy_context;
	kens_easy_mapping map = (kens_easy_mapping)malloc(sizeof(struct kens_easy_mapping_t));
	map->easy = easy_context;
	map->kens = ctx;
	ctx->mapping = map;
	list_add_head(ktcp.easy_context_list, map);
	T_TCP_CB("(%08x) ksocket allocated",ctx);

	return ctx;
}

tcp_socket tcp_open_passive(int *err)
{
	tcp_context *ctx;
	*err = 0;

	ctx = (tcp_context *)malloc(sizeof(tcp_context));
	if ( ctx == NULL ) {
		*err = ENOMEM;
		return NULL;
	}

	memset(ctx, 0, sizeof(tcp_context));
	ctx->pipe = -1;

	list_add_tail(ktcp.allocated_ctx_list, ctx);

	T_TCP_CB("(%08x) ksocket allocated",ctx);

	return ctx;
}

int tcp_context_free(void *handle)
{
	tcp_context *ctx = (tcp_context *)handle;

	if(ctx->mapping)
		list_remove(ktcp.easy_context_list, ctx->mapping);
	free(ctx->mapping);
	if(ctx->is_bound)
		list_remove(ktcp.conn_ctx_list, ctx);

	ctx->easy_context = 0;

	tcp_context* subctx;
	if(ctx->accept_pending_ctx_list)
	{
		while((subctx = list_remove_head(ctx->accept_pending_ctx_list)))
			tcp_context_free(subctx);
		list_close(ctx->accept_pending_ctx_list);
	}

	if ( ctx->ro.ro_rt != NULL
			&& (ctx->ro.ro_rt->rt_flags & RTF_SHOULD_FREED) ) {
		free(ctx->ro.ro_rt);
		ctx->ro.ro_rt = NULL;
	}
	list_remove(ktcp.allocated_ctx_list, ctx);
	free(ctx);


	return 0;
}

bool tcp_close(tcp_socket handle,int *err)
{
	tcp_context *ctx;

	/* Validate parameters. */
	if (handle == NULL) {
		*err = EBADF;
		return false;
	}

	ctx = (tcp_context *)handle;
	ctx->pipe |= PIPE_CLOSED;

	ker_message(ASYNCH_CLOSE,0,NULL,ctx);

	*err = 0;
	ktcp.my_tcp->close(ktcp.my_tcp, ctx->easy_context, err);
	tcp_context_free(ctx);

	return true;
}

bool tcp_bind(tcp_socket handle, const struct sockaddr *my_addr, socklen_t addrlen, int *err)
{
	tcp_context *ctx;

	ctx = (tcp_context *)handle;

	return ktcp.my_tcp->bind(ktcp.my_tcp, ctx->easy_context, my_addr, addrlen, err);
}

bool tcp_listen(tcp_socket handle, int backlog, int *err)
{
	tcp_context *ctx;

	ctx = (tcp_context *)handle;
	return ktcp.my_tcp->listen(ktcp.my_tcp, ctx->easy_context, backlog, err);
}

bool tcp_accept(tcp_socket bind_handle,tcp_socket conn_handle, int pipe, int *err)
{
	tcp_context *bind_ctx;

	/* Validate parameters. */
	if ((bind_handle == NULL) || (conn_handle == NULL) || (pipe == -1)) {
		*err = EBADF;
		return false;
	}

	bind_ctx = (tcp_context *)bind_handle;
	if(ktcp.my_tcp->accept(ktcp.my_tcp, bind_ctx->easy_context, err) == false)
		return false;

	((tcp_context *)conn_handle)->pipe = pipe;
	((tcp_context *)conn_handle)->bind_ctx = bind_ctx;
	list_add_tail(bind_ctx->accept_pending_ctx_list, conn_handle);
	return true;
}

bool tcp_connect(tcp_socket handle, const struct sockaddr *serv_addr, socklen_t addrlen, int pipe, int *err)
{
	tcp_context *ctx;
	struct sockaddr_in my_addr;

	/* Validate parameters. */
	if ((handle == NULL) || (serv_addr == NULL)
			|| (serv_addr->sa_family != AF_INET)
			|| (addrlen < 8) || (addrlen > 16)
			|| (pipe == -1)) {
		if ( handle == NULL ) *err = EBADF;
		else if ( serv_addr == NULL ) *err = EFAULT;
		else if ( serv_addr->sa_family != AF_INET ) *err = EAFNOSUPPORT;
		else *err = EBADF;
		T_TCP("tcp_connect : invalid argument handle = %08x addrlen = %u af = %u addr = %s pipe = %u",handle,addrlen,serv_addr->sa_family,inet_ntoa(((struct sockaddr_in *)serv_addr)->sin_addr),pipe);
		return false;
	}

	ctx = (tcp_context *)handle;
	*err = 0;
	if (ktcp.my_tcp->connect(ktcp.my_tcp, ctx->easy_context, serv_addr, addrlen, err) == false) {
		return false;
	}
	ctx->pipe = pipe;

	return true;
}

bool tcp_getsockname(tcp_socket handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
	if ((handle == NULL) || (name == NULL) || (*namelen < 8)) {
		*err = EBADF;
		return false;
	}
	*err = 0;
	return ktcp.my_tcp->getsockname(ktcp.my_tcp, ((tcp_context*)handle)->easy_context, name, namelen, err);
}

bool tcp_getpeername(tcp_socket handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
	if ((handle == NULL) || (name == NULL) || (*namelen < 8)) {
		*err = EBADF;
		T_TCP_CB("tcp_getpeername  handle = %08x namelen = %d",handle,*namelen);
		return false;
	}
	*err = 0;
	return ktcp.my_tcp->getpeername(ktcp.my_tcp, ((tcp_context*)handle)->easy_context, name, namelen, err);
}

bool tcp_dispatch(void)
{
	/* nothing to schedule. small optimization for router */
	if ( list_get_count(ktcp.allocated_ctx_list) != 0)
		tcp_dispatch_out();
	if(list_get_count(ktcp.timer_list) != 0)
		tcp_dispatch_timer();

	return true;
}

bool tcp_dispatch_in(struct in_addr src_addr, struct in_addr dest_addr, const void *buf, size_t count)
{
	ktcp.my_tcp->ip_dispatch_tcp(ktcp.my_tcp, src_addr, dest_addr, buf, count);

	return true;
}

bool tcp_register_timer(my_context context, int mtime)
{
	list_position timer_ptr = tcp_find_timer(context);
	kens_easy_timer* timer = 0;
	if(timer_ptr)
	{
		timer = (kens_easy_timer*)list_get_at(timer_ptr);
		timer->mtime = mtime;
		return true;
	}

	timer = malloc(sizeof(kens_easy_timer));

	timer->easy = context;
	timer->mtime = mtime;
	list_add_tail(ktcp.timer_list, timer);
	return true;
}

void tcp_unregister_timer(my_context context)
{
	list_position timer = tcp_find_timer(context);
	if(timer)
	{
		free(list_remove_at(timer));
	}
}

void tcp_dispatch_timer()
{
	list_position iter = list_get_head_position(ktcp.timer_list);
	int current = tcp_get_mtime();

	while(iter)
	{
		kens_easy_timer* ctx = (kens_easy_timer*)list_get_at(iter);
		list_position next = list_get_next_position(iter);
		if(ctx->mtime <= current)
		{
			my_context* easy = ctx->easy;
			free(list_remove_at(iter));
			ktcp.my_tcp->timer(ktcp.my_tcp, easy, current);
		}

		iter = next;
	}
}

bool tcp_dispatch_out()
{
	fd_set fds;
	struct timeval timeout;
	int max_fd, err;
	tcp_context *ctx;
	list_position pos;
	char buf[MPS];
	int data_length;

	if (list_get_count(ktcp.conn_ctx_list) == 0)
		return true;

	max_fd = -1;
	FD_ZERO(&fds);
	pos = list_get_head_position(ktcp.conn_ctx_list);
	while (pos != NULL) {
		ctx = list_get_next(&pos);
		if ( (ctx->pipe & PIPE_NO_RD) != 0 ) continue;
		max_fd = MAX(max_fd, PIPE_FD(ctx->pipe));
		FD_SET(PIPE_FD(ctx->pipe), &fds);
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000; /* Set 1 msec. */

	switch (select(max_fd + 1, &fds, NULL, NULL, &timeout)) {
	case -1:
		T_TCP("(%08x) pipe to application has been closed %s",
				ctx,
				( data_length == 0 ) ? "" : strerror(errno)
		);
		return false;
	case 0:
		break;
	default:
		pos = list_get_head_position(ktcp.conn_ctx_list);
		while (pos != NULL) {
			ctx = list_get_next(&pos);
			if ( (ctx->pipe & PIPE_NO_RD) == 0
					&& FD_ISSET(PIPE_FD(ctx->pipe), &fds)) {
				data_length = read(PIPE_FD(ctx->pipe), buf, MPS);

				T_TCP("(%08x) %d bytes data from application",ctx,data_length);

				if ( data_length <= 0 ) {
					/* connection upruptly closed by application */
					/* call tcp_close and let kernel knows the socket has
					 * been closed
					 */
					T_TCP("(%08x) pipe to application has been closed %s",
							ctx,
							( data_length == 0 ) ? "" : strerror(errno)
					);
					tcp_close(ctx,&err);
				} else {
					T_TCP("(%08x) %d bytes from application",ctx,data_length);
					if(!ctx->easy_context)
						T_TCP("No matching my_context");
					while(data_length > 0)
					{
						void* data = buf;
						int len = ktcp.my_tcp->app_dispatch_tcp(ktcp.my_tcp, ctx->easy_context, data, data_length);
						if(data_length < len)
							break;
						data += len;
						data_length -= len;
					}
				}
			}
		}
		break;
	}
	return true;
}

int tcp_get_mtime()
{
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

/**
 * @breif
 * This function passes data to IP layer.
 *
 * @author leeopop
 * @param src_addr source IP address (in network ordering)
 * @param dest_addr destination IP address (in network ordering)
 * @param data IP payload
 * @param data_size size of data
 * @return actual written bytes (-1 means error)
 */
int tcp_dispatch_ip(struct in_addr src_addr, struct in_addr dest_addr, void * data, size_t data_size)
{
	return ip_output(src_addr, dest_addr, data, data_size, NULL);
}


/**
 * @breif
 * This function passes data to application
 *
 * @author leeopop
 * @param handle abstraction of application socket
 * @param data data to be passed
 * @param data_size size of data
 * @return actual written bytes (-1 means closed socket)
 */
int tcp_dispatch_app(my_context handle, const void* data, size_t data_size)
{
	tcp_context* ctx = tcp_get_kens_from_easy(handle);
	if(ctx == NULL)
		return -1;
	if ( !(ctx->pipe & PIPE_NO_WR) )
		return write(PIPE_FD(ctx->pipe), data, data_size);
	else
		return -1;
}

/**
 * @breif
 * This function wakes up 'kaccept' and 'kaccept' will return @param new_handle.
 *
 * @author leeopop
 * @param server_handle TCP context to be waken up
 * @param new_handle passively opened socket used as the return value of 'kaccept'
 * @return whether operation is successful (for example, if server_handle is not blocked)
 */
bool tcp_passive_open(my_context server_handle, my_context new_handle)
{
	T_TCP_PENDING("it's server");
	tcp_context* bind_ctx = tcp_get_kens_from_easy(server_handle);
	if(!bind_ctx)
	{
		T_TCP_PENDING("No linked KENS context with my_context (%08x)", server_handle);
		return false;
	}

	if (list_get_count(bind_ctx->accept_pending_ctx_list) == 0) {
		T_TCP_PENDING("(%08x) has no accept pending context",bind_ctx);
		return false;
	}

	tcp_context* accept_pending_ctx = list_remove_head(bind_ctx->accept_pending_ctx_list);
	accept_pending_ctx->is_bound = true;
	accept_pending_ctx->easy_context = new_handle;
	kens_easy_mapping map = malloc(sizeof(struct kens_easy_mapping_t));
	map->easy = new_handle;
	map->kens = accept_pending_ctx;
	accept_pending_ctx->mapping = map;
	list_add_head(ktcp.easy_context_list, map);

	T_TCP_PENDING("(%08x) accept pending context = %08x",bind_ctx, accept_pending_ctx);

	T_TCP_PENDING("(%08x) has been accepted to binding ctx (%08x)",accept_pending_ctx,bind_ctx);

	list_add_tail(ktcp.conn_ctx_list, accept_pending_ctx);
	accept_pending_ctx->is_bound = true;
	ker_message(ASYNCH_RETURN_ACCEPT, 0, bind_ctx, accept_pending_ctx);

	return true;
}

/**
 * @breif
 * This function wakes up 'kconnect'
 *
 * @author leeopop
 * @param handle TCP context to be waken up
 * @return whether operation is successful (for example, if handle is not blocked)
 */
bool tcp_active_open(my_context handle)
{
	tcp_context* conn_ctx = tcp_get_kens_from_easy(handle);
	if(!conn_ctx)
	{
		T_TCP_PENDING("No linked KENS context with my_context (%08x)", handle);
		return false;
	}

	T_TCP_PENDING("(%08x) has been connected",conn_ctx);
	list_add_tail(ktcp.conn_ctx_list, conn_ctx);
	conn_ctx->is_bound = true;
	ker_message(ASYNCH_RETURN_CONNECT, 0, conn_ctx, NULL);

	return true;
}

void tcp_shutdown_app(my_context handle)
{
	tcp_context *ctx = tcp_get_kens_from_easy(handle);
	if(!ctx)
		return;

	ctx->pipe |= PIPE_NO_WR;
	ker_message(ASYNCH_EOF,0,NULL,ctx);
}

static list_position tcp_find_timer(my_context ctx)
{
	list_position iter = list_get_head_position(ktcp.timer_list);
	while(iter)
	{
		kens_easy_timer* timer = (kens_easy_timer*)list_get_at(iter);
		if(timer->easy == ctx)
			return iter;
		iter = list_get_next_position(iter);
	}
	return NULL;
}

static ktcp_easy_lib my_lib;
extern ktcp_easy_impl* my_startup(ktcp_easy_lib* lib);
bool tcp_startup(void)
{
	ktcp.allocated_ctx_list = list_open();
	ktcp.conn_ctx_list = list_open();
	ktcp.async_pending_ctx_list = list_open();
	ktcp.easy_context_list = list_open();
	ktcp.timer_list = list_open();

	my_lib.ip_host_address = ip_host_address;
	my_lib.tcp_active_open = tcp_active_open;
	my_lib.tcp_dispatch_app = tcp_dispatch_app;
	my_lib.tcp_dispatch_ip = tcp_dispatch_ip;
	my_lib.tcp_get_mtime = tcp_get_mtime;
	my_lib.tcp_passive_open = tcp_passive_open;
	my_lib.tcp_register_timer = tcp_register_timer;
	my_lib.tcp_shutdown_app = tcp_shutdown_app;
	my_lib.tcp_unregister_timer = tcp_unregister_timer;

	ktcp_easy_impl* impl = my_startup(&my_lib);

	ktcp.my_tcp = impl;
	return impl != NULL;
}

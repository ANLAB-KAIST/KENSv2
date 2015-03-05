
#ifndef __KENS_KTCP_H__
#define __KENS_KTCP_H__

#if defined(_WIN32)
	#include <winsock2.h>
	typedef int socklen_t;
#else
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <netinet/tcp.h>
	#include <netinet/in.h>
#endif

#if !defined(__bool_defined) && !defined(__cplusplus) && !defined(c_plusplus)
	#define __bool_defined
	typedef char bool;
	#define false	(0)
	#define true	(1)
#endif

#include "linked_list.h"
#include "ktcp_easy_impl.h"

typedef void * tcp_socket;

struct ktcp_t {
	list allocated_ctx_list;
	list async_pending_ctx_list;		/* list of sockets which are about to return
						    system calls from kernel simulation.
						    Ex. connect(), accept() */
	list conn_ctx_list;

	list easy_context_list;
	list timer_list;
	ktcp_easy_impl* my_tcp;
};

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

extern bool tcp_startup();
extern void tcp_shutdown();

extern tcp_socket tcp_open(int *err);
extern bool tcp_close(tcp_socket handle,int *err);
extern bool tcp_bind(tcp_socket handle, const struct sockaddr *my_addr, socklen_t addrlen,int *err);
extern bool tcp_listen(tcp_socket handle, int backlog, int *err);
extern bool tcp_accept(tcp_socket bind_handle, tcp_socket conn_handle, int pipe, int *err);
extern bool tcp_connect(tcp_socket handle, const struct sockaddr *serv_addr, socklen_t addrlen, int pipe, int *err);
extern bool tcp_getsockname(tcp_socket handle, struct sockaddr *name, socklen_t *namelen, int *err);
extern bool tcp_getpeername(tcp_socket handle, struct sockaddr *name, socklen_t *namelen, int *err);

extern bool tcp_dispatch();
extern bool tcp_dispatch_in(struct in_addr src_addr, struct in_addr dest_addr, const void *buf, size_t count);
extern void tcp_dispatch_pending();

extern void tcp_debug();

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif


#endif /* __KENS_KTCP_H__ */

/**
 * @file        ktcp_easy_impl.c
 * @author      leeopop
 * @date        Aug 2013
 * @version     $Revision: 1.00 $
 * @brief       Template for easy-KTCP project
 *
 * This is the main project template for transport layer implementation.
 * All functions below are linked with KENS kernel, so do not change the name or type of function.
 */

#include "ktcp_easy_impl.h"
#include "ktcp_easy_lib.h"

//suggesting header
#include <stdlib.h>

typedef struct
{
	ktcp_easy_impl my_syscall;

	//add global variables here
	ktcp_easy_lib* ktcp_lib;
}global_context_t;

ktcp_easy_impl* my_startup(ktcp_easy_lib* lib);

static void my_shutdown(global_context_t* tcp_context); //finalize tcp context manager

static my_context my_open(global_context_t* tcp_context, int *err); //called when kopen is called
static void my_close(global_context_t* tcp_context, my_context handle,int *err); //handle: memory allocated from my_open
static bool my_bind(global_context_t* tcp_context, my_context handle, const struct sockaddr *my_addr, socklen_t addrlen,int *err);
static bool my_listen(global_context_t* tcp_context, my_context handle, int backlog, int *err);
static bool my_connect(global_context_t* tcp_context, my_context handle, const struct sockaddr *serv_addr, socklen_t addrlen, int *err);
static bool my_accept(global_context_t* tcp_context, my_context handle, int *err);
static bool my_getsockname(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err);
static bool my_getpeername(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err);
static void my_timer(global_context_t* tcp_context, my_context handle, int actual_called);
static void my_ip_dispatch_tcp(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size);
static int my_app_dispatch_tcp(global_context_t* tcp_context, my_context handle, const void* data, size_t data_size);




/**
 * @todo
 *
 * @breif
 * This function is called when KENS TCP layer is starting.
 *
 * @param ktcp_easy_lib library functions to use
 * @return prepared ktcp_easy_impl context for further use
 */
ktcp_easy_impl* my_startup(ktcp_easy_lib* lib)
{
	global_context_t* my_tcp = malloc(sizeof(global_context_t));

	my_tcp->my_syscall.shutdown = (void (*)(ktcp_easy_impl*))my_shutdown;
	my_tcp->my_syscall.open = (my_context (*)(ktcp_easy_impl*, int *))my_open;
	my_tcp->my_syscall.close = (void (*)(ktcp_easy_impl*, my_context,int *))my_close;
	my_tcp->my_syscall.bind = (bool (*)(ktcp_easy_impl*, my_context, const struct sockaddr *, socklen_t,int *))my_bind;
	my_tcp->my_syscall.listen = (bool (*)(ktcp_easy_impl*, my_context, int, int *))my_listen;
	my_tcp->my_syscall.connect = (bool (*)(ktcp_easy_impl*, my_context, const struct sockaddr *, socklen_t, int *))my_connect;
	my_tcp->my_syscall.accept = (bool (*)(ktcp_easy_impl*, my_context, int *))my_accept;
	my_tcp->my_syscall.getsockname = (bool (*)(ktcp_easy_impl*, my_context, struct sockaddr *, socklen_t *, int *))my_getsockname;
	my_tcp->my_syscall.getpeername = (bool (*)(ktcp_easy_impl*, my_context, struct sockaddr *, socklen_t *, int *))my_getpeername;
	my_tcp->my_syscall.timer = (void (*)(ktcp_easy_impl*, my_context, int))my_timer;
	my_tcp->my_syscall.ip_dispatch_tcp = (void (*)(ktcp_easy_impl*, struct in_addr, struct in_addr, const void *, size_t))my_ip_dispatch_tcp;
	my_tcp->my_syscall.app_dispatch_tcp = (int (*)(ktcp_easy_impl*, my_context, const void*, size_t))my_app_dispatch_tcp;

	my_tcp->ktcp_lib = lib;

	//add your initialization codes here

	return (ktcp_easy_impl*)my_tcp;
}

/**
 * @todo
 *
 * @breif
 * This function is called when KENS TCP layer is exiting.
 *
 * @param tcp_context global context generated in my_startup. This includes KENS libraries and global variables.
 */
static void my_shutdown(global_context_t* tcp_context)
{
	free(tcp_context);
}


/**
 * @todo
 *
 * @breif
 * Mapped with 'ksocket'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param err ERRNO value
 * @return TCP context data to be used (used to identify each application sockets)
 */
static my_context my_open(global_context_t* tcp_context, int *err)
{
	return 0;
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'kclose'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param err ERRNO value
 */
static void my_close(global_context_t* tcp_context, my_context handle,int *err)
{
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'kbind'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param my_addr address of this socket
 * @param addrlen length of my_addr structure
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_bind(global_context_t* tcp_context, my_context handle, const struct sockaddr *my_addr, socklen_t addrlen,int *err)
{
	return false;
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'klisten'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param backlog maximum number of concurrently opening connections
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_listen(global_context_t* tcp_context, my_context handle, int backlog, int *err)
{
	return false;
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'kconnect'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param serv_addr remote address connecting to
 * @param addrlen length of serv_addr structure
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_connect(global_context_t* tcp_context, my_context handle, const struct sockaddr *serv_addr, socklen_t addrlen, int *err)
{
	return false;
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'kaccept'.
 * 'kaccept' is immediately blocked (my_accept is not blocked).
 * Even if 'kaccept' is called after connection is established, it is blocked.
 * 'kaccept' can be waken up via tcp_context->ktcp_lib->tcp_passive_open.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open' (listening socket)
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_accept(global_context_t* tcp_context, my_context handle, int *err)
{
	return false;
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'kgetsockname'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param name address of socket address structure
 * Write my address here.
 *
 * @param namelen length of address structure
 * Write length of my address structure size here.
 * This value should be initialized with the actual size of 'name' structure.
 *
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_getsockname(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
	return false;
}

/**
 * @todo
 *
 * @breif
 * Mapped with 'kgetpeername'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param name address of socket address structure
 * Write peer address here.
 *
 * @param namelen length of address structure
 * Write length of my address structure size here.
 * This value should be initialized with the actual size of 'name' structure.
 *
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_getpeername(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
	return false;
}

/**
 * @todo
 *
 * @breif
 * Every time application calls 'write', this function is called.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context linked with application socket
 * @param dest_addr destination IP address (in network ordering)
 * @param data written data via 'write'
 * @param data_size size of data
 * @return actual written bytes (-1 means closed socket)
 */
static int my_app_dispatch_tcp(global_context_t* tcp_context, my_context handle, const void* data, size_t data_size)
{
	return -1;
}

/**
 * @todo
 *
 * @breif
 * When ip packet is received, this callback function is called.
 * Most IP headers are removed, and only data part is passed.
 * However, source IP address and destination IP address are passed for header computation.
 *
 * @param tcp_context global context generated in my_startup.
 * @param src_addr source IP address (in network ordering)
 * @param dest_addr destination IP address (in network ordering)
 * @param data IP payload
 * @param data_size size of data
 */
static void my_ip_dispatch_tcp(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size)
{
}

/**
 * @todo
 *
 * @breif
 * This function is called when timer activated.
 * Each timer is bound to each context.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context bound to this timer
 * @param actual_called actual time this timer called (in mtime)
 */
static void my_timer(global_context_t* tcp_context, my_context handle, int actual_called)
{
}


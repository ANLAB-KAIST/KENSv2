/*
 * ktcp_easy_impl.h
 *
 *  Created on: 2013. 7. 5.
 *      Author: leeopop
 */

#ifndef KTCP_EASY_IMPL_H_
#define KTCP_EASY_IMPL_H_


/*
 * Never change here (callback functions)
 */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#if !defined(__bool_defined) && !defined(__cplusplus) && !defined(c_plusplus)
	#define __bool_defined
	typedef char bool;
	#define false	(0)
	#define true	(1)
#endif

typedef void* my_context;

typedef struct ktcp_easy_impl_t ktcp_easy_impl;

struct ktcp_easy_impl_t
{
	//system call mapping
	void (*shutdown)(ktcp_easy_impl* tcp_context); //finalize tcp context manager
	
	my_context (*open)(ktcp_easy_impl* tcp_context, int *err); //called when kopen is called
	void (*close)(ktcp_easy_impl* tcp_context, my_context handle,int *err); //handle: memory allocated from my_open
	bool (*bind)(ktcp_easy_impl* tcp_context, my_context handle, const struct sockaddr *my_addr, socklen_t addrlen,int *err);
	bool (*listen)(ktcp_easy_impl* tcp_context, my_context handle, int backlog, int *err);
	bool (*connect)(ktcp_easy_impl* tcp_context, my_context handle, const struct sockaddr *serv_addr, socklen_t addrlen, int *err);
	bool (*accept)(ktcp_easy_impl* tcp_context, my_context handle, int *err);
	bool (*getsockname)(ktcp_easy_impl* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err);
	bool (*getpeername)(ktcp_easy_impl* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err);

	void (*timer)(ktcp_easy_impl* tcp_context, my_context handle, int actual_called);

	//automatically called by ip layer
	void (*ip_dispatch_tcp)(ktcp_easy_impl* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size);

	//application link
	int (*app_dispatch_tcp)(ktcp_easy_impl* tcp_context, my_context handle, const void* data, size_t data_size);
};

/*
 * Implementation suggestion (free to modify after here)
 */


#endif /* KTCP_EASY_IMPL_H_ */

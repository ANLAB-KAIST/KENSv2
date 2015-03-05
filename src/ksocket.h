#ifndef __KSOCKET_H_
#define __KSOCKET_H_

#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_APP_SOCK 20


extern int ksocket(int domain, int type, int protocol);
extern int kconnect(int sockfd,const struct sockaddr *serv_addr,socklen_t addrlen);
extern int kbind(int sockfd,struct sockaddr *my_addr, socklen_t addrlen);
extern int kaccept(int s, struct  sockaddr  *addr,  socklen_t *addrlen);
extern int klisten(int s, int backlog);
extern ssize_t kread(int fd, void *buf, size_t count);
extern ssize_t kwrite(int fd, const void *buf, size_t count);
extern int kclose(int fd);

extern int kgetsockname(int fd, struct sockaddr *localaddr, socklen_t *addrlen);
extern int kgetpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);
extern int kfcntl(int fd,int cmd,...);
extern size_t kreadline(int fd,void *vptr,size_t maxlen);
extern int kshutdown(int fd,int how);
extern int kselect(int n, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout);

extern int kgetkensopt(int optname, void *optval, socklen_t *optlen);
extern int ksetkensopt(int optname, const void *optval, socklen_t optlen);

#define KO_DL_DELAY					0
#define KO_DL_DROP_RATE				1
#define KO_DL_REORDER_RATE			2
#define KO_DL_ENABLE_SETH			3
#define KO_DL_DISABLE_SETH			4
#define KO_KRIP_UPDATE_INTERVAL		5
#define KO_KRIP_TIMEOUT				6


typedef struct _message {
	u_short type;	
	struct sockaddr saddr;
	int len;
	char result;
	int err;
	u_short port;	/* for identifing socket to be assiciated to pipe
					 when connect is called */
	u_short port2;	/* for identifing bind socket when accept is called	*/

	int optname;
	socklen_t optlen;
	char optval[4];
} message;

#endif

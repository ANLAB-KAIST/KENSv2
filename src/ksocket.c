#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "ksocket.h"
#include "ksockconst.h"
#include "log.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

typedef struct lib_sock {
	int udp_sock;
	int tcp_sock;	
	char used;
	int flag;
} lib_sock;

static int inited = 0;
/* 1 to MAX_APP_SOCK use range */
static lib_sock lib_socks[MAX_APP_SOCK+1];

static int sock_count;
static struct sockaddr_in to;
static struct sockaddr_in tcp_addr;


static int send_msg(message *m, int sockfd, int flag);

static void _init_kenslib(void)
{
	char *v;

	tcp_addr.sin_family = to.sin_family=AF_INET;
	tcp_addr.sin_addr.s_addr = to.sin_addr.s_addr = inet_addr("127.0.0.1");

	v = getenv("KENS_UDP_PORT");
	if ( v == NULL ) {
		fprintf(stderr,"FATAL ERROR : KENS_UDP_PORT environment variable is not defined\n");
		exit(1);
	}
	to.sin_port=htons(atoi(v));

	v = getenv("KENS_TCP_PORT");
	if ( v == NULL ) {
		fprintf(stderr,"FATAL ERROR : KENS_TCP_PORT environment variable is not defined\n");
		exit(1);
	}
	tcp_addr.sin_port=htons(atoi(v));

	/* initialize log */
	LOG_init(NULL,NULL,NULL);

	inited = 1;
}


int ksocket(int domain, int type, int protocol)
{
	int i, rv, udp_sd;
	int bind_len;
	int _err;
	message m;
	struct sockaddr_in my_addr;

	/*fprintf(stderr,">> ksocket ");*/
	if ( !inited ) _init_kenslib();

	if (sock_count>=MAX_APP_SOCK)
	{
		T_SOCK_FUNC("cannot create more socket");
		errno = ENFILE;
		return -1;
	}
	for (i=1;i<MAX_APP_SOCK;i++)
	{
		if (lib_socks[i].used==0)
			break;
	}
	udp_sd=socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sd==-1)
	{
		_err = errno;
		T_SOCK_FUNC("socket : %s",strerror(errno));
		errno = _err;
		return -1;
	}
	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_family=AF_INET;
	my_addr.sin_port=htons(0);
	my_addr.sin_addr.s_addr=INADDR_ANY;
	bind_len= sizeof(struct sockaddr_in);
	if(bind(udp_sd,(struct sockaddr *) &my_addr,bind_len  )==-1)
	{
		_err = errno;
		T_SOCK_FUNC("bind : %s",strerror(errno));
		close(udp_sd);
		errno = _err;
		return -1;
	}	
	lib_socks[i].udp_sock= udp_sd;
	m.type = CALL_SOCKET;
	rv = send_msg(&m, udp_sd, 0);
	if (rv==FAIL)
	{
		T_SOCK_FUNC("error has returned from kens");
		close(lib_socks[i].udp_sock);
		errno = m.err;
		return -1;
	}
	sock_count++;
	lib_socks[i].flag = 0;
	lib_socks[i].used = 1;

	return i;		
}

static int kpassivesocket(int domain, int type, int protocol)
{
	int i, rv, udp_sd;
	int bind_len;
	int _err;
	message m;
	struct sockaddr_in my_addr;

	/*fprintf(stderr,">> ksocket ");*/
	if ( !inited ) _init_kenslib();

	if (sock_count>=MAX_APP_SOCK)
	{
		T_SOCK_FUNC("cannot create more socket");
		errno = ENFILE;
		return -1;
	}
	for (i=1;i<MAX_APP_SOCK;i++)
	{
		if (lib_socks[i].used==0)
			break;
	}
	udp_sd=socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sd==-1)
	{
		_err = errno;
		T_SOCK_FUNC("socket : %s",strerror(errno));
		errno = _err;
		return -1;
	}
	memset(&my_addr, 0, sizeof(struct sockaddr_in));
	my_addr.sin_family=AF_INET;
	my_addr.sin_port=htons(0);
	my_addr.sin_addr.s_addr=INADDR_ANY;
	bind_len= sizeof(struct sockaddr_in);
	if(bind(udp_sd,(struct sockaddr *) &my_addr,bind_len  )==-1)
	{
		_err = errno;
		T_SOCK_FUNC("bind : %s",strerror(errno));
		close(udp_sd);
		errno = _err;
		return -1;
	}
	lib_socks[i].udp_sock= udp_sd;
	m.type = CALL_PASSIVE_SOCKET;
	rv = send_msg(&m, udp_sd, 0);
	if (rv==FAIL)
	{
		T_SOCK_FUNC("error has returned from kens");
		close(lib_socks[i].udp_sock);
		errno = m.err;
		return -1;
	}
	sock_count++;
	lib_socks[i].flag = 0;
	lib_socks[i].used = 1;

	return i;
}

int kconnect(int fd, const struct sockaddr *serv_addr,socklen_t addrlen)
{
	int rv, udp_sd, tcp_sd, _err;
	struct sockaddr_in sockname;
	int size;
	message m;
	
	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type=CALL_CONNECT;
	udp_sd= lib_socks[fd].udp_sock;

	tcp_sd=socket(AF_INET,SOCK_STREAM ,0 );
	if ( connect(tcp_sd,(struct sockaddr *)&tcp_addr,sizeof(struct sockaddr_in))==-1)
	{	
		_err = errno;
		T_SOCK_FUNC("connect : %s",strerror(errno));
		errno = _err;
		return -1;
	}
	size = sizeof(struct sockaddr_in);
	getsockname(tcp_sd, (struct sockaddr *)&sockname, &size);

	m.port = ntohs(sockname.sin_port);
	/*fprintf(stderr," m.port %d\n", m.port);*/
	memcpy(&(m.saddr), serv_addr, addrlen);

	m.len = addrlen;
	rv = send_msg(&m, udp_sd, lib_socks[fd].flag);

	if (rv==FAIL) {
		T_SOCK_FUNC("error has returned from kens");
		close(tcp_sd);
		errno = m.err;
		return -1;
	}
	
	lib_socks[fd].tcp_sock = tcp_sd;

	return 0;
}

int kbind(int fd, struct sockaddr *my_addr, socklen_t addrlen)
{
	int rv, udp_sd;
	message m;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type=CALL_BIND;
	
	m.len=addrlen;
	udp_sd=lib_socks[fd].udp_sock;	

	memcpy(&(m.saddr), my_addr, sizeof(struct sockaddr));

	rv=send_msg(&m, udp_sd, lib_socks[fd].flag);
	
	if (rv==SUCCESS) {
		return 0;
	} else {
		errno = m.err;
		return -1;
	}

}
int kaccept(int fd,  struct  sockaddr  *addr,  socklen_t *addrlen)
{
	int rv, udp_sd, tcp_sd, _err;
	struct sockaddr_in sockname;
	int size;
	int new_ksocket;
	message m;
	
	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type = CALL_ACCEPT;

	new_ksocket = kpassivesocket(AF_INET, SOCK_STREAM, 0);
	if ( new_ksocket == -1 ) return -1;	

	udp_sd = lib_socks[new_ksocket].udp_sock;
	tcp_sd = socket(AF_INET,SOCK_STREAM ,0 );

	if ( connect(tcp_sd, (struct sockaddr *)&tcp_addr, sizeof(struct sockaddr_in)) == -1 )
	{	
		_err = errno;
		T_SOCK_FUNC("connect : %s",strerror(errno));
		errno = _err;
		return -1;
	}

	size = sizeof(struct sockaddr_in);
	getsockname(tcp_sd, (struct sockaddr *)&sockname, &size);
	m.port = ntohs(sockname.sin_port);

	size = sizeof(struct sockaddr_in);
	getsockname(lib_socks[fd].udp_sock, (struct sockaddr *)&sockname,&size);
	m.port2 = ntohs(sockname.sin_port) ;

	m.len = *addrlen;

	T_SOCK_FUNC("kaccept : udp = %d tcp = %d",m.port2,m.port);

	rv=send_msg(&m, udp_sd, lib_socks[fd].flag);

	if ( rv == FAIL ) {
		T_SOCK_FUNC("error has returned from kens");
		kclose(new_ksocket);
		errno = m.err;
		return -1;
	}
	
	lib_socks[new_ksocket].tcp_sock = tcp_sd;

	*addrlen = ( sizeof(struct sockaddr_in) > *addrlen) ? *addrlen : sizeof(struct sockaddr_in);
	memcpy(addr,&m.saddr,*addrlen);

	return new_ksocket;
}

int klisten(int fd, int backlog)
{
	int rv, udp_sd;
	message m;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type=CALL_LISTEN;
	m.len=backlog;
	udp_sd=lib_socks[fd].udp_sock;	
	rv=send_msg(&m, udp_sd, lib_socks[fd].flag);
	
	if (rv==SUCCESS) {
		return 0;
	} else {
		errno = m.err;
		return -1;
	}
}

ssize_t kread(int fd, void *buf, size_t count)
{
	int tcp_sd;
	int rc;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}
	tcp_sd = lib_socks[fd].tcp_sock;	

	if ( lib_socks[fd].flag & (O_NONBLOCK|O_NDELAY) ) {
		/* prepare nonblock read */
		fd_set fds;
		struct timeval tmo;

		tmo.tv_sec=0;
		tmo.tv_usec=0;

		FD_ZERO(&fds);
		FD_SET(tcp_sd, &fds);
		if ( (rc = select(tcp_sd+1, &fds,NULL,NULL,&tmo)) > 0 ) {
			return read(tcp_sd, buf, count);
		} else if ( rc == 0 ) {
			errno = EAGAIN;
			return -1;
		} else {
			return -1;
		}
	} else {
		return read(tcp_sd, buf, count);
	}
}

ssize_t kwrite(int fd, const void *buf, size_t count)
{
	int tcp_sd;
	int rc;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}
	tcp_sd = lib_socks[fd].tcp_sock;	

	if ( lib_socks[fd].flag & (O_NONBLOCK|O_NDELAY) ) {
		/* prepare nonblock read */
		fd_set fds;
		struct timeval tmo;

		tmo.tv_sec=0;
		tmo.tv_usec=0;

		FD_ZERO(&fds);
		FD_SET(tcp_sd, &fds);
		if ( (rc = select(tcp_sd+1, NULL, &fds, NULL, &tmo)) > 0 ) {
			return write(tcp_sd, buf, count);
		} else if ( rc == 0 ) {
			errno = EAGAIN;
			return -1;
		} else {
			return -1;
		}
	} else {
		return write(tcp_sd, buf, count);
	}
}

int kclose(int fd)
{
	int rv, udp_sd;
	message m;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type=CALL_CLOSE;
	udp_sd=lib_socks[fd].udp_sock;	

	rv=send_msg(&m, udp_sd, lib_socks[fd].flag);

	close(udp_sd);
	close(lib_socks[fd].tcp_sock);
	if (lib_socks[fd].used)
		sock_count--;	

	lib_socks[fd].flag = 0;
	lib_socks[fd].used = 0;

	if (rv==SUCCESS) {
		return 0;
	} else {
		errno = m.err;
		return -1;
	}
}

int kgetsockname(int fd, struct sockaddr *localaddr, socklen_t *addrlen)
{
	int rv, udp_sd;
	message m;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type=CALL_SOCKNAME;
	udp_sd=lib_socks[fd].udp_sock;	
	m.len=*addrlen;

	rv = send_msg(&m, udp_sd, lib_socks[fd].flag);

	memcpy( localaddr, &(m.saddr), sizeof(struct sockaddr));

	/*fprintf(stderr, "port %d\n", ntohs(((struct sockaddr_in *) localaddr)->sin_port));	*/
	/*fprintf(stderr, "addr %s\n", inet_ntoa(((struct sockaddr_in*)localaddr)->sin_addr));	*/
	*addrlen= m.len;
	if ( rv == SUCCESS ) {
		return 0;
	} else {
		errno = m.err;
		return -1;
	}
} 

int kgetpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rv, udp_sd;
	message m;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	m.type=CALL_PEERNAME;
	udp_sd=lib_socks[fd].udp_sock;	
	rv=send_msg(&m, udp_sd, lib_socks[fd].flag);

	memcpy( addr, &(m.saddr), sizeof(struct sockaddr));

	*addrlen= m.len;
	if (rv==SUCCESS) {
		return 0;
	} else {
		errno = m.err;
		return -1;
	}
}

static int send_msg(message *m, int sockfd, int flag)
{
	static char inited = 0;
	fd_set fds;
	struct timeval tmo;
	struct sockaddr_in from;
	int len,rv,rc;
	message m_recv;
	u_short port;

	errno = 0;
	len = sendto(sockfd, (void *)m, sizeof(message), 0,
	    (struct sockaddr *)&to,sizeof(struct sockaddr_in));	

	if ( errno == EBADF ) {
		m->err = EBADF;
		return FAIL;
	}

	/*fprintf(stderr,"sendmsg sent %d %d\n", len, sizeof(message));*/

	len=sizeof(message);

	FD_ZERO(&fds);
again:
	tmo.tv_sec=5;
	tmo.tv_usec=0;
	FD_SET(sockfd, &fds);
	if ( (rc = select(sockfd+1, &fds,NULL,NULL,&tmo)) > 0 ) {
		rv = recvfrom(sockfd,(void *)&m_recv, sizeof(message),
				0,(struct sockaddr *)&from, &len );
		T_SOCK_FUNC("%d bytes of control response received",rv);

		if ( m_recv.type==RETURN_SOCKNAME
				|| m_recv.type==RETURN_PEERNAME
				|| m_recv.type==RETURN_ACCEPT 
				|| m_recv.type==RETURN_GETKENSOPT
				) {
			/*printf("socket name return\n");*/
			memcpy(m, &m_recv, sizeof(message));
		}

		m->err = m_recv.err;
	} else if ( rc == 0 ) {
		/* timeout? */
		if ( (flag & (O_NONBLOCK|O_NDELAY)) == 0 ) goto again;
		m->err = EAGAIN;
		return FAIL;
	} else {
		if ( errno == EINTR ) goto again;
		m->err = errno;
		return FAIL;	
	}

	return m_recv.result;
}

/*
 * utility functions
 */
size_t kreadline(int fd,void *vptr,size_t maxlen)
{
	size_t n,rc;
	char c,*ptr;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	ptr = vptr;
	for ( n = 1; n < maxlen; n++ ) {
again:
		if ( (rc = kread(fd,&c,1)) == 1 ) {
			*ptr++ = c;
			if ( c == '\n' )
				break;
		} else if ( rc == 0 ) {
			if ( n == 1 ) return 0;
			else break;
		} else {
			if ( errno == EINTR )
				goto again;
			return -1;
		}
	}

	*ptr = '\0';

	return n;
}

int kfcntl(int fd,int cmd,...)
{
	va_list args;

	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EINVAL;
		return -1;
	}

	switch ( cmd ) {
		case F_SETFL:
			/* set flag */
			va_start(args,cmd);
			lib_socks[fd].flag = va_arg(args,int);
			va_end(args);
			break;
		case F_GETFL:
			return lib_socks[fd].flag;
	}

	return 0;
}

int kshutdown(int fd,int how)
{
	if ( !inited ) _init_kenslib();

	if ( fd < 0 || fd > MAX_APP_SOCK || lib_socks[fd].used == 0 ) {
		errno = EBADF;
		return -1;
	}

	if ( how & SHUT_RDWR ) {
		/* the same as kclose */
	} else if ( how & SHUT_RD ) {
		/* shutdown read pipe */
	} else if ( how & SHUT_WR ) {
		/* shutdown write pipe */
	}

	return 0;
}

static fd_set *copy_fd_set(int n,fd_set *fds,fd_set *kfds,int *max)
{
	int i;
	if ( kfds == NULL ) return NULL;

	FD_ZERO(fds);
	for ( i = 0; i < n; i++ ) {
		if ( FD_ISSET(i,kfds) ) {
			FD_SET(lib_socks[i].tcp_sock,fds);
			*max = ( lib_socks[i].tcp_sock > *max )
					? lib_socks[i].tcp_sock
					: *max;
		}
	}

	return fds;
}

static void copy_back_fd_set(int n,fd_set *fds,fd_set *kfds)
{
	int i;
	if ( kfds == NULL ) return;

	for ( i = 0; i < n; i++ ) {
		if ( FD_ISSET(i,kfds) ) {
			if ( FD_ISSET(lib_socks[i].tcp_sock,fds) )
				FD_CLR(i,kfds);
			else
				FD_SET(i,kfds);
		}
	}
}

int kselect(int n, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
	int rc,max,i;
	fd_set _read,_write,_except;
	fd_set *rp,*wp,*ep;

	if ( !inited ) _init_kenslib();

	max = -1;
	rp = copy_fd_set(n,&_read,readfds,&max);
	wp = copy_fd_set(n,&_write,writefds,&max);
	ep = copy_fd_set(n,&_except,exceptfds,&max);

	rc = select(max+1,rp,wp,ep,timeout);

	if ( rc > 0 ) {
		/* convert into ksocket descriptor */
		copy_back_fd_set(n,rp,readfds);
		copy_back_fd_set(n,wp,writefds);
		copy_back_fd_set(n,ep,exceptfds);
	}

	return rc;
}

int kgetkensopt(int optname, void *optval, socklen_t *optlen)
{
	int rv, udp_sd;
	int bind_len;
	int _err;
	message m;
	struct sockaddr_in my_addr;

	if (*optlen != 4)
	{
		errno = EINVAL;
		return -1;
	}

	/*fprintf(stderr,">> ksocket ");*/
	if ( !inited ) _init_kenslib();

	udp_sd=socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sd==-1)
	{
		_err = errno;
		T_SOCK_FUNC("socket : %s",strerror(errno));
		errno = _err;
		return -1;
	}
	my_addr.sin_family=AF_INET;	
	my_addr.sin_port=htons(0);
	my_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
	bind_len= sizeof(struct sockaddr);
	if(bind(udp_sd,(struct sockaddr *) &my_addr,bind_len  )==-1)
	{
		_err = errno;
		T_SOCK_FUNC("bind : %s",strerror(errno));
		close(udp_sd);
		errno = _err;
		return -1;
	}	
	m.type = CALL_GETKENSOPT;
	m.optname = optname;
	m.optlen = *optlen;
	memcpy(m.optval, optval, m.optlen);
	rv = send_msg(&m, udp_sd, 0);
	close(udp_sd);
	if (rv==FAIL)
	{
		T_SOCK_FUNC("error has returned from kens");
		errno = m.err;
		return -1;
	}
	*optlen = m.optlen;
	memcpy(optval, m.optval, m.optlen);

	return 0;		
}

int ksetkensopt(int optname, const void *optval, socklen_t optlen)
{
	int rv, udp_sd;
	int bind_len;
	int _err;
	message m;
	struct sockaddr_in my_addr;

	if (optlen != 4)
	{
		errno = EINVAL;
		return -1;
	}

	/*fprintf(stderr,">> ksocket ");*/
	if ( !inited ) _init_kenslib();

	udp_sd=socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sd==-1)
	{
		_err = errno;
		T_SOCK_FUNC("socket : %s",strerror(errno));
		errno = _err;
		return -1;
	}
	my_addr.sin_family=AF_INET;	
	my_addr.sin_port=htons(0);
	my_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
	bind_len= sizeof(struct sockaddr);
	if(bind(udp_sd,(struct sockaddr *) &my_addr,bind_len  )==-1)
	{
		_err = errno;
		T_SOCK_FUNC("bind : %s",strerror(errno));
		close(udp_sd);
		errno = _err;
		return -1;
	}	
	m.type = CALL_SETKENSOPT;
	m.optname = optname;
	m.optlen = optlen;
	memcpy(m.optval, optval, m.optlen);
	rv = send_msg(&m, udp_sd, 0);
	close(udp_sd);
	if (rv==FAIL)
	{
		T_SOCK_FUNC("error has returned from kens");
		errno = m.err;
		return -1;
	}

	return 0;		
}


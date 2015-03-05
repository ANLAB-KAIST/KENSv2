#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <fcntl.h>


#include "iniparser.h"

#include "ksockconst.h"
#include "ksocket.h"
#include "kernel.h"
#include "krip.h"
#include "log.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

typedef struct list_node {
	struct list_node * next;
	u_short port;
	int tcp_sd;
} list_node; 

#define KENS_NAME_MAX	1024

typedef struct kernel_context_t {
	char name[KENS_NAME_MAX];

	int num_socks;
	int tcp_sockfd;
	int udp_sockfd;
	struct sockaddr_in udp;
	struct sockaddr_in tcp;
	list_node * unassociated_pipe_list;
} kernel_context_t;

int pcap_log_fd = -1;
unsigned int random_seed = 0;

typedef struct sock_context_t {
	unsigned short int app_udp_port;
	tcp_socket tcp_sock;
	int pipe;
} sock_context_t;

static sock_context_t *socks[MAX_SOCKETS];
static kernel_context_t ker_context;

/***
 MAIN Functions ****/
static void KENS_startup(dictionary *conf);
static void KENS_dispatch_loop();
static void sigint_handler();
static void KENS_shutdown();
static void ker_shutdown();
static void ker_startup();
static void ker_dispatch();

/***
 helper functions
	    ***/
void add_to_list(int fd, u_short port);
void process_ctrl_message(int sockfd);
int make_ker_socket(tcp_socket tcp_handle, u_short port, int *err);
int find_ker_socket(u_short port);
int remove_from_list(u_short port);

/*****/
static char *MSG_TYPE[] = {
	"",
	"ksocket",
	"return ksocket",
	"kconnect",
	"return kconnect",
	"kbind",
	"return kbind",
	"kaccept",
	"return kaccept",
	"klisten",
	"return klisten",
	"kclose",
	"return kclose",
	"kgetsockname",
	"return kgetsockname",
	"kgetpeername",
	"return kgetpeername",
	"asynch return kaccept",
	"asynch return kconnect",
	"asynch EOF",
	"asynch kclose",
	"kgetkensopt",
	"return kgetkensopt",
	"ksetkensopt",
	"return ksetkensopt",
	"passive ksocket",
};

int main(int argc, char *argv[])
{
	dictionary *conf = NULL;

	if (argc!=2)
	{
		fprintf(stderr,"Usage %s <config_filename>\n", argv[0]);
		exit(0);
	}

	conf = iniparser_load(argv[1]);
	if ( conf == NULL ) {
		fprintf(stderr,"cannot parse file %s\n",argv[1]);
		exit(-1);
	}

	KENS_startup(conf);

	if ( conf != NULL )
		iniparser_freedict(conf);

	T_SOCK_KRNL("KENS Host is starting\n");

	KENS_dispatch_loop();

	return 0;
}
void KENS_dispatch_loop()
{	
	
	for (; ;)
	{
		ker_dispatch();
		dl_dispatch();
		tcp_dispatch();
		krip_dispatch();
		ip_dispatch();
		kmgmt_dispatch();
	}
}

void KENS_startup(dictionary *conf)
{
	ker_startup(conf);

	kmgmt_init (conf);

	dl_init(conf);
	ip_init(conf);

	krip_init(conf);

	tcp_startup();
}

static void ker_dispatch()
{
	fd_set fds;
	struct timeval tmo;
	int max_fd;
	int udp_sd= ker_context.udp_sockfd;
	int tcp_sd= ker_context.tcp_sockfd;	

	FD_ZERO(&fds);
	FD_SET(udp_sd, &fds);	
	FD_SET(tcp_sd, &fds);	
	tmo.tv_sec=0;
	/*tmo.tv_usec=0;*/
	tmo.tv_usec=/*1000*/0;
	max_fd= MAX(udp_sd, tcp_sd);

	/* FIXME : poll로 고치자 */
	switch (select(max_fd+1, &fds, NULL,NULL,&tmo))
	{
		case -1: 
			break;
		case 0:
			break;
		default:
			if ( FD_ISSET(tcp_sd, &fds) )
			{
				int new_sd;
				int len= sizeof(struct sockaddr_in);
				struct sockaddr_in addr;

				new_sd = accept(tcp_sd,(struct sockaddr *)&addr, &len);
				if (new_sd>0 && addr.sin_addr.s_addr == inet_addr("127.0.0.1"))
				{
					T_SOCK_KRNL("local pipe from %d",ntohs(addr.sin_port));
					add_to_list(new_sd, ntohs(addr.sin_port)) ;	
				} else {	/* connection from different host */
					T_SOCK_KRNL("pipe from external host");
					close(new_sd);
				}
			}
			if (FD_ISSET(udp_sd, &fds))
			{
				T_SOCK_KRNL("control message is available");
				process_ctrl_message(udp_sd);
			}
	}
}

void add_to_list(int new_sd, u_short port)
{
	list_node * node=ker_context.unassociated_pipe_list;
	list_node * next_node=node->next;
	while(next_node!=NULL)
	{
		node=node->next;
		next_node=next_node->next;	
	}
	next_node=(list_node *)malloc(sizeof(list_node));
	next_node->tcp_sd=new_sd;
	next_node->port= port;
	next_node->next=NULL;
	node->next=next_node;
	
}

int  remove_from_list(u_short port)
{
	list_node * node=ker_context.unassociated_pipe_list;
	list_node * next_node=node->next;
	int return_tcpsd;
	while(next_node!=NULL)
	{
		if(next_node->port==port)
			break;
		node=node->next;
		next_node=next_node->next;	
	}
	if(next_node==NULL)
		return -1;
	if (next_node->port!=port)
		return -1;
	return_tcpsd= next_node->tcp_sd;
	node->next=next_node->next;
	free(next_node);
	return return_tcpsd;
}

static struct pcap_file_header {
	uint32_t magic;
	u_short version_major;
	u_short version_minor;
	uint32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;    /* accuracy of timestamps */
	uint32_t snaplen;    /* max length saved portion of each pkt */
	uint32_t linktype;   /* data link type (LINKTYPE_*) */
};

void ker_startup(dictionary *conf)
{
	char fn[128];
	char dir[1024];
	FILE *fp;
	char *svrname,*v;
	int udp_port,tcp_port;

	fprintf(stderr,"KENS Kernel startup\n");

	/* parse udp port number */
	udp_port = iniparser_getint(conf,"KENS:udp_port",0);
	tcp_port = iniparser_getint(conf,"KENS:tcp_port",0);
	svrname = iniparser_getstring(conf,"KENS:server_name","KENS");
	random_seed = iniparser_getint(conf, "KENS:random_seed", 110123177);

	if ( svrname == NULL || udp_port == 0 || tcp_port == 0 ) {
		fprintf(stderr,"invalid configuration. server_name, udp_port and tcp_port are should be specified.\n");
		exit(1);
	}

	/* initialize log */
	sprintf(fn,"%s.log",svrname);
	LOG_init(conf,fn,NULL);
	LOG_print(NULL,"KENS Start");

	memset(&ker_context, 0x00, sizeof(kernel_context_t));
	memcpy(ker_context.name, svrname, strlen(svrname));

	signal(SIGINT, sigint_handler);
	ker_context.udp_sockfd= socket(AF_INET, SOCK_DGRAM, 0);	
	ker_context.tcp_sockfd= socket(AF_INET, SOCK_STREAM, 0);	
	if (ker_context.udp_sockfd==-1
		|| ker_context.tcp_sockfd==-1)
	{
		fprintf(stderr,"error ker_startup in making socket\n");
		exit(0);
	}

#ifdef SO_REUSEADDR
	{
		int tmp = 1,rc;
		rc = setsockopt( ker_context.tcp_sockfd, SOL_SOCKET, SO_REUSEADDR,
				(char *)&tmp,sizeof(tmp) );
		assert( !rc );
		rc = setsockopt( ker_context.udp_sockfd, SOL_SOCKET, SO_REUSEADDR,
				(char *)&tmp,sizeof(tmp) );
		assert( !rc );
	}
#endif


	ker_context.udp.sin_family = AF_INET;
	ker_context.tcp.sin_family= AF_INET;
	ker_context.udp.sin_addr.s_addr = inet_addr("127.0.0.1");
	ker_context.tcp.sin_addr.s_addr = inet_addr("127.0.0.1");
	ker_context.udp.sin_port = htons(udp_port);
	ker_context.tcp.sin_port = htons(tcp_port);

	char pcap_file_name_buf[128];
	strcpy(pcap_file_name_buf, svrname);
	strcat(pcap_file_name_buf, ".pcap");
	pcap_log_fd = open(pcap_file_name_buf, O_CREAT | O_TRUNC | O_RDWR, 00644);
	if(pcap_log_fd == -1)
		perror("pcap open");
	struct pcap_file_header pcap_header;
	memset(&pcap_header, 0, sizeof(pcap_header));
	pcap_header.magic = 0xa1b2c3d4;
	pcap_header.version_major = 2;
	pcap_header.version_minor = 4;
	pcap_header.snaplen = NETWORK_BUFFER_SIZE;
	pcap_header.linktype = 228;//LINKTYPE_IPV4
	if(pcap_log_fd != -1)
		write(pcap_log_fd, &pcap_header, sizeof(pcap_header));

	v = LOG_get_flags();
	assert( getcwd(dir,1024) != NULL );

	/* write environment file */
	sprintf(fn,"%s.csh",svrname);
	fp=fopen(fn,"w");
	if (fp==NULL) {
		printf("Cannot open file %s\n",fn);
		exit(0);
	}
	fprintf(fp, "setenv KENS_UDP_PORT %d\n", udp_port);
	fprintf(fp, "setenv KENS_TCP_PORT %d\n", tcp_port);
	if ( v != NULL && kens_log_flag != LOG_NONE ) {
		fprintf(fp, "setenv %s %s/%s.log\n",ENV_KENS_LOG_FILE,dir,svrname);
		fprintf(fp, "setenv %s \"%s\"\n",ENV_KENS_LOG_FLAG,v);
	}
	fclose(fp);

	sprintf(fn,"%s.sh",svrname);
	fp=fopen(fn,"w");
	if (fp==NULL) {
		printf("Cannot open file %s\n",fn);
		exit(0);
	}
	fprintf(fp, "export KENS_UDP_PORT=%d\n", udp_port);
	fprintf(fp, "export KENS_TCP_PORT=%d\n", tcp_port);
	if ( v != NULL && kens_log_flag != LOG_NONE ) {
		fprintf(fp, "export %s=%s/%s.log\n",ENV_KENS_LOG_FILE,dir,svrname);
		fprintf(fp, "export %s=\"%s\"\n",ENV_KENS_LOG_FLAG,v);
	}
	fclose(fp);

	if (bind(ker_context.udp_sockfd, (struct sockaddr*)&(ker_context.udp), sizeof(struct sockaddr_in))==-1
	 || bind(ker_context.tcp_sockfd,(struct sockaddr*) &(ker_context.tcp), sizeof(struct sockaddr_in))==-1)
	{
		fprintf(stderr,"error in ker_startup bind\n");
		exit(0);
	}
	if (listen(ker_context.tcp_sockfd, 10) == -1)
	{
		fprintf(stderr,"error in ker_startup listen\n");
		exit(0);
	}	

	ker_context.unassociated_pipe_list= (list_node *)malloc(sizeof(list_node));
	memset(ker_context.unassociated_pipe_list, 0x00, sizeof(list_node));
}

static void sigint_handler()
{
	KENS_shutdown();
}
static void KENS_shutdown()
{
	fprintf(stderr, "KENS shutting down\n");


	kmgmt_shutdown ();

	tcp_shutdown();

	krip_shutdown();

	ip_shutdown();
 	dl_shutdown();
	ker_shutdown();

#ifdef dmalloc
	dmalloc_shutdown();
#endif

	exit(0);	
}
static void ker_shutdown()
{
	int i;
	list_node *p,*t;

	fprintf(stderr, "kernel shutting down\n");

	for (i=0;i<MAX_SOCKETS;i++)
	{
		if (socks[i]!=NULL)
			free(socks[i]);
	}
	close(ker_context.udp_sockfd);	
	close(ker_context.tcp_sockfd);	

	p = ker_context.unassociated_pipe_list;
	while ( p != NULL ) {
		t = p->next;
		free(p);
		p = t;
	}

	if(pcap_log_fd != -1)
	{
		close(pcap_log_fd);
		pcap_log_fd = -1;
	}
	LOG_shutdown();
}

void process_ctrl_message(int sockfd)
{
	int size;
	int recv_len,rv;
	struct sockaddr_in from;	
	message m;
	message m_ret;
	int kernel_sd;
	int kernel_accept_sd;
	int kernel_bind_sd;
	tcp_socket tcp_handle=NULL;
	size= sizeof(struct sockaddr);
	
	recv_len=recvfrom(sockfd, (void *)&m, sizeof(message), 0, (struct sockaddr *)&from, &size);	
	if ( recv_len != sizeof(message) ) {
		T_SOCK_KRNL("corrupted message : %d bytes out of %d",recv_len,sizeof(message));
		return;
	}
	
	if ( m.type > MAX_MSG ) {
		T_SOCK_KRNL("invalid ctrl message type");
		return;
	} else {
		T_SOCK_KRNL("ctrl from = %d type = %s",ntohs(from.sin_port),MSG_TYPE[m.type]);
	}

	m_ret.err = 0;	/* no error */
	m_ret.result = FAIL;

	switch(m.type)	{
		case CALL_SOCKET:
			if ( ker_context.num_socks < MAX_SOCKETS ) {	
				tcp_handle = tcp_open(&m_ret.err);
				if ( tcp_handle != NULL ) {
					if ( make_ker_socket(tcp_handle,ntohs(from.sin_port),&m_ret.err) ) {
						/* free allocated socket */
						int t;
						tcp_close(tcp_handle,&t);
					} else {
						m_ret.result =SUCCESS;	
					}
				}
			}
			m_ret.type = RETURN_SOCKET;
			break;
		case CALL_PASSIVE_SOCKET:
			if ( ker_context.num_socks < MAX_SOCKETS ) {
				tcp_handle = tcp_open_passive(&m_ret.err);
				if ( tcp_handle != NULL ) {
					if ( make_ker_socket(tcp_handle,ntohs(from.sin_port),&m_ret.err) ) {
						/* free allocated socket */
						int t;
						tcp_context_free(tcp_handle);
					} else {
						m_ret.result =SUCCESS;
					}
				}
			}
			m_ret.type = RETURN_SOCKET;
			break;
		case CALL_LISTEN:
			kernel_sd=find_ker_socket(ntohs(from.sin_port));
			if (kernel_sd == -1 || socks[kernel_sd]==NULL) {
				m_ret.err = EBADF;
			} else {
				int backlog=m.len;
				
				if (tcp_listen(socks[kernel_sd]->tcp_sock, backlog, &m_ret.err)) {
					m_ret.result=SUCCESS;
				}
			}
			m_ret.type=RETURN_LISTEN;
			break;

		case CALL_CONNECT:
			kernel_sd = find_ker_socket(ntohs(from.sin_port));
			if (kernel_sd == -1 || socks[kernel_sd]==NULL) {
				m_ret.err = EBADF;
			} else {
				struct sockaddr_in s;
				int pipe;
				memcpy(&s, &(m.saddr), m.len);
				pipe = remove_from_list(m.port);	
				socks[kernel_sd]->pipe = pipe;
				T_SOCK_KRNL("kconnect to %s:%d with pipe 0x%x",inet_ntoa(s.sin_addr), ntohs(s.sin_port), pipe);
				if (tcp_connect(socks[kernel_sd]->tcp_sock, (struct sockaddr *)&s, m.len, pipe,&m_ret.err) ) {
					m_ret.result=SUCCESS;
				}
			}
			return;
		case CALL_BIND:
			kernel_sd=find_ker_socket(ntohs(from.sin_port));
			if (kernel_sd == -1 || socks[kernel_sd]==NULL) {
				m_ret.err = EBADF;
			} else {
				struct sockaddr_in s;
				memcpy(&s, &(m.saddr), sizeof(s));

				T_SOCK_KRNL("bind at %s:%d",inet_ntoa(s.sin_addr),ntohs(s.sin_port));

				if (tcp_bind(socks[kernel_sd]->tcp_sock, (struct sockaddr *)&s, sizeof(s), &m_ret.err)) {
					m_ret.result=SUCCESS;
				}
			}
			m_ret.type=RETURN_BIND;
			break;
		case CALL_ACCEPT:
			kernel_accept_sd=find_ker_socket(ntohs(from.sin_port));
			kernel_bind_sd=find_ker_socket(m.port2);
			if (kernel_sd == -1 || socks[kernel_accept_sd]==NULL) {
				m_ret.err = EBADF;
			} else {
				int pipe;

				pipe = remove_from_list(m.port);	
				socks[kernel_accept_sd]->pipe=pipe;

				if (tcp_accept(socks[kernel_bind_sd]->tcp_sock,
					socks[kernel_accept_sd]->tcp_sock, pipe, &m_ret.err) ) {
					m_ret.result=SUCCESS;
				}
			}
			return;
		case CALL_CLOSE:
			kernel_sd=find_ker_socket(ntohs(from.sin_port));
			if (kernel_sd < 0 || socks[kernel_sd] == NULL) {
				m_ret.err = EBADF;
			} else {
				if ( tcp_close(socks[kernel_sd]->tcp_sock, &m_ret.err) ) {
					m_ret.result=SUCCESS;
				}
				if ( socks[kernel_sd] != NULL ) {	
					if(socks[kernel_sd]->pipe != 0)
							close(socks[kernel_sd]->pipe);	/* no more read/write is available */
					socks[kernel_sd]->pipe = -1;
				}
			}
			m_ret.type=RETURN_CLOSE;
			break;
		case CALL_SOCKNAME:
			kernel_sd=find_ker_socket(ntohs(from.sin_port));
			if (kernel_sd == -1 || socks[kernel_sd]==NULL) {
				m_ret.err = EBADF;
			} else {
				struct sockaddr name;
				int len;

				len = m.len;

				if ( tcp_getsockname(socks[kernel_sd]->tcp_sock,&name,&len, &m_ret.err) ) {
					m_ret.result = SUCCESS;
					m_ret.len= len;
					memcpy(&(m_ret.saddr), &name, len);
					T_SOCK_KRNL("sockname is %s:%d",inet_ntoa(((struct sockaddr_in *)&name)->sin_addr),ntohs(((struct sockaddr_in *)&name)->sin_port));
				}
			}
			m_ret.type=RETURN_SOCKNAME;
			break;
		case CALL_PEERNAME:
			kernel_sd = find_ker_socket(ntohs(from.sin_port));
			if (kernel_sd == -1 || socks[kernel_sd]==NULL) {
				T_SOCK_KRNL("failed to search kernel socket for %d",ntohs(from.sin_port));
				m_ret.err = EBADF;
			} else {
				struct sockaddr name;
				int len = sizeof(struct sockaddr);

				if (tcp_getpeername(socks[kernel_sd]->tcp_sock,&name ,&len, &m_ret.err)) {
					m_ret.result=SUCCESS;
					m_ret.len= len;
					memcpy(&(m_ret.saddr), &name, len);

					T_SOCK_KRNL("peername is %s:%d", inet_ntoa(((struct sockaddr_in *)&name)->sin_addr), ntohs(((struct sockaddr_in *)&name)->sin_port));
				}
			}
			m_ret.type=RETURN_PEERNAME;
			break;
		case CALL_GETKENSOPT:
			switch (m.optname) {
				case KO_DL_DELAY:
					*(int*)m_ret.optval = dl_get_delay();
					m_ret.optlen = sizeof(int);
					m_ret.result = SUCCESS;	
					break;
				case KO_DL_DROP_RATE:
					*(float*)m_ret.optval = dl_get_drop_rate();
					m_ret.optlen = sizeof(float);
					m_ret.result = SUCCESS;	
					break;
				case KO_DL_REORDER_RATE:
					*(float*)m_ret.optval = dl_get_reorder_rate();
					m_ret.optlen = sizeof(float);
					m_ret.result = SUCCESS;	
					break;
				case KO_DL_ENABLE_SETH:
					*(int*)m_ret.optval = dl_get_enable_seth(*(int*)m.optval);
					m_ret.optlen = sizeof(int);
					m_ret.result = SUCCESS;	
					break;
				case KO_DL_DISABLE_SETH:
					*(int*)m_ret.optval = dl_get_disable_seth(*(int*)m.optval);
					m_ret.optlen = sizeof(int);
					m_ret.result = SUCCESS;	
					break;
				case KO_KRIP_UPDATE_INTERVAL:
					*(int*)m_ret.optval = krip_get_update_interval();
					m_ret.optlen = sizeof(int);
					m_ret.result = SUCCESS;	
					break;
				case KO_KRIP_TIMEOUT:
					*(int*)m_ret.optval = krip_get_timeout();
					m_ret.optlen = sizeof(int);
					m_ret.result = SUCCESS;	
					break;
			}
			m_ret.type = RETURN_GETKENSOPT;
			break;
		case CALL_SETKENSOPT:
			switch (m.optname) {
				case KO_DL_DELAY:
					if (dl_set_delay(*(int*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
				case KO_DL_DROP_RATE:
					if (dl_set_drop_rate(*(float*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
				case KO_DL_REORDER_RATE:
					if (dl_set_reorder_rate(*(float*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
				case KO_DL_ENABLE_SETH:
					if (dl_set_enable_seth(*(int*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
				case KO_DL_DISABLE_SETH:
					if (dl_set_disable_seth(*(int*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
				case KO_KRIP_UPDATE_INTERVAL:
					if (krip_set_update_interval(*(int*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
				case KO_KRIP_TIMEOUT:
					if (krip_set_timeout(*(int*)m.optval) == 0)
						m_ret.result = SUCCESS;	
					break;
			}
			m_ret.type = RETURN_SETKENSOPT;
			break;
	}

	T_SOCK_KRNL("ctrl return type = %s result = %s", MSG_TYPE[m_ret.type], ( m_ret.result == SUCCESS ) ? "SUCCESS" : "FAIL");

	/*
		Return message
	*/
	rv=sendto(sockfd, (void *)&m_ret, sizeof(message), 0,
		 (struct sockaddr *)&from, sizeof(struct sockaddr_in));
	T_SOCK_KRNL("%d bytes were sent to network",rv);
}

int find_ker_socket(u_short port)
/* search for "port"*/
/* return -1 on error*/
{
	int i;
	for ( i = 0; i < MAX_SOCKETS; i++ ) {
		if ( socks[i] != NULL && socks[i]->app_udp_port == port ) {
			return i;
		}
	}
	T_SOCK_KRNL("failed to find kernel socket for port %d",port);
	/*
	fprintf(stderr,"app udp port 0 %d %d\n", socks[0]->app_udp_port, port);
	fprintf(stderr,"not found in ker socket\n");
	*/
	return -1;
}

int make_ker_socket(tcp_socket tcp_handle, u_short port, int *err)
{
	int i;

	if ( ker_context.num_socks >= MAX_SOCKETS ) {
		*err = ENFILE;
		return -1;
	}
	
	for ( i = 0; i < MAX_SOCKETS; i++ ) {
		if ( socks[i] == NULL ) break;
	}	
	socks[i]= (sock_context_t *)malloc(sizeof(sock_context_t));
	if ( socks[i] == NULL ) {
		*err = ENOMEM;
		return -1;
	}
	ker_context.num_socks++;
	socks[i]->tcp_sock = tcp_handle;
	socks[i]->app_udp_port = port;
	/*printf("i is %d\n",i);*/
	return 0;		
}

int find_ker_socket_t(tcp_socket tcp_sock)
/* search for "tcp_sock"*/
/* return -1 on error*/
{
	int i;
	for (i=0;i<MAX_SOCKETS;i++)
	{
		if (socks[i]!=NULL && socks[i]->tcp_sock==tcp_sock)
		{
			return i;
		}
	}
	T_SOCK_KRNL("no matched kernel socket to tcp context %08x",tcp_sock);
	return -1;
}

int ker_message(char msg_id,int status, tcp_socket tcp_bind_handle, tcp_socket tcp_conn_handle)
{
	int ker_bind;
	int ker_conn;	
	u_short app_port;
	struct sockaddr_in s;
	int sent;
	int s_size;
	message m;

	T_SOCK_KRNL("asynch message type = %s",MSG_TYPE[msg_id]);

	switch ( msg_id ) {
		case ASYNCH_RETURN_ACCEPT:
			if(tcp_conn_handle==NULL)
				return -1;
			ker_conn=find_ker_socket_t(tcp_conn_handle);
			if(ker_conn==-1)
				return -1;
						
			app_port= socks[ker_conn]->app_udp_port;

			T_SOCK_KRNL("kernel socket = %d actual udp port = %d",ker_conn,app_port);

			s.sin_family = AF_INET;
			s.sin_port = htons(app_port);
			s.sin_addr.s_addr = inet_addr("127.0.0.1");
			/* send return msg to s*/
			m.type=RETURN_ACCEPT;
			if(status==0)
			{
				m.result=SUCCESS;
				s_size=sizeof(struct sockaddr);
				tcp_getpeername(tcp_conn_handle ,&(m.saddr),&s_size,&m.err);
				m.len= s_size;
			}
			else if (status==-1)
				m.result=FAIL;
			
			sent=sendto(ker_context.udp_sockfd, &m, sizeof(m),
					0, (struct sockaddr *)&s, sizeof(s));

			T_SOCK_KRNL("return kaccept result = %s %d out of %d bytes sent", ( m.result == SUCCESS ) ? "SUCCESS" : "FAIL", sent, sizeof(m));

			if(sent==sizeof(m))
				return 0;
			else
				return -1;
		case ASYNCH_RETURN_CONNECT:
			if(tcp_bind_handle==NULL)
				return -1;
			ker_bind=find_ker_socket_t(tcp_bind_handle);
			if(ker_bind==-1)
				return -1;
			app_port= socks[ker_bind]->app_udp_port;

			T_SOCK_KRNL("kernel socket = %d actual udp port = %d",ker_bind,app_port);

			s.sin_family=AF_INET;
			s.sin_port=htons(app_port);
			s.sin_addr.s_addr=inet_addr("127.0.0.1");
			
			/* send return msg to s */
			m.type=RETURN_CONNECT;
			if(status==0)
				m.result=SUCCESS;
			else if (status==-1)
				m.result=FAIL;
			sent=sendto(ker_context.udp_sockfd, &m, sizeof(m),
					0,(struct sockaddr *)&s,sizeof(s));

			T_SOCK_KRNL("return kaccept result = %s %d out of %d bytes sent", ( m.result == SUCCESS ) ? "SUCCESS" : "FAIL", sent, sizeof(m));

			if(sent==sizeof(m))
				return 0;
			else return -1;
		case ASYNCH_EOF:
			/* just close socket */
			ker_conn = find_ker_socket_t(tcp_conn_handle);
			if ( ker_conn == -1 )
				return -1;

			T_SOCK_KRNL("(%08x) has reached to EOF",tcp_conn_handle);

			if ( socks[ker_conn] != NULL )
				shutdown(socks[ker_conn]->pipe,SHUT_WR);

			return 0;
		case ASYNCH_CLOSE:
			/* just close socket */
			ker_conn = find_ker_socket_t(tcp_conn_handle);
			if ( ker_conn == -1 )
				return -1;

			T_SOCK_KRNL("asynchronous close for socket %08x",tcp_conn_handle);

			if ( socks[ker_conn] != NULL ) {	
				if ( socks[ker_conn]->pipe != -1 )
					close(socks[ker_conn]->pipe);
				free(socks[ker_conn]);
				socks[ker_conn]=NULL;
				ker_context.num_socks--;
			}

			return 0;
	}

	return -1;
}

char *get_server_name (void)
{
	return ker_context.name;
}

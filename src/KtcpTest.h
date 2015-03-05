#ifndef __KENS_KTCPTEST_H__
#define __KENS_KTCPTEST_H__

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

#define SHS (sizeof(struct tcphdr))
#define MPS (536 - 20)
#define MSS (SHS + MPS)
#define ASYNCH_RETURN_ACCEPT 17
#define ASYNCH_RETURN_CONNECT 18
#define ASYNCH_EOF 19
#define ASYNCH_CLOSE 20

#define MIN(x,y)  ((x) <= (y) ? (x) : (y))
#define MAX(x,y)  ((x) >= (y) ? (x) : (y))

enum {
	CSTATE_CLOSED = 0,
	CSTATE_LISTEN = 1,
	CSTATE_SYN_SENT = 2,
	CSTATE_SYN_RECV = 3,
	CSTATE_ESTABLISHED = 4,
	CSTATE_FIN_WAIT1 = 5,
	CSTATE_FIN_WAIT2 = 6,
	CSTATE_CLOSING = 7,
	CSTATE_TIME_WAIT = 8,
	CSTATE_CLOSE_WAIT = 9,
	CSTATE_LAST_ACK = 10
};

typedef struct tcp_container_t {
	tcp_seq seq_num;
	u_char flags;
	tcp_seq data_length;
	char data[MPS];

	int last_sent; /* Unit of mtime. */
	int timeout; /* Unit of mtime. */
	int trial;
} tcp_container;

typedef struct tcp_stream_t {
	tcp_seq seq_num;
	tcp_seq ack_num;
	tcp_seq win;
	list container_list;
} tcp_stream;

typedef struct tcp_context_t {
	int state;

	struct sockaddr_in my_addr;
	struct sockaddr_in peer_addr;

	bool is_bound;

#define PIPE_NO_RD		0x40000000
#define PIPE_NO_WR		0x80000000
#define PIPE_NO_RDWR	(PIPE_NO_RD|PIPE_NO_WR)
#define PIPE_CLOSED		PIPE_NO_RDWR
#define PIPE_FD(x)		(int)((x) & (~PIPE_CLOSED))

	int pipe;

	route ro;

	struct tcp_context_t *bind_ctx;
	int backlog;
	list pending_ctx_list;
	list accept_pending_ctx_list;

	int timeout;
	int estimated_rtt;

	tcp_stream my_stream;
	tcp_stream peer_stream;

	int snd_cwnd;
	int snd_ssthresh;
	int t_dupacks;

} tcp_context;

typedef struct tcp_segment_t {
	struct tcphdr header;
	char data[MPS];
	tcp_seq length;
} tcp_segment;

void TestBind(CuTest *tc);
void TestListen(CuTest *tc);
void TestAccept(CuTest *tc);
void TestConnect(CuTest *tc);
void TestSendSegment1(CuTest *tc);
void TestSendSegment2(CuTest *tc);
void TestSendSegment3(CuTest *tc);
void TestFindCtx(CuTest *tc);
void TestCreateCtx(CuTest *tc);
void TestDispatchPending(CuTest *tc);
void TestChangeState1(CuTest *tc);
void TestChangeState2(CuTest *tc);
void TestClose2(CuTest *tc);
void TestClose3(CuTest *tc);
void TestCleanupTimewaitCtx(CuTest *tc);
void TestAddToMyStream(CuTest *tc);
void TestSendStream3(CuTest *tc);
void TestSendStream4(CuTest *tc);
void TestAcceptPeerACK3(CuTest *tc);
void TestAcceptPeerACK4(CuTest *tc);
void TestAcceptPeerSYN(CuTest *tc);
void TestAcceptPeerFIN(CuTest *tc);
void TestAddToPeerStream(CuTest *tc);
void TestRecvStream(CuTest *tc);
void TestRetransmit3(CuTest *tc);
void TestRetransmit4(CuTest *tc);

#endif /* __KENS_KTCPTEST_H__ */

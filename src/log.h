#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

#include "iniparser.h"

extern unsigned int kens_log_flag;

#define LOG_NONE			0

#define LOG_SOCK_ALL		LOG_SOCK_MASK
#define LOG_SOCK_MASK		0x0000000f
#define LOG_SOCK_CTRL		0x00000001
#define LOG_SOCK_FUNC		0x00000002
#define LOG_SOCK_KRNL		0x00000004

#define LOG_TCP_ALL			LOG_TCP_MASK
#define LOG_TCP_MASK		0x00000ff0
#define LOG_TCP				0x00000010
#define LOG_TCP_CB			0x00000020
#define LOG_TCP_HDR			0x00000040
#define LOG_TCP_PKT			0x00000080
#define LOG_TCP_PENDING		0x00000100
#define LOG_TCP_CONG		0x00000200

#define LOG_IP_ALL			LOG_IP_MASK
#define LOG_IP_MASK			0x000ff000
#define LOG_IP				0x00001000
#define LOG_IP_ROUTE		0x00002000
#define LOG_ROUTE			LOG_IP_ROUTE
#define LOG_IP_HDR			0x00004000
#define LOG_ICMP			0x00080000

#define LOG_LINK_ALL		LOG_LINK_MASK
#define LOG_LINK_MASK		0x0ff00000
#define LOG_LINK			0x00100000
#define LOG_LINK_HDR		0x00200000
#define LOG_LINK_MAC		0x00400000
#define LOG_MAC				LOG_LINK_MAC

#define LOG_KERNEL_ALL		LOG_KERNEL_MASK
#define LOG_KERNEL_MASK		0xf0000000
#define LOG_KERNEL			0x10000000


#define ENV_KENS_LOG_FLAG	"KENS_LOG"
#define ENV_KENS_LOG_FILE	"KENS_LOG_FILE"

/*
 * macro
 */
#ifndef DISABLE_LOG
#define _LOG(t,x...) if ( kens_log_flag & LOG_##t ) LOG_print(#t,##x)
#define _TRACE(t,x...)	if ( kens_log_flag & LOG_##t ) LOG_trace(#t,__FILE__,__LINE__,##x)
#else
#define _LOG(t,x...) {}
#define _TRACE(t,x...)	{}
#endif

#define L_SOCK_CTRL(x...)		_LOG(SOCK_CTRL,##x)
#define T_SOCK_CTRL(x...)		_TRACE(SOCK_CTRL,##x)
#define L_SOCK_FUNC(x...)		_LOG(SOCK_FUNC,##x)
#define T_SOCK_FUNC(x...)		_TRACE(SOCK_FUNC,##x)
#define L_SOCK_KRNL(x...)		_LOG(SOCK_KRNL,##x)
#define T_SOCK_KRNL(x...)		_TRACE(SOCK_KRNL,##x)

#define L_TCP(x...)		_LOG(TCP,##x)
#define T_TCP(x...)		_TRACE(TCP,##x)
#define L_TCP_CB(x...)		_LOG(TCP_CB,##x)
#define T_TCP_CB(x...)		_TRACE(TCP_CB,##x)
#define L_TCP_HDR(x...)		_LOG(TCP_HDR,##x)
#define T_TCP_HDR(x...)		_TRACE(TCP_HDR,##x)
#define L_TCP_PKT(x...)		_LOG(TCP_PKT,##x)
#define T_TCP_PKT(x...)		_TRACE(TCP_PKT,##x)
#define L_TCP_PENDING(x...)		_LOG(TCP_PENDING,##x)
#define T_TCP_PENDING(x...)		_TRACE(TCP_PENDING,##x)
#define L_TCP_CONG(x...)	_LOG(TCP_CONG,##x)
#define T_TCP_CONG(x...)	_TRACE(TCP_CONG,##x)

#define L_IP(x...)		_LOG(IP,##x)
#define T_IP(x...)		_TRACE(IP,##x)
#define L_IP_HDR(x...)		_LOG(IP_HDR,##x)
#define T_IP_HDR(x...)		_TRACE(IP_HDR,##x)

#define L_ICMP(x...)	_LOG(ICMP,##x)
#define T_ICMP(x...)	_TRACE(ICMP,##x)

#define L_ROUTE(x...)		_LOG(ROUTE,##x)
#define T_ROUTE(x...)		_TRACE(ROUTE,##x)

#define L_MAC(x...)		_LOG(MAC,##x)
#define T_MAC(x...)		_TRACE(MAC,##x)

#define L_LINK(x...)	_LOG(LINK,##x)
#define T_LINK(x...)	_TRACE(LINK,##x)


void LOG_init(dictionary *conf,char *fn,char *opts);
void LOG_dump_data(unsigned char *buf,int len);
void LOG_trace(const char *hdr,const char *fn,int line,char *fmt,...);
void LOG_print(const char *hdr,char *fmt,...);
char *LOG_get_flags(void);
void LOG_shutdown(void);


#endif

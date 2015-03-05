#ifndef __KSOCKCONST_H_
#define __KSOCKCONST_H_

#define CALL_SOCKET			1
#define RETURN_SOCKET		2
#define CALL_CONNECT		3
#define RETURN_CONNECT		4
#define CALL_BIND			5
#define RETURN_BIND			6
#define CALL_ACCEPT			7
#define RETURN_ACCEPT		8	
#define CALL_LISTEN			9
#define RETURN_LISTEN		10
#define CALL_CLOSE			11
#define RETURN_CLOSE		12
#define CALL_SOCKNAME		13
#define RETURN_SOCKNAME		14
#define CALL_PEERNAME		15
#define RETURN_PEERNAME		16

#define ASYNCH_RETURN_ACCEPT	17
#define ASYNCH_RETURN_CONNECT	18
#define ASYNCH_EOF				19
#define ASYNCH_CLOSE			20

#define CALL_GETKENSOPT		21
#define RETURN_GETKENSOPT	22
#define CALL_SETKENSOPT		23
#define	RETURN_SETKENSOPT	24
#define CALL_PASSIVE_SOCKET 25

#define MAX_MSG				CALL_PASSIVE_SOCKET

#define SUCCESS 1
#define FAIL 0

#define MIN(x,y)  ((x) <= (y) ? (x) : (y))
#define MAX(x,y)  ((x) >= (y) ? (x) : (y))

#define MAX_SOCKETS 100
#endif

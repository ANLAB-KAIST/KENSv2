#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ktcp.h"
#include "ktcp_test.h"
#if defined(_WIN32)
	#define sleep Sleep
	#define write(s,b,l) send(s,b,l,0)
	#define read(s,b,l) recv(s,b,l,0)
#else
	#define SOCKET_ERROR -1
#endif
#define MAX_SOCKET_BUF 32768

#define ACTION(msg) printf("> %s: ", msg)
#define CHECK(cond) if (cond) puts("OK"); else { puts("Error occurred"); exit(1); }
#define CHECK_(cond) if (cond) printf("."); else { puts("Error occurred"); exit(1); }

static tcp_socket async_server = NULL;
static tcp_socket async_client = NULL;
static bool localsocketpair(int sd[2]);

int main(int argc, char **argv) {
	tcp_socket h0, h1, h2, h3;
	struct sockaddr_in sin;
	int p1[2], p2[2];
	char buf1[1024], buf2[1024];
	int sum1, sum2;
	int num1, num2;
	int *err = (int *)malloc(sizeof(int));

#if defined(_WIN32)
	WSADATA wsaData;
	p1[0] = WSAStartup(MAKEWORD(2, 0), &wsaData);
#endif

	srand((u_int)time(NULL));


	puts("---------------------------");
	puts("  KENS - KTCP Module Test  ");
	puts("---------------------------");

	ACTION("Startup KTCP");
	CHECK(tcp_startup() == true);

	ACTION("Create new handle of server");
	CHECK((h0 = tcp_open(err)) != NULL);

	ACTION("Bind");
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7F000001);
	sin.sin_port = htons(0x1111);
	CHECK(tcp_bind(h0, (struct sockaddr *)&sin, sizeof(sin), err) == true);

	ACTION("Listen");
	CHECK(tcp_listen(h0, 5, err));

	ACTION("Create new handle to accept new connection");
	CHECK((h1 = tcp_open(err)) != NULL);

	ACTION("Create two pairs of pipe");
	CHECK_(localsocketpair(p1) == true);
	CHECK(localsocketpair(p2) == true);

	ACTION("Try to accept new connection");
	CHECK(tcp_accept(h0, h1, p1[1], err) == true);

	ACTION("Create new handle of client");
	CHECK((h2 = tcp_open(err)) != NULL);

	ACTION("Try to connect the server");
	CHECK(tcp_connect(h2, (struct sockaddr *)&sin, sizeof(sin), p2[1], err) == true);

	ACTION("Client waits for connection establishment using tcp_dispatch");
	tcp_dispatch();
	CHECK_(async_server == h1);
	CHECK(async_client == h2);

	/* Let's play the 1-or-2-until-20 game. */
	ACTION("Let's play the 1-or-2-until-20 game");
	printf("\n");
	sum1 = sum2 = 0;
	while (1) {
		if (sum1 < 18)
			num1 = (rand() % 2) + 1;
		else
			num1 = 20 - sum1;
		printf("    Server: %2d    ", num1);
		sum1 += num1;
		sprintf(buf1, "%d", num1);
		write(p1[0], buf1, strlen(buf1) + 1);
		tcp_dispatch();

		read(p2[0], buf2, 1024);
		sscanf(buf2, "%d", &num2);
		sum2 += num2;
		printf("Sum: %2d\n", sum2);
		if (sum2 == 20) {
			printf("  Server Win!\n");
			break;
		}
		if (sum2 < 18)
			num2 = (rand() % 2) + 1;
		else
			num2 = 20 - sum2;
		printf("    Client: %2d    ", num2);
		sum2 += num2;
		sprintf(buf2, "%d", num2);
		write(p2[0], buf2, strlen(buf2) + 1);
		tcp_dispatch();

		read(p1[0], buf1, 1024);
		sscanf(buf1, "%d", &num1);
		sum1 += num1;
		printf("Sum: %2d\n", sum1);
		if (sum1 == 20) {
			printf("  Client Win!\n");
			break;
		}
	}
	ACTION("Close sockets");
	CHECK_(tcp_close(h2, err));
	CHECK_(tcp_dispatch());
	CHECK_(tcp_close(h1, err));
	CHECK_(tcp_dispatch());
	CHECK(tcp_close(h0, err));

	ACTION("Shutdown KTCP");
	tcp_shutdown();
	CHECK(true);

#if defined(_WIN32)
	WSACleanup();
#endif
	return 0;
}

int ker_message(char msg_id, int status, void *tcp_bind_handle, void *tcp_conn_handle)
{
	if (status == 0) {
		switch (msg_id) {
			case ASYNCH_RETURN_ACCEPT:
				async_server = tcp_conn_handle;
				break;
			case ASYNCH_RETURN_CONNECT:
				async_client = tcp_bind_handle;
				break;
		}
	}
	else {
		CHECK(false);
	}
	return 0;
}

int IP_output(u_long src_addr, u_long dest_addr, char *data, size_t data_size)
{
	struct in_addr src, dest;
	src.s_addr = src_addr;
	dest.s_addr = dest_addr;
	tcp_dispatch_in(src, dest, data, data_size);
	return (int)data_size;
}

u_long *IP_host_addresses()
{
	static u_long addresses[3] = { 0x0100007F, 0x0D0C0B0A, 0 };
	return addresses;
}

u_long IP_host_address(u_long dest_addr)
{
	return 0x0100007F;
}

bool localsocketpair(int sd[2])
{
  struct sockaddr_in sin;
  int newsd;
  int len;
  int newsndbuf_size;  /* to resize our sockets' send buffers */

  sd[0] = socket(AF_INET, SOCK_STREAM, 0);
  sd[1] = socket(AF_INET, SOCK_STREAM, 0);

  if (sd[0] == -1 || sd[1] == -1) {
    goto fail;
  }

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(0x7F000001);
  sin.sin_port = htons(0);

  if (bind(sd[0], (struct sockaddr *) &sin, sizeof(sin)) == SOCKET_ERROR) {
    goto fail;
  }

  if (listen(sd[0], 5) == SOCKET_ERROR) {
    goto fail;
  }

  len = sizeof(sin);
  if (getsockname(sd[0], (struct sockaddr *)&sin, &len) == SOCKET_ERROR) {
    goto fail;
  }

  if (connect(sd[1], (struct sockaddr *)&sin, len) == SOCKET_ERROR) {
    goto fail;
  }


  if ((newsd = accept(sd[0], (struct sockaddr *) &sin, &len)) == SOCKET_ERROR) {
    goto fail;
  }

  close(sd[0]);
  sd[0] = newsd;

  newsndbuf_size = MAX_SOCKET_BUF;
  setsockopt(sd[0], SOL_SOCKET, SO_SNDBUF, 
			 (char *) &newsndbuf_size, sizeof(int));
  setsockopt(sd[1], SOL_SOCKET, SO_SNDBUF, 
			 (char *) &newsndbuf_size, sizeof(int));

  return true;

 fail:
  if (sd[0] != -1) {
    close(sd[0]);
  }

  if (sd[1] != -1) {
    close(sd[1]);
  }

  return false;
}

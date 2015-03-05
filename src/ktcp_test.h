
#ifndef __KENS_KTCP_TEST_H__
#define __KENS_KTCP_TEST_H__

typedef struct application_t {
	int pipe_sd;
	struct sockaddr *caller;
} application;

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#define ASYNCH_RETURN_ACCEPT	17
#define ASYNCH_RETURN_CONNECT	18
extern int ker_message(char msg_id, int status, void *tcp_bind_handle, void *tcp_conn_handle);

extern int IP_output(u_long src_addr, u_long dest_addr, char *data, size_t data_size);
extern u_long *IP_host_addresses();
extern u_long IP_host_address(u_long dest_addr);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __KENS_KTCP_TEST_H__ */

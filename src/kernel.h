#ifndef __KENS_KERNEL_
#define __KENS_KERNEL_

#include "ksockconst.h"
#include "datalink.h"
#include "kip.h"
#include "ktcp.h"

extern int ker_message(char msg_id, int status, void *tcp_bind_handle, void *tcp_conn_handle);
#endif


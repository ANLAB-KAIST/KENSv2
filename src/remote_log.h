#ifndef _REMOTE_LOG_H_
#define _REMOTE_LOG_H_

#define HAVE_REMOTE_LOG		1

void rlog_init (dictionary *conf);
void rlog_shutdown (void);
void rlog_send (const char *hdr, const char *string);
void rlog_send_format (const char *hdr, const char *format, ...);
int rlog_set_server (const char *address /* domain name or ip */);
const char* get_remote_server_name (void);

#endif /* _REMOTE_LOG_H_ */


/**
 * @file        ktcp_easy_lib.h
 * @author      leeopop
 * @date        Aug 2013
 * @version     $Revision: 1.00 $
 * @brief       Library for easy-KTCP project
 *
 * This is the collection of useful libraries used in easy-KTCP project.
 * Layer abstraction and connectivity functions are included.
*/

#ifndef KTCP_EASY_LIB_H_
#define KTCP_EASY_LIB_H_

#include "ktcp_easy_impl.h"
#include <stddef.h>
#include <stdint.h>

typedef struct
{
	/**
	 * @breif
	 * This function retuns local ip address of KTCP interface.
	 *
	 * @author leeopop
	 * @param target target IP address (in network ordering)
	 * @return local ip address that can reach target ip address (INADDR_ANY if there is no specific route)
	 */
	uint32_t (*ip_host_address)(struct in_addr target);


	/**
	 * @breif
	 * This function passes data to IP layer.
	 *
	 * @author leeopop
	 * @param src_addr source IP address (in network ordering)
	 * @param dest_addr destination IP address (in network ordering)
	 * @param data IP payload
	 * @param data_size size of data
	 * @return actual written bytes (-1 means error)
	 */
	int (*tcp_dispatch_ip)(struct in_addr src_addr, struct in_addr dest_addr, void * data, size_t data_size);

	/**
	 * @breif
	 * This function passes data to application
	 *
	 * @author leeopop
	 * @param handle abstraction of application socket
	 * @param data data to be passed
	 * @param data_size size of data
	 * @return actual written bytes (-1 means closed socket)
	 */
	int (*tcp_dispatch_app)(my_context handle, const void* data, size_t data_size);

	/**
	 * @breif
	 * This function wakes up 'kaccept' and 'kaccept' will return @param new_handle.
	 *
	 * @author leeopop
	 * @param server_handle TCP context to be waken up
	 * @param new_handle passively opened socket used as the return value of 'kaccept'
	 * @return whether operation is successful (for example, if server_handle is not blocked)
	 */
	bool (*tcp_passive_open)(my_context server_handle, my_context new_handle);

	/**
	 * @breif
	 * This function wakes up 'kconnect'.
	 *
	 * @author leeopop
	 * @param handle TCP context to be waken up
	 * @return whether operation is successful (for example, if handle is not blocked)
	 */
	bool (*tcp_active_open)(my_context handle);

	/**
	 * @breif
	 * This function returns absolute time in milliseconds.
	 *
	 * @return absolute time in milliseconds (use this value for time registration)
	 */
	int (*tcp_get_mtime)();

	/**
	 * @breif
	 * This function registers timer for each context.
	 * If it is already registered, it overwrites it.
	 *
	 * @author leeopop
	 * @param context TCP context that will be bound to this timer
	 * @param absolute time to wake up (@see tcp_get_mtime)
	 * @return whether registration is successful
	 */
	bool (*tcp_register_timer)(my_context context, int mtime);

	/**
	 * @breif
	 * This function unregisters timer for each context.
	 * If it is not registered, no action.
	 *
	 * @author leeopop
	 * @param context TCP context that is bound to a timer
	 */
	void (*tcp_unregister_timer)(my_context context);

	/**
	 * @breif
	 * This function shuts down tcp-app connection.
	 * If it is not bound, no action.
	 *
	 * @author leeopop
	 * @param context TCP context that is bound to an application
	 */
	void (*tcp_shutdown_app)(my_context handle);

}ktcp_easy_lib;

#endif /* KTCP_EASY_LIB_H_ */

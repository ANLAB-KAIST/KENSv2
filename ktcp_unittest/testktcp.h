/*
 * testktcp.h
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */

#ifndef TESTKTCP_H_
#define TESTKTCP_H_


#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include "ktcp_easy_impl.h"
#include "ktcp_easy_lib.h"
#include "ktcp_test_lib.h"
#include "linked_list.h"
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

extern ktcp_easy_impl* __target;
extern ktcp_easy_impl* __reference;
extern ktcp_easy_lib* __target_env;
extern ktcp_easy_lib* __reference_env;



//Test functions
void __testOpen(void);

//Bind
void __testBind_Simple();
void __testBind_GetSockName();
void __testBind_DoubleBind();
void __testBind_OverlapPort();
void __testBind_OverlapClosed();
void __testBind_DifferentIP_SamePort();
void __testBind_SameIP_DifferentPort();


//connect
void __testConnect_Simple_Default_IP();
void __testConnect_Simple_Second_IP();
void __testConnect_Simultaneous();


//listen
void __testListen_Accept_Before_Connect();
void __testListen_Accept_After_Connect();
void __testListen_Accept_Multiple();
void __testListen_Multiple_Interfaces();

//close
void __testClose_Passive_Close_First();
void __testClose_Passive_Close_Later();
void __testClose_Active_Close_First();
void __testClose_Active_Close_Later();

//transfer
void __testTransfer_Passive_Close_First_Send();
void __testTransfer_Passive_Close_Later_Send();
void __testTransfer_Active_Close_First_Send();
void __testTransfer_Active_Close_Later_Send();
void __testTransfer_Passive_Close_First_Receive();
void __testTransfer_Passive_Close_Later_Receive();
void __testTransfer_Active_Close_First_Receive();
void __testTransfer_Active_Close_Later_Receive();

#endif /* TESTKTCP_H_ */

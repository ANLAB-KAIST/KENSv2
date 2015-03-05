/*
 * testopen.c
 *
 *  Created on: 2013. 11. 24.
 *      Author: leeopop
 */


#include "testktcp.h"

void __testOpen()
{
	int err = 0;
	my_context created = __target->open(__target, &err);
	CU_ASSERT_PTR_NOT_NULL_FATAL(created);
	CU_ASSERT_EQUAL_FATAL(err, 0);

	__target->close(__target, created, &err);
}

/*
 * utils.cpp
 *
 *  Created on: Sep 8, 2016
 *      Author: user
 */

#include "utils.h"

bool guardig_utils::is_ipv4_mapped_ipv6(uint8_t* paddr)
{
	if(paddr[0] == 0 && paddr[1] == 0 && paddr[2] == 0 && paddr[3] == 0 && paddr[4] == 0 &&
		paddr[5] == 0 && paddr[6] == 0 && paddr[7] == 0 && paddr[8] == 0 && paddr[9] == 0 &&
		paddr[10] == 0xff && paddr[11] == 0xff)
	{
		return true;
	}
	else
	{
		return false;
	}
}


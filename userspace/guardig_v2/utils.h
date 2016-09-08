/*
 * utils.h
 *
 *  Created on: Sep 8, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_V2_UTILS_H_
#define USERSPACE_GUARDIG_V2_UTILS_H_

#include <stdint.h>

class guardig_utils {
public:

	static bool is_ipv4_mapped_ipv6(uint8_t* paddr);

};

#endif /* USERSPACE_GUARDIG_V2_UTILS_H_ */
